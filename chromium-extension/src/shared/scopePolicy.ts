import type {
  ScopeDecision,
  ScopePolicy,
  TrafficEndpointV1,
  TrafficScopeDisposition,
  TrafficScopeRuleMatcherV1,
  TrafficScopeRuleV1,
  TrafficScheme
} from '../../../shared-schema/src';

export interface ScopeOriginContext {
  targetUrl?: string;
  targetOrigin?: string;
  targetRegistrableDomain?: string;
}

export interface ScopeEvaluationInput {
  endpoint: TrafficEndpointV1;
  rawUrl: string;
  evaluatedAt?: string;
}

export interface CaptureTargetScopePolicyOptions {
  policyId?: string;
  version?: string;
  defaultDisposition?: Exclude<TrafficScopeDisposition, 'in-scope'>;
}

export interface ParseScopePatternLinesInput {
  policyId: string;
  version: string;
  includeText: string;
  excludeText: string;
  reviewText?: string;
  defaultDisposition?: Exclude<TrafficScopeDisposition, 'in-scope'>;
}

export interface FormattedScopePolicyPatterns {
  includeText: string;
  excludeText: string;
  reviewText: string;
}

export interface AppendScopePatternLinesInput {
  policy: ScopePolicy;
  version?: string;
  includeText?: string;
  excludeText?: string;
  reviewText?: string;
  defaultDisposition?: Exclude<TrafficScopeDisposition, 'in-scope'>;
}

const DISPOSITION_TIE_RANK: Record<TrafficScopeRuleV1['disposition'], number> = {
  'out-of-scope': 3,
  review: 2,
  'in-scope': 1
};

export function createCaptureTargetScopePolicy(
  targetUrl: string,
  options: CaptureTargetScopePolicyOptions = {}
): ScopePolicy {
  const parsed = parseTrafficUrl(targetUrl);
  const scheme = normalizeScheme(parsed.protocol);
  const host = normalizeHostname(parsed.hostname);
  const port = effectivePort(parsed);

  return {
    policyId: options.policyId ?? `capture-target:${scheme}:${host}:${port}`,
    version: options.version ?? '1',
    defaultDisposition: options.defaultDisposition ?? 'review',
    evaluation: 'highest-priority-exclude-on-tie',
    rules: [
      {
        ruleId: 'capture-target-origin',
        priority: 100,
        disposition: 'in-scope',
        source: 'capture-target',
        matcher: {
          kind: 'exact-host',
          hostname: host,
          schemes: [scheme],
          ports: [port]
        },
        note: 'Matches only the exact origin selected for this capture.'
      }
    ]
  };
}

export function parseScopePatternLines(input: ParseScopePatternLinesInput): ScopePolicy {
  const includeRules = parsePatternBlock(input.includeText, 'in-scope', 'include');
  const excludeRules = parsePatternBlock(input.excludeText, 'out-of-scope', 'exclude');
  const reviewRules = parsePatternBlock(input.reviewText ?? '', 'review', 'review');
  return normalizeScopePolicy({
    policyId: input.policyId,
    version: input.version,
    defaultDisposition: input.defaultDisposition ?? 'review',
    evaluation: 'highest-priority-exclude-on-tie',
    rules: [...includeRules, ...excludeRules, ...reviewRules]
  });
}

export function formatScopePolicyPatterns(policy: ScopePolicy): FormattedScopePolicyPatterns {
  const normalized = normalizeScopePolicy(policy);
  const includeLines: string[] = [];
  const excludeLines: string[] = [];
  const reviewLines: string[] = [];
  const sortedRules = [...normalized.rules].sort(
    (left, right) => right.priority - left.priority || left.ruleId.localeCompare(right.ruleId)
  );

  for (const rule of sortedRules) {
    const target =
      rule.disposition === 'in-scope'
        ? includeLines
        : rule.disposition === 'out-of-scope'
          ? excludeLines
          : reviewLines;
    const pattern = formatMatcherWithConstraints(rule.matcher);
    const methods = rule.methods?.length ? rule.methods : [undefined];
    for (const method of methods) {
      target.push(method ? `${method} ${pattern}` : pattern);
    }
  }

  return {
    includeText: includeLines.join('\n'),
    excludeText: excludeLines.join('\n'),
    reviewText: reviewLines.join('\n')
  };
}

export function cloneScopePolicy(policy: ScopePolicy): ScopePolicy {
  return {
    ...policy,
    rules: policy.rules.map((rule) => ({
      ...rule,
      matcher: cloneScopeMatcher(rule.matcher),
      methods: rule.methods ? [...rule.methods] : undefined
    }))
  };
}

export function appendScopePatternLines(input: AppendScopePatternLinesInput): ScopePolicy {
  const basePolicy = cloneScopePolicy(input.policy);
  const version = input.version ?? basePolicy.version;
  const defaultDisposition = input.defaultDisposition ?? basePolicy.defaultDisposition;
  const additions = parseScopePatternLines({
    policyId: basePolicy.policyId,
    version,
    includeText: input.includeText ?? '',
    excludeText: input.excludeText ?? '',
    reviewText: input.reviewText ?? '',
    defaultDisposition
  });
  const usedRuleIds = new Set(basePolicy.rules.map((rule) => rule.ruleId));
  const addedRules = additions.rules.map((rule) => {
    const ruleId = allocateUniqueRuleId(rule.ruleId, usedRuleIds);
    usedRuleIds.add(ruleId);
    return { ...rule, ruleId };
  });

  return normalizeScopePolicy({
    ...basePolicy,
    version,
    defaultDisposition,
    rules: [...basePolicy.rules, ...addedRules]
  });
}

export function normalizeScopePolicy(policy: ScopePolicy): ScopePolicy {
  if (!policy || typeof policy !== 'object') {
    throw new Error('Scope policy must be an object.');
  }
  if (typeof policy.policyId !== 'string' || !policy.policyId.trim()) {
    throw new Error('Scope policy requires a non-empty policyId.');
  }
  if (typeof policy.version !== 'string' || !policy.version.trim()) {
    throw new Error('Scope policy requires a non-empty version.');
  }
  if (!isDefaultDisposition(policy.defaultDisposition)) {
    throw new Error(`Scope policy has an invalid default disposition: ${String(policy.defaultDisposition)}`);
  }
  if (!Array.isArray(policy.rules)) {
    throw new Error('Scope policy rules must be an array.');
  }

  const rules = policy.rules.map(normalizeScopeRule);
  const seenRuleIds = new Set<string>();
  for (const rule of rules) {
    if (seenRuleIds.has(rule.ruleId)) {
      throw new Error(`Scope policy contains duplicate ruleId ${rule.ruleId}.`);
    }
    seenRuleIds.add(rule.ruleId);
  }

  return {
    policyId: policy.policyId.trim(),
    version: policy.version.trim(),
    defaultDisposition: policy.defaultDisposition,
    evaluation: 'highest-priority-exclude-on-tie',
    rules
  };
}

export function evaluateTrafficScope(
  policy: ScopePolicy,
  input: ScopeEvaluationInput
): ScopeDecision {
  const normalizedPolicy = normalizeScopePolicy(policy);
  const matches = normalizedPolicy.rules
    .filter((rule) => scopeRuleMatches(rule, input))
    .sort((left, right) => {
      const priorityDifference = right.priority - left.priority;
      if (priorityDifference !== 0) {
        return priorityDifference;
      }

      const dispositionDifference =
        DISPOSITION_TIE_RANK[right.disposition] - DISPOSITION_TIE_RANK[left.disposition];
      return dispositionDifference !== 0
        ? dispositionDifference
        : left.ruleId.localeCompare(right.ruleId);
    });
  const winningPriority = matches[0]?.priority;
  const winningMatches =
    winningPriority === undefined
      ? []
      : matches.filter((rule) => rule.priority === winningPriority);
  const winner = winningMatches[0];

  if (!winner) {
    return {
      disposition: normalizedPolicy.defaultDisposition,
      confidence: normalizedPolicy.defaultDisposition === 'unknown' ? 'low' : 'medium',
      basis: 'default',
      policyId: normalizedPolicy.policyId,
      policyVersion: normalizedPolicy.version,
      matchedRuleIds: [],
      reasonCodes: [`SCOPE_POLICY_DEFAULT_${toReasonSegment(normalizedPolicy.defaultDisposition)}`],
      evaluatedAt: input.evaluatedAt ?? new Date().toISOString()
    };
  }

  const excludeTieBreak =
    winner.disposition === 'out-of-scope' &&
    winningMatches.some((rule) => rule.disposition !== 'out-of-scope');

  return {
    disposition: winner.disposition,
    confidence: 'high',
    basis: 'matched-rule',
    policyId: normalizedPolicy.policyId,
    policyVersion: normalizedPolicy.version,
    matchedRuleIds: winningMatches.map((rule) => rule.ruleId),
    reasonCodes: [
      `SCOPE_RULE_MATCH_${toReasonSegment(winner.matcher.kind)}`,
      ...(excludeTieBreak ? ['SCOPE_EXCLUDE_EQUAL_PRIORITY_TIE'] : [])
    ],
    evaluatedAt: input.evaluatedAt ?? new Date().toISOString()
  };
}

export function scopeRuleMatches(
  rawRule: TrafficScopeRuleV1,
  input: ScopeEvaluationInput
): boolean {
  const rule = normalizeScopeRule(rawRule);
  if (
    rule.methods &&
    !rule.methods.includes(input.endpoint.method.toUpperCase())
  ) {
    return false;
  }

  switch (rule.matcher.kind) {
    case 'exact-host':
      return (
        input.endpoint.host === rule.matcher.hostname &&
        matchesSchemeAndPort(rule.matcher, input.endpoint)
      );
    case 'wildcard-subdomain':
      return (
        input.endpoint.host !== rule.matcher.baseHostname &&
        input.endpoint.host.endsWith(`.${rule.matcher.baseHostname}`) &&
        matchesSchemeAndPort(rule.matcher, input.endpoint)
      );
    case 'url-prefix':
      return canonicalUrlWithoutValues(input.rawUrl).startsWith(rule.matcher.prefix);
    case 'ipv4-cidr':
      return (
        ipv4MatchesCidr(input.endpoint.host, rule.matcher.cidr) &&
        matchesSchemeAndPort(rule.matcher, input.endpoint)
      );
  }
}

function normalizeScopeRule(rule: TrafficScopeRuleV1): TrafficScopeRuleV1 {
  if (!rule || typeof rule !== 'object') {
    throw new Error('Every scope rule must be an object.');
  }
  if (typeof rule.ruleId !== 'string' || !rule.ruleId.trim()) {
    throw new Error('Every scope rule requires a non-empty ruleId.');
  }
  if (!Number.isFinite(rule.priority)) {
    throw new Error(`Scope rule ${rule.ruleId} has an invalid priority.`);
  }
  if (!isRuleDisposition(rule.disposition)) {
    throw new Error(`Scope rule ${rule.ruleId} has an invalid disposition: ${String(rule.disposition)}`);
  }
  if (!isRuleSource(rule.source)) {
    throw new Error(`Scope rule ${rule.ruleId} has an invalid source: ${String(rule.source)}`);
  }
  if (
    rule.methods !== undefined &&
    (!Array.isArray(rule.methods) || rule.methods.some((method) => typeof method !== 'string'))
  ) {
    throw new Error(`Scope rule ${rule.ruleId} methods must be an array of strings.`);
  }
  if (rule.note !== undefined && typeof rule.note !== 'string') {
    throw new Error(`Scope rule ${rule.ruleId} note must be a string.`);
  }

  return {
    ...rule,
    ruleId: rule.ruleId.trim(),
    priority: Math.trunc(rule.priority),
    matcher: normalizeMatcher(rule.matcher),
    methods: rule.methods?.length ? uniqueSorted(rule.methods.map(normalizeMethod)) : undefined,
    note: rule.note?.trim() || undefined
  };
}

function parsePatternBlock(
  text: string,
  disposition: TrafficScopeRuleV1['disposition'],
  idPrefix: string
): TrafficScopeRuleV1[] {
  const rules: TrafficScopeRuleV1[] = [];
  for (const [lineIndex, rawLine] of text.split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }

    try {
      const { core, schemes, ports } = splitMatcherConstraints(line);
      const { method, pattern } = splitMethodPrefix(core);
      const matcher = applyMatcherConstraints(parsePatternMatcher(pattern), schemes, ports);
      rules.push({
        ruleId: `${idPrefix}-${String(rules.length + 1).padStart(3, '0')}`,
        priority: 100,
        disposition,
        source: 'operator',
        matcher: normalizeMatcher(matcher),
        methods: method ? [method] : undefined
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Invalid ${idPrefix} scope pattern on line ${lineIndex + 1}: ${message}`);
    }
  }
  return rules;
}

function splitMatcherConstraints(line: string): {
  core: string;
  schemes?: TrafficScheme[];
  ports?: number[];
} {
  const coreTokens: string[] = [];
  let schemes: TrafficScheme[] | undefined;
  let ports: number[] | undefined;
  let foundConstraint = false;

  for (const token of line.split(/\s+/)) {
    const constraint = token.match(/^(schemes|ports)=(.*)$/i);
    if (!constraint) {
      if (foundConstraint) {
        throw new Error('Scope constraints must follow the matcher pattern.');
      }
      coreTokens.push(token);
      continue;
    }

    foundConstraint = true;
    const name = constraint[1]?.toLowerCase();
    const value = constraint[2] ?? '';
    if (name === 'schemes') {
      if (schemes) {
        throw new Error('Scope pattern contains more than one schemes constraint.');
      }
      schemes = parseSchemeConstraint(value);
    } else {
      if (ports) {
        throw new Error('Scope pattern contains more than one ports constraint.');
      }
      ports = parsePortConstraint(value);
    }
  }

  const core = coreTokens.join(' ').trim();
  if (!core) {
    throw new Error('Scope pattern matcher cannot be empty.');
  }
  return { core, schemes, ports };
}

function parseSchemeConstraint(rawValue: string): TrafficScheme[] {
  const values = rawValue.split(',').map((value) => value.trim());
  if (values.some((value) => !value)) {
    throw new Error('schemes requires a comma-separated list.');
  }
  return uniqueSorted(values.map(normalizeScheme)) as TrafficScheme[];
}

function parsePortConstraint(rawValue: string): number[] {
  const values = rawValue.split(',').map((value) => Number(value.trim()));
  if (values.some((value) => !Number.isInteger(value))) {
    throw new Error('ports requires a comma-separated list of integers.');
  }
  return normalizePorts(values) ?? [];
}

function applyMatcherConstraints(
  matcher: TrafficScopeRuleMatcherV1,
  schemes: TrafficScheme[] | undefined,
  ports: number[] | undefined
): TrafficScopeRuleMatcherV1 {
  if (!schemes && !ports) {
    return matcher;
  }
  if (matcher.kind === 'url-prefix') {
    throw new Error('URL-prefix rules carry their scheme and port in the URL.');
  }
  return {
    ...matcher,
    schemes,
    ports
  };
}

function splitMethodPrefix(line: string): { method?: string; pattern: string } {
  const bracketed = line.match(/^\[([^\]]+)]\s+(.+)$/);
  if (bracketed) {
    return {
      method: normalizeMethod(bracketed[1] ?? ''),
      pattern: (bracketed[2] ?? '').trim()
    };
  }

  const plain = line.match(/^([A-Za-z][A-Za-z0-9._-]*)\s+(.+)$/);
  if (plain) {
    return {
      method: normalizeMethod(plain[1] ?? ''),
      pattern: (plain[2] ?? '').trim()
    };
  }
  return { pattern: line };
}

function parsePatternMatcher(pattern: string): TrafficScopeRuleMatcherV1 {
  if (/^(?:https?|wss?):\/\//i.test(pattern)) {
    return { kind: 'url-prefix', prefix: pattern };
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(pattern)) {
    return { kind: 'ipv4-cidr', cidr: pattern };
  }
  if (pattern.startsWith('*.')) {
    return { kind: 'wildcard-subdomain', baseHostname: pattern.slice(2) };
  }
  if (!pattern || /[/?#@]/.test(pattern)) {
    throw new Error(`Unsupported pattern ${JSON.stringify(pattern)}.`);
  }
  return { kind: 'exact-host', hostname: pattern };
}

function formatMatcher(matcher: TrafficScopeRuleMatcherV1): string {
  switch (matcher.kind) {
    case 'exact-host':
      return matcher.hostname;
    case 'wildcard-subdomain':
      return `*.${matcher.baseHostname}`;
    case 'url-prefix':
      return matcher.prefix;
    case 'ipv4-cidr':
      return matcher.cidr;
  }
}

function formatMatcherWithConstraints(matcher: TrafficScopeRuleMatcherV1): string {
  const parts = [formatMatcher(matcher)];
  if (matcher.kind !== 'url-prefix') {
    if (matcher.schemes?.length) {
      parts.push(`schemes=${matcher.schemes.join(',')}`);
    }
    if (matcher.ports?.length) {
      parts.push(`ports=${matcher.ports.join(',')}`);
    }
  }
  return parts.join(' ');
}

function normalizeMatcher(matcher: TrafficScopeRuleMatcherV1): TrafficScopeRuleMatcherV1 {
  if (!matcher || typeof matcher !== 'object') {
    throw new Error('Scope rule matcher must be an object.');
  }
  switch (matcher.kind) {
    case 'exact-host':
      return {
        kind: matcher.kind,
        hostname: normalizeHostname(requireString(matcher.hostname, 'exact-host hostname')),
        schemes: normalizeSchemes(requireOptionalStringArray(matcher.schemes, 'matcher schemes')),
        ports: normalizePorts(requireOptionalNumberArray(matcher.ports, 'matcher ports'))
      };
    case 'wildcard-subdomain':
      return {
        kind: matcher.kind,
        baseHostname: normalizeHostname(
          requireString(matcher.baseHostname, 'wildcard-subdomain hostname').replace(/^\*\./, '')
        ),
        schemes: normalizeSchemes(requireOptionalStringArray(matcher.schemes, 'matcher schemes')),
        ports: normalizePorts(requireOptionalNumberArray(matcher.ports, 'matcher ports'))
      };
    case 'url-prefix':
      return {
        kind: matcher.kind,
        prefix: canonicalUrlWithoutValues(requireString(matcher.prefix, 'URL prefix'))
      };
    case 'ipv4-cidr':
      return {
        kind: matcher.kind,
        cidr: normalizeIpv4Cidr(requireString(matcher.cidr, 'IPv4 CIDR')),
        schemes: normalizeSchemes(requireOptionalStringArray(matcher.schemes, 'matcher schemes')),
        ports: normalizePorts(requireOptionalNumberArray(matcher.ports, 'matcher ports'))
      };
    default:
      throw new Error(
        `Scope rule has an invalid matcher kind: ${String((matcher as { kind?: unknown }).kind)}`
      );
  }
}

function cloneScopeMatcher(matcher: TrafficScopeRuleMatcherV1): TrafficScopeRuleMatcherV1 {
  if (matcher.kind === 'url-prefix') {
    return { ...matcher };
  }
  return {
    ...matcher,
    schemes: matcher.schemes ? [...matcher.schemes] : undefined,
    ports: matcher.ports ? [...matcher.ports] : undefined
  };
}

function allocateUniqueRuleId(candidate: string, usedRuleIds: Set<string>): string {
  if (!usedRuleIds.has(candidate)) {
    return candidate;
  }
  let suffix = 2;
  while (usedRuleIds.has(`${candidate}-${suffix}`)) {
    suffix += 1;
  }
  return `${candidate}-${suffix}`;
}

function isDefaultDisposition(
  value: unknown
): value is Exclude<TrafficScopeDisposition, 'in-scope'> {
  return value === 'review' || value === 'out-of-scope' || value === 'unknown';
}

function isRuleDisposition(value: unknown): value is TrafficScopeRuleV1['disposition'] {
  return value === 'in-scope' || value === 'out-of-scope' || value === 'review';
}

function isRuleSource(value: unknown): value is TrafficScopeRuleV1['source'] {
  return value === 'operator' || value === 'burp' || value === 'capture-target' || value === 'imported';
}

function requireString(value: unknown, fieldName: string): string {
  if (typeof value !== 'string') {
    throw new Error(`Scope rule ${fieldName} must be a string.`);
  }
  return value;
}

function requireOptionalStringArray(
  value: unknown,
  fieldName: string
): TrafficScheme[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new Error(`Scope rule ${fieldName} must be an array of strings.`);
  }
  return value as TrafficScheme[];
}

function requireOptionalNumberArray(value: unknown, fieldName: string): number[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'number')) {
    throw new Error(`Scope rule ${fieldName} must be an array of numbers.`);
  }
  return value;
}

function matchesSchemeAndPort(
  matcher: Extract<TrafficScopeRuleMatcherV1, { schemes?: string[]; ports?: number[] }>,
  endpoint: TrafficEndpointV1
): boolean {
  const schemesMatch = !matcher.schemes || matcher.schemes.includes(endpoint.scheme);
  const portsMatch = !matcher.ports || matcher.ports.includes(endpoint.port);
  return schemesMatch && portsMatch;
}

function canonicalUrlWithoutValues(rawUrl: string): string {
  const parsed = parseTrafficUrl(rawUrl);
  parsed.username = '';
  parsed.password = '';
  parsed.search = '';
  parsed.hash = '';
  return `${parsed.origin}${parsed.pathname}`;
}

function parseTrafficUrl(rawUrl: string): URL {
  const parsed = new URL(rawUrl);
  normalizeScheme(parsed.protocol);
  return parsed;
}

function normalizeHostname(rawHostname: string): string {
  const candidate = rawHostname.trim().replace(/^\*\./, '').replace(/\.$/, '');
  if (!candidate) {
    throw new Error('Scope rule hostname cannot be empty.');
  }

  try {
    return new URL(`http://${candidate}`).hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    throw new Error(`Invalid scope rule hostname: ${rawHostname}`);
  }
}

function normalizeMethod(method: string): string {
  const normalized = method.trim().toUpperCase();
  if (!normalized || !/^[A-Z][A-Z0-9._-]*$/.test(normalized)) {
    throw new Error(`Invalid HTTP method in scope rule: ${method}`);
  }
  return normalized;
}

function normalizeScheme(scheme: string): TrafficScheme {
  const normalized = scheme.trim().toLowerCase().replace(/:$/, '');
  switch (normalized) {
    case 'http':
    case 'https':
    case 'ws':
    case 'wss':
      return normalized;
    default:
      throw new Error(`Unsupported scope rule scheme: ${normalized}`);
  }
}

function normalizeSchemes(schemes: TrafficScheme[] | undefined): TrafficScheme[] | undefined {
  if (!schemes?.length) {
    return undefined;
  }
  const normalized = uniqueSorted(schemes.map(normalizeScheme));
  return normalized as TrafficScheme[];
}

function normalizePorts(ports: number[] | undefined): number[] | undefined {
  if (!ports?.length) {
    return undefined;
  }
  if (ports.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) {
    throw new Error('Scope rule ports must be integers between 1 and 65535.');
  }
  return [...new Set(ports)].sort((left, right) => left - right);
}

function effectivePort(url: URL): number {
  if (url.port) {
    return Number(url.port);
  }
  return url.protocol === 'https:' || url.protocol === 'wss:' ? 443 : 80;
}

function ipv4MatchesCidr(host: string, cidr: string): boolean {
  const hostValue = ipv4ToUint32(host);
  const [networkText, prefixText] = cidr.split('/');
  if (hostValue === undefined || networkText === undefined || prefixText === undefined) {
    return false;
  }
  const networkValue = ipv4ToUint32(networkText);
  const prefix = Number(prefixText);
  if (networkValue === undefined || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (hostValue & mask) === (networkValue & mask);
}

function normalizeIpv4Cidr(cidr: string): string {
  const [address, prefixText] = cidr.trim().split('/');
  const addressValue = address ? ipv4ToUint32(address) : undefined;
  const prefix = Number(prefixText);
  if (addressValue === undefined || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error(`Invalid IPv4 CIDR scope rule: ${cidr}`);
  }
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return `${uint32ToIpv4(addressValue & mask)}/${prefix}`;
}

function ipv4ToUint32(rawAddress: string): number | undefined {
  const parts = rawAddress.split('.');
  if (parts.length !== 4) {
    return undefined;
  }
  const octets = parts.map(Number);
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return undefined;
  }
  return (
    (((octets[0] ?? 0) << 24) |
      ((octets[1] ?? 0) << 16) |
      ((octets[2] ?? 0) << 8) |
      (octets[3] ?? 0)) >>>
    0
  );
}

function uint32ToIpv4(value: number): string {
  return [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join('.');
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort((left, right) => left.localeCompare(right));
}

function toReasonSegment(value: string): string {
  return value.toUpperCase().replace(/[^A-Z0-9]+/g, '_');
}
