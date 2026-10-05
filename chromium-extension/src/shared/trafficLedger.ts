import {
  BLANCHE_TRAFFIC_LEDGER_KIND,
  BLANCHE_TRAFFIC_LEDGER_SCHEMA_VERSION,
  type BlancheTrafficLedgerV1,
  type ConfidenceLevel,
  type ScopePolicy,
  type TrafficAccess,
  type TrafficBoundary,
  type TrafficCacheState,
  type TrafficClassificationV1,
  type TrafficDataClass,
  type TrafficEndpointV1,
  type TrafficEnvironment,
  type TrafficEvidenceReferenceV1,
  type TrafficLedgerEntry,
  type TrafficLedgerSummary,
  type TrafficObservationSource,
  type TrafficOperation,
  type TrafficOwnership,
  type TrafficPriorityAssessmentV1,
  type TrafficPriorityBand,
  type TrafficPriorityFactorV1,
  type TrafficRole,
  type TrafficScopeDecisionV1,
  type TrafficScopeDisposition,
  type TrafficScheme
} from '../../../shared-schema/src';
import {
  createCaptureTargetScopePolicy,
  evaluateTrafficScope,
  normalizeScopePolicy,
  type ScopeOriginContext
} from './scopePolicy';

export interface TrafficClassificationHints {
  registrableDomain?: string;
  ownership?: TrafficOwnership;
  environment?: TrafficEnvironment;
  roles?: TrafficRole[];
  access?: TrafficAccess;
  operations?: TrafficOperation[];
  dataClasses?: TrafficDataClass[];
  confidence?: ConfidenceLevel;
  reasonCodes?: string[];
}

export interface TrafficObservationInput {
  url: string;
  observedAt: string;
  source: TrafficObservationSource;
  method?: string;
  sourceOrigin?: string;
  frameId?: number;
  initiatorType?: string;
  resourceType?: string;
  statusCode?: number;
  contentType?: string;
  protocol?: string;
  cacheState?: TrafficCacheState;
  requestHeaderNames?: string[];
  responseHeaderNames?: string[];
  requestBodyFieldNames?: string[];
  coverageGaps?: string[];
  bytes?: {
    transfer?: number;
    encoded?: number;
    decoded?: number;
  };
  evidence?: TrafficEvidenceReferenceV1[];
  classification?: TrafficClassificationHints;
}

export interface TrafficLedgerSettings {
  scopePolicy: ScopePolicy;
  originContext: ScopeOriginContext;
}

export interface BuildTrafficLedgerInput {
  sourceSessionId: string;
  settings: TrafficLedgerSettings;
  observations: TrafficObservationInput[];
  ledgerId?: string;
  generatedAt?: string;
  observationWindowStart?: string;
  observationWindowBasis?: 'retained-last-seen';
}

export interface TrafficLedgerQuery {
  scope?: TrafficScopeDisposition[];
  priorityBands?: TrafficPriorityBand[];
  minimumScore?: number;
  roles?: TrafficRole[];
  limit?: number;
}

export interface TrafficTaxonomyResult {
  endpoint: TrafficEndpointV1;
  scope: TrafficScopeDecisionV1;
  classification: TrafficClassificationV1;
}

const SCORE_DELTAS = {
  STATE_CHANGING: 25,
  AUTHENTICATION: 25,
  ADMINISTRATION: 25,
  AUTHORIZATION: 20,
  UPLOAD: 20,
  PRIVILEGED: 20,
  SENSITIVE_DATA: 20,
  CONFIGURATION: 15,
  REALTIME: 15,
  CLIENT_CONTROL: 15,
  SOURCE_MAP: 15,
  API: 10,
  AUTHENTICATED: 10,
  DOWNLOAD: 10,
  CROSS_SITE: 10,
  STATIC_ASSET: -15,
  TELEMETRY: -15
} as const;

const SENSITIVE_PATH_LABELS = new Set([
  'account',
  'accounts',
  'activation',
  'access-token',
  'api-key',
  'apikey',
  'attachment',
  'attachments',
  'auth',
  'case',
  'cases',
  'credential',
  'customer',
  'customers',
  'device',
  'devices',
  'document',
  'documents',
  'file',
  'files',
  'invite',
  'invites',
  'invoice',
  'invoices',
  'key',
  'member',
  'members',
  'order',
  'orders',
  'password',
  'patient',
  'patients',
  'person',
  'people',
  'profile',
  'profiles',
  'project',
  'projects',
  'record',
  'records',
  'recovery',
  'reset',
  'secret',
  'session',
  'tenant',
  'tenants',
  'ticket',
  'tickets',
  'token',
  'user',
  'users'
]);

const SAFE_ROUTE_PATH_SEGMENTS = new Set([
  'batch',
  'bulk',
  'config',
  'configuration',
  'create',
  'current',
  'download',
  'export',
  'import',
  'lookup',
  'me',
  'new',
  'permissions',
  'roles',
  'search',
  'self',
  'settings',
  'upload',
  'validate',
  'verify'
]);

export function canonicalizeTrafficEndpoint(rawUrl: string, rawMethod?: string): TrafficEndpointV1 {
  const url = parseTrafficUrl(rawUrl);
  const endpoint: TrafficEndpointV1 = {
    scheme: normalizeTrafficScheme(url.protocol),
    host: normalizeHost(url.hostname),
    port: effectivePort(url),
    method: normalizeMethod(rawMethod),
    pathTemplate: templatePath(url.pathname),
    queryParameterNames: uniqueSorted([...url.searchParams.keys()])
  };
  return endpoint;
}

export function classifyTrafficObservation(
  input: TrafficObservationInput,
  policy: ScopePolicy,
  originContext: ScopeOriginContext
): TrafficTaxonomyResult {
  const normalizedInput = normalizeObservation(input);
  const endpoint = canonicalizeTrafficEndpoint(normalizedInput.url, normalizedInput.method);
  if (normalizedInput.classification?.registrableDomain) {
    endpoint.registrableDomain = normalizeHost(normalizedInput.classification.registrableDomain);
  }
  const scope = evaluateTrafficScope(policy, {
    endpoint,
    rawUrl: normalizedInput.url,
    evaluatedAt: normalizedInput.observedAt
  });
  const classification = deriveClassification(normalizedInput, endpoint, originContext);
  return { endpoint, scope, classification };
}

export function scoreTrafficObservation(
  input: TrafficObservationInput,
  classification: TrafficClassificationV1
): TrafficPriorityAssessmentV1 {
  return scoreTrafficClassification(
    classification,
    evidenceConfidenceForSources([input.source]),
    (input.evidence ?? []).map((entry) => entry.id)
  );
}

export function scoreTrafficClassification(
  classification: TrafficClassificationV1,
  evidenceConfidence: ConfidenceLevel,
  evidenceRefs: string[] = []
): TrafficPriorityAssessmentV1 {
  const factors = new Map<string, TrafficPriorityFactorV1>();
  const addFactor = (code: keyof typeof SCORE_DELTAS, reason: string) => {
    if (!factors.has(code)) {
      factors.set(code, {
        code,
        delta: SCORE_DELTAS[code],
        reason,
        evidenceRefs: uniqueSorted(evidenceRefs)
      });
    }
  };

  if (classification.operations.some(isStateChangingOperation)) {
    addFactor('STATE_CHANGING', 'The observed operation may change server-side state.');
  }
  if (classification.roles.includes('authentication')) {
    addFactor('AUTHENTICATION', 'The endpoint participates in authentication.');
  }
  if (classification.roles.includes('administration')) {
    addFactor('ADMINISTRATION', 'The endpoint appears to expose an administrative function.');
  }
  if (classification.roles.includes('authorization')) {
    addFactor('AUTHORIZATION', 'The endpoint participates in authorization or entitlement checks.');
  }
  if (classification.roles.includes('upload')) {
    addFactor('UPLOAD', 'The endpoint appears to accept uploaded or imported content.');
  }
  if (classification.access === 'privileged') {
    addFactor('PRIVILEGED', 'The endpoint is classified as privileged.');
  }
  if (classification.dataClasses.length > 0) {
    addFactor('SENSITIVE_DATA', 'The endpoint carries indicators of sensitive data classes.');
  }
  if (classification.roles.includes('configuration')) {
    addFactor('CONFIGURATION', 'The endpoint supplies or changes configuration.');
  }
  if (classification.roles.includes('realtime')) {
    addFactor('REALTIME', 'The endpoint establishes a realtime or subscribed channel.');
  }
  if (classification.roles.includes('client-control')) {
    addFactor('CLIENT_CONTROL', 'The endpoint exposes a client-side control or feature surface.');
  }
  if (classification.roles.includes('source-map')) {
    addFactor('SOURCE_MAP', 'The endpoint exposes source-map material.');
  }
  if (classification.roles.includes('api')) {
    addFactor('API', 'The endpoint is application-facing API traffic.');
  }
  if (classification.access === 'authenticated') {
    addFactor('AUTHENTICATED', 'The endpoint is classified as authenticated.');
  }
  if (classification.roles.includes('download')) {
    addFactor('DOWNLOAD', 'The endpoint appears to return downloadable content.');
  }
  if (classification.boundary === 'cross-site') {
    addFactor('CROSS_SITE', 'The request crosses the target site boundary.');
  }
  if (classification.roles.includes('static')) {
    addFactor('STATIC_ASSET', 'Routine static resources are normally lower-priority traffic.');
  }
  if (classification.roles.includes('telemetry')) {
    addFactor('TELEMETRY', 'Routine telemetry is normally lower-priority traffic.');
  }

  const factorList = [...factors.values()];
  const score = clampScore(factorList.reduce((total, factor) => total + factor.delta, 0));
  return {
    score,
    band: priorityBandForScore(score),
    evidenceConfidence,
    classificationConfidence: classification.confidence,
    factors: factorList
  };
}

export async function buildTrafficLedgerEntry(
  input: TrafficObservationInput,
  settings: TrafficLedgerSettings
): Promise<TrafficLedgerEntry> {
  const normalizedInput = normalizeObservation(input);
  const taxonomy = classifyTrafficObservation(
    normalizedInput,
    settings.scopePolicy,
    settings.originContext
  );
  const evidence = dedupeEvidence(normalizedInput.evidence ?? []);
  const entryId = await endpointEntryId(taxonomy.endpoint);
  const priority = scoreTrafficObservation(normalizedInput, taxonomy.classification);
  const coverageGaps = new Set(normalizedInput.coverageGaps ?? []);
  if (taxonomy.endpoint.method === 'UNKNOWN') {
    coverageGaps.add('METHOD_UNAVAILABLE');
  }
  if (normalizedInput.statusCode === undefined) {
    coverageGaps.add('STATUS_UNAVAILABLE');
  }

  return {
    entryId,
    endpoint: taxonomy.endpoint,
    observation: {
      firstSeen: normalizedInput.observedAt,
      lastSeen: normalizedInput.observedAt,
      count: 1,
      sources: [normalizedInput.source],
      sourceOrigins: normalizedInput.sourceOrigin
        ? [normalizeOrigin(normalizedInput.sourceOrigin)]
        : [],
      frameIds: normalizedInput.frameId === undefined ? [] : [normalizedInput.frameId],
      initiatorTypes: normalizedInput.initiatorType ? [normalizedInput.initiatorType] : [],
      resourceTypes: normalizedInput.resourceType ? [normalizedInput.resourceType] : [],
      statusCodes: normalizedInput.statusCode === undefined ? [] : [normalizedInput.statusCode],
      contentTypes: normalizedInput.contentType ? [normalizedInput.contentType] : [],
      protocols: normalizedInput.protocol ? [normalizedInput.protocol] : [],
      cacheStates: [normalizedInput.cacheState ?? 'unknown'],
      requestHeaderNames: normalizedInput.requestHeaderNames ?? [],
      responseHeaderNames: normalizedInput.responseHeaderNames ?? [],
      requestBodyFieldNames: normalizedInput.requestBodyFieldNames ?? [],
      coverageGaps: uniqueSorted([...coverageGaps]),
      bytes: normalizedInput.bytes ? normalizeBytes(normalizedInput.bytes) : undefined
    },
    scope: taxonomy.scope,
    classification: taxonomy.classification,
    priority,
    evidence
  };
}

export async function buildTrafficLedger(
  input: BuildTrafficLedgerInput
): Promise<BlancheTrafficLedgerV1> {
  const generatedAt = normalizeTimestamp(input.generatedAt ?? new Date().toISOString());
  const scopePolicy = normalizeScopePolicy(input.settings.scopePolicy);
  const settings: TrafficLedgerSettings = {
    ...input.settings,
    scopePolicy
  };
  const builtEntries = await Promise.all(
    input.observations.map((observation) => buildTrafficLedgerEntry(observation, settings))
  );
  const entries = mergeTrafficLedgerEntries(builtEntries);
  const targetOrigin = resolveTargetOrigin(input.settings.originContext);
  const ledgerId =
    input.ledgerId ??
    `ledger_${(await sha256Hex(`${input.sourceSessionId}\n${generatedAt}`)).slice(0, 32)}`;

  return {
    kind: BLANCHE_TRAFFIC_LEDGER_KIND,
    schemaVersion: BLANCHE_TRAFFIC_LEDGER_SCHEMA_VERSION,
    metadata: {
      ledgerId,
      generatedAt,
      sourceSessionId: input.sourceSessionId,
      targetOrigin,
      observationWindowStart: input.observationWindowStart
        ? normalizeTimestamp(input.observationWindowStart)
        : undefined,
      observationWindowBasis: input.observationWindowBasis,
      identityModel: 'blanche.endpoint-sha256.v1',
      scoreModel: 'blanche.traffic-priority.v1'
    },
    scopePolicy,
    entries,
    summary: summarizeTrafficLedgerEntries(entries),
    dataHandling: {
      queryValuesIncluded: false,
      fragmentsIncluded: false,
      userinfoIncluded: false,
      pathHandling: {
        model: 'blanche.path-template.v1',
        recognizedIdentifiersTemplated: true,
        unrecognizedPathSegmentsIncluded: true,
        residualIdentifierRisk: true
      },
      rawEvidenceOutsideLedger: true
    }
  };
}

export function mergeTrafficLedgerEntries(entries: TrafficLedgerEntry[]): TrafficLedgerEntry[] {
  const merged = new Map<string, TrafficLedgerEntry>();
  for (const entry of entries) {
    const existing = merged.get(entry.entryId);
    merged.set(entry.entryId, existing ? mergeEntryPair(existing, entry) : entry);
  }
  return [...merged.values()].sort(compareEntries);
}

export function summarizeTrafficLedgerEntries(entries: TrafficLedgerEntry[]): TrafficLedgerSummary {
  const byScope: TrafficLedgerSummary['byScope'] = {
    'in-scope': 0,
    'out-of-scope': 0,
    review: 0,
    unknown: 0
  };
  const byPriority: TrafficLedgerSummary['byPriority'] = {
    low: 0,
    medium: 0,
    high: 0,
    urgent: 0
  };

  for (const entry of entries) {
    byScope[entry.scope.disposition] += 1;
    byPriority[entry.priority.band] += 1;
  }

  return {
    entryCount: entries.length,
    byScope,
    byPriority,
    handoffEligibleCount: byScope['in-scope'],
    highestScore: entries.reduce((highest, entry) => Math.max(highest, entry.priority.score), 0)
  };
}

export function queryTrafficLedger(
  entries: TrafficLedgerEntry[],
  query: TrafficLedgerQuery = {}
): TrafficLedgerEntry[] {
  const minimumScore = clampScore(query.minimumScore ?? 0);
  const matches = entries
    .filter((entry) => !query.scope || query.scope.includes(entry.scope.disposition))
    .filter((entry) => !query.priorityBands || query.priorityBands.includes(entry.priority.band))
    .filter((entry) => entry.priority.score >= minimumScore)
    .filter(
      (entry) =>
        !query.roles || query.roles.some((role) => entry.classification.roles.includes(role))
    )
    .sort(compareEntries);
  const limit = query.limit === undefined ? matches.length : Math.max(0, Math.trunc(query.limit));
  return matches.slice(0, limit);
}

export function serializeTrafficLedgerJsonl(ledger: BlancheTrafficLedgerV1): string {
  const ledgerContext = {
    kind: ledger.kind,
    schemaVersion: ledger.schemaVersion,
    metadata: ledger.metadata,
    scopePolicy: ledger.scopePolicy,
    summary: ledger.summary,
    dataHandling: ledger.dataHandling
  };
  const records = [
    {
      recordType: 'blanche.traffic-ledger.metadata',
      ledger: ledgerContext
    },
    ...ledger.entries.map((entry) => ({
      recordType: 'blanche.traffic-ledger.entry',
      ledgerId: ledger.metadata.ledgerId,
      entry
    }))
  ];
  return `${records.map((record) => JSON.stringify(record)).join('\n')}\n`;
}

export function priorityBandForScore(rawScore: number): TrafficPriorityBand {
  const score = clampScore(rawScore);
  if (score >= 75) return 'urgent';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}

export function defaultTrafficLedgerSettings(targetUrl: string): TrafficLedgerSettings {
  const target = parseTrafficUrl(targetUrl);
  return {
    scopePolicy: createCaptureTargetScopePolicy(targetUrl),
    originContext: {
      targetUrl,
      targetOrigin: target.origin
    }
  };
}

function deriveClassification(
  input: TrafficObservationInput,
  endpoint: TrafficEndpointV1,
  originContext: ScopeOriginContext
): TrafficClassificationV1 {
  const hints = input.classification ?? {};
  const roles = new Set<TrafficRole>(hints.roles ?? []);
  const operations = new Set<TrafficOperation>(hints.operations ?? []);
  const dataClasses = new Set<TrafficDataClass>(hints.dataClasses ?? []);
  const reasons = new Set(hints.reasonCodes ?? []);
  const path = endpoint.pathTemplate.toLowerCase();
  const queryNames = endpoint.queryParameterNames.map((name) => name.toLowerCase());
  const contentType = input.contentType?.toLowerCase() ?? '';
  const resourceType = input.resourceType?.toLowerCase() ?? '';
  const initiatorType = input.initiatorType?.toLowerCase() ?? '';
  const requestHeaderNames = input.requestHeaderNames ?? [];
  const responseHeaderNames = input.responseHeaderNames ?? [];
  const requestBodyFieldNames = input.requestBodyFieldNames ?? [];

  addDerivedRoles(
    roles,
    reasons,
    endpoint,
    path,
    contentType,
    resourceType,
    initiatorType,
    requestHeaderNames,
    responseHeaderNames,
    requestBodyFieldNames
  );
  addDerivedOperations(operations, endpoint.method, roles);
  addDerivedDataClasses(
    dataClasses,
    reasons,
    path,
    [...queryNames, ...requestHeaderNames, ...responseHeaderNames, ...requestBodyFieldNames],
    roles
  );
  if (roles.size === 0) {
    roles.add('other');
  }
  if (operations.size === 0) {
    operations.add('unknown');
  }

  const boundary = classifyBoundary(endpoint, originContext);
  const ownership = hints.ownership ?? (boundary === 'same-origin' ? 'target' : 'unknown');
  const environment = hints.environment ?? inferEnvironment(endpoint.host);
  const confidence = hints.confidence ?? (roles.has('other') ? 'low' : 'medium');

  reasons.add(`BOUNDARY_${toReasonSegment(boundary)}`);
  if (endpoint.method === 'UNKNOWN') {
    reasons.add('METHOD_UNAVAILABLE');
  }

  return {
    boundary,
    ownership,
    environment,
    roles: [...roles].sort(),
    access: hints.access ?? inferAccess(requestHeaderNames, requestBodyFieldNames),
    operations: [...operations].sort(),
    dataClasses: [...dataClasses].sort(),
    confidence,
    reasonCodes: [...reasons].sort()
  };
}

function addDerivedRoles(
  roles: Set<TrafficRole>,
  reasons: Set<string>,
  endpoint: TrafficEndpointV1,
  path: string,
  contentType: string,
  resourceType: string,
  initiatorType: string,
  requestHeaderNames: string[],
  responseHeaderNames: string[],
  requestBodyFieldNames: string[]
): void {
  const add = (role: TrafficRole, reason: string) => {
    roles.add(role);
    reasons.add(reason);
  };
  if (/main_frame|sub_frame|navigation/.test(`${resourceType} ${initiatorType}`)) {
    add('navigation', 'ROLE_NAVIGATION_RESOURCE');
  }
  if (/\.(?:js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot)$/.test(path)) {
    add('static', 'ROLE_STATIC_EXTENSION');
  }
  if (/\.map$/.test(path)) {
    add('source-map', 'ROLE_SOURCE_MAP_EXTENSION');
  }
  if (/worker|serviceworker|sharedworker/.test(`${resourceType} ${initiatorType} ${path}`)) {
    add('worker', 'ROLE_WORKER_SIGNAL');
  }
  if (
    /(?:^|\/)api(?:\/|$)|graphql|\/rpc(?:\/|$)/.test(path) ||
    /json|graphql/.test(contentType) ||
    /fetch|xmlhttprequest|xhr/.test(`${resourceType} ${initiatorType}`) ||
    requestBodyFieldNames.some((name) => /^(?:query|operationname|variables)$/.test(name))
  ) {
    add('api', 'ROLE_API_SIGNAL');
  }
  if (/(?:login|log-in|signin|sign-in|oauth|sso|token|session|authenticate)/.test(path)) {
    add('authentication', 'ROLE_AUTHENTICATION_PATH');
  }
  if (
    responseHeaderNames.some((name) => /^(?:authentication-info|www-authenticate)$/.test(name)) ||
    requestBodyFieldNames.some((name) => /(?:password|passwd|otp|mfa|totp|credential)/.test(name))
  ) {
    add('authentication', 'ROLE_AUTHENTICATION_METADATA_NAME');
  }
  if (/(?:authorize|authorization|permission|entitlement|policy)/.test(path)) {
    add('authorization', 'ROLE_AUTHORIZATION_PATH');
  }
  if (requestBodyFieldNames.some((name) => /(?:permission|entitlement|policy|role|scope)/.test(name))) {
    add('authorization', 'ROLE_AUTHORIZATION_FIELD_NAME');
  }
  if (/(?:^|\/)(?:admin|administrator|manage|management|console)(?:\/|$)/.test(path)) {
    add('administration', 'ROLE_ADMINISTRATION_PATH');
  }
  if (/(?:config|configuration|settings|feature|flag|experiment|variant|bootstrap)/.test(path)) {
    add('configuration', 'ROLE_CONFIGURATION_PATH');
  }
  if (/(?:feature|flag|experiment|variant|rollout)/.test(path)) {
    add('client-control', 'ROLE_CLIENT_CONTROL_PATH');
  }
  if (/(?:upload|import|attachment)/.test(path)) {
    add('upload', 'ROLE_UPLOAD_PATH');
  }
  if (requestBodyFieldNames.some((name) => /(?:file|upload|attachment|import)/.test(name))) {
    add('upload', 'ROLE_UPLOAD_FIELD_NAME');
  }
  if (/(?:download|export|report|attachment)/.test(path)) {
    add('download', 'ROLE_DOWNLOAD_PATH');
  }
  if (
    ['ws', 'wss'].includes(endpoint.scheme) ||
    /websocket|eventstream|event-stream|socket|subscribe/.test(
      `${resourceType} ${initiatorType} ${contentType} ${path}`
    )
  ) {
    add('realtime', 'ROLE_REALTIME_SIGNAL');
  }
  if (/(?:telemetry|analytics|metrics|beacon|tracking|collect|events)/.test(path)) {
    add('telemetry', 'ROLE_TELEMETRY_PATH');
  }
  if (
    requestHeaderNames.some((name) => /^(?:authorization|proxy-authorization|x-api-key|x-auth-token)$/.test(name))
  ) {
    reasons.add('ACCESS_AUTHENTICATED_HEADER_NAME');
  }
}

function addDerivedOperations(
  operations: Set<TrafficOperation>,
  method: string,
  roles: Set<TrafficRole>
): void {
  switch (method) {
    case 'GET':
    case 'HEAD':
    case 'OPTIONS':
      operations.add('read');
      break;
    case 'POST':
      operations.add('create');
      break;
    case 'PUT':
    case 'PATCH':
      operations.add('update');
      break;
    case 'DELETE':
      operations.add('delete');
      break;
    case 'UNKNOWN':
      break;
    default:
      operations.add('execute');
  }
  if (roles.has('authentication')) operations.add('authenticate');
  if (roles.has('authorization')) operations.add('authorize');
  if (roles.has('upload')) operations.add('upload');
  if (roles.has('download')) operations.add('download');
  if (roles.has('realtime')) operations.add('subscribe');
}

function addDerivedDataClasses(
  dataClasses: Set<TrafficDataClass>,
  reasons: Set<string>,
  path: string,
  queryNames: string[],
  roles: Set<TrafficRole>
): void {
  const searchable = `${path} ${queryNames.join(' ')}`;
  const add = (dataClass: TrafficDataClass, reason: string) => {
    dataClasses.add(dataClass);
    reasons.add(reason);
  };
  if (/(?:password|passwd|secret|credential|access.?token|api.?key)/.test(searchable)) {
    add('credential', 'DATA_CLASS_CREDENTIAL_NAME');
  }
  if (/(?:session|cookie|refresh.?token)/.test(searchable)) {
    add('session', 'DATA_CLASS_SESSION_NAME');
  }
  if (/(?:email|phone|address|profile|person|customer|user)/.test(searchable)) {
    add('personal', 'DATA_CLASS_PERSONAL_NAME');
  }
  if (/(?:payment|billing|card|bank|invoice|financial)/.test(searchable)) {
    add('financial', 'DATA_CLASS_FINANCIAL_NAME');
  }
  if (/(?:health|medical|patient|diagnosis)/.test(searchable)) {
    add('health', 'DATA_CLASS_HEALTH_NAME');
  }
  if (roles.has('administration') || /(?:internal|private)/.test(searchable)) {
    add('internal', 'DATA_CLASS_INTERNAL_SIGNAL');
  }
  if (roles.has('source-map')) {
    add('source-code', 'DATA_CLASS_SOURCE_MAP');
  }
}

function classifyBoundary(
  endpoint: TrafficEndpointV1,
  originContext: ScopeOriginContext
): TrafficBoundary {
  const rawTarget = originContext.targetOrigin ?? originContext.targetUrl;
  if (!rawTarget) {
    return 'unknown';
  }
  try {
    const target = parseTrafficUrl(rawTarget);
    const targetScheme = target.protocol.slice(0, -1).toLowerCase();
    const targetHost = normalizeHost(target.hostname);
    const targetPort = effectivePort(target);
    if (
      endpoint.scheme === targetScheme &&
      endpoint.host === targetHost &&
      endpoint.port === targetPort
    ) {
      return 'same-origin';
    }
    if (
      endpoint.scheme === targetScheme &&
      (endpoint.host === targetHost ||
        (Boolean(endpoint.registrableDomain) &&
          endpoint.registrableDomain === originContext.targetRegistrableDomain))
    ) {
      return 'same-site';
    }
    return 'cross-site';
  } catch {
    return 'unknown';
  }
}

function inferEnvironment(host: string): TrafficEnvironment {
  if (host === 'localhost' || host.endsWith('.localhost') || isPrivateIpv4(host)) {
    return 'local';
  }
  const labels = host.split('.');
  if (labels.some((label) => /^(?:stage|staging|preprod|pre-prod|uat)$/.test(label))) {
    return 'staging';
  }
  if (labels.some((label) => /^(?:dev|develop|development|sandbox)$/.test(label))) {
    return 'development';
  }
  if (labels.some((label) => /^(?:test|testing|qa)$/.test(label))) {
    return 'test';
  }
  return 'unknown';
}

function mergeEntryPair(left: TrafficLedgerEntry, right: TrafficLedgerEntry): TrafficLedgerEntry {
  const classification = mergeClassifications(left.classification, right.classification);
  const evidence = dedupeEvidence([...left.evidence, ...right.evidence]);
  const priority = scoreTrafficClassification(
    classification,
    strongerConfidence(left.priority.evidenceConfidence, right.priority.evidenceConfidence),
    evidence.map((entry) => entry.id)
  );
  return {
    entryId: left.entryId,
    endpoint: left.endpoint,
    observation: {
      firstSeen: earlierTimestamp(left.observation.firstSeen, right.observation.firstSeen),
      lastSeen: laterTimestamp(left.observation.lastSeen, right.observation.lastSeen),
      count: left.observation.count + right.observation.count,
      sources: uniqueSortedValues([...left.observation.sources, ...right.observation.sources]),
      sourceOrigins: uniqueSorted([...left.observation.sourceOrigins, ...right.observation.sourceOrigins]),
      frameIds: uniqueSortedNumbers([...left.observation.frameIds, ...right.observation.frameIds]),
      initiatorTypes: uniqueSorted([
        ...left.observation.initiatorTypes,
        ...right.observation.initiatorTypes
      ]),
      resourceTypes: uniqueSorted([
        ...left.observation.resourceTypes,
        ...right.observation.resourceTypes
      ]),
      statusCodes: uniqueSortedNumbers([
        ...left.observation.statusCodes,
        ...right.observation.statusCodes
      ]),
      contentTypes: uniqueSorted([
        ...left.observation.contentTypes,
        ...right.observation.contentTypes
      ]),
      protocols: uniqueSorted([...left.observation.protocols, ...right.observation.protocols]),
      cacheStates: uniqueSortedValues([
        ...left.observation.cacheStates,
        ...right.observation.cacheStates
      ]),
      requestHeaderNames: uniqueSorted([
        ...left.observation.requestHeaderNames,
        ...right.observation.requestHeaderNames
      ]),
      responseHeaderNames: uniqueSorted([
        ...left.observation.responseHeaderNames,
        ...right.observation.responseHeaderNames
      ]),
      requestBodyFieldNames: uniqueSorted([
        ...left.observation.requestBodyFieldNames,
        ...right.observation.requestBodyFieldNames
      ]),
      coverageGaps: uniqueSorted([
        ...left.observation.coverageGaps,
        ...right.observation.coverageGaps
      ]),
      bytes: mergeBytes(left.observation.bytes, right.observation.bytes)
    },
    scope: mergeScopeDecisions(left.scope, right.scope),
    classification,
    priority,
    evidence
  };
}

function mergeClassifications(
  left: TrafficClassificationV1,
  right: TrafficClassificationV1
): TrafficClassificationV1 {
  return {
    boundary: selectBoundary(left.boundary, right.boundary),
    ownership: selectKnownValue(left.ownership, right.ownership),
    environment: selectKnownValue(left.environment, right.environment),
    roles: uniqueSortedValues([...left.roles, ...right.roles]),
    access: selectAccess(left.access, right.access),
    operations: uniqueSortedValues([...left.operations, ...right.operations]),
    dataClasses: uniqueSortedValues([...left.dataClasses, ...right.dataClasses]),
    confidence: strongerConfidence(left.confidence, right.confidence),
    reasonCodes: uniqueSorted([...left.reasonCodes, ...right.reasonCodes])
  };
}

function mergeScopeDecisions(
  left: TrafficScopeDecisionV1,
  right: TrafficScopeDecisionV1
): TrafficScopeDecisionV1 {
  const rank: Record<TrafficScopeDisposition, number> = {
    'out-of-scope': 4,
    unknown: 3,
    review: 2,
    'in-scope': 1
  };
  const selected = rank[right.disposition] > rank[left.disposition] ? right : left;
  return {
    ...selected,
    matchedRuleIds: uniqueSorted([...left.matchedRuleIds, ...right.matchedRuleIds]),
    reasonCodes: uniqueSorted([...left.reasonCodes, ...right.reasonCodes]),
    evaluatedAt: laterTimestamp(left.evaluatedAt, right.evaluatedAt)
  };
}

function normalizeObservation(input: TrafficObservationInput): TrafficObservationInput {
  return {
    ...input,
    url: input.url.trim(),
    observedAt: normalizeTimestamp(input.observedAt),
    method: input.method ? normalizeMethod(input.method) : undefined,
    sourceOrigin: input.sourceOrigin ? normalizeOrigin(input.sourceOrigin) : undefined,
    initiatorType: input.initiatorType?.trim() || undefined,
    resourceType: input.resourceType?.trim() || undefined,
    contentType: input.contentType?.trim().toLowerCase() || undefined,
    protocol: input.protocol?.trim().toLowerCase() || undefined,
    statusCode:
      input.statusCode === undefined || !Number.isFinite(input.statusCode)
        ? undefined
        : Math.min(999, Math.max(0, Math.trunc(input.statusCode))),
    frameId:
      input.frameId === undefined || !Number.isFinite(input.frameId)
        ? undefined
        : Math.trunc(input.frameId),
    cacheState: input.cacheState ?? 'unknown',
    requestHeaderNames: normalizeMetadataNames(input.requestHeaderNames, 'header'),
    responseHeaderNames: normalizeMetadataNames(input.responseHeaderNames, 'header'),
    requestBodyFieldNames: normalizeMetadataNames(input.requestBodyFieldNames, 'field'),
    coverageGaps: input.coverageGaps ? uniqueSorted(input.coverageGaps) : undefined,
    bytes: input.bytes ? normalizeBytes(input.bytes) : undefined,
    evidence: input.evidence ? dedupeEvidence(input.evidence) : undefined
  };
}

function normalizeBytes(bytes: NonNullable<TrafficObservationInput['bytes']>): {
  transfer: number;
  encoded: number;
  decoded: number;
} {
  return {
    transfer: normalizeByteCount(bytes.transfer),
    encoded: normalizeByteCount(bytes.encoded),
    decoded: normalizeByteCount(bytes.decoded)
  };
}

function mergeBytes(
  left: TrafficLedgerEntry['observation']['bytes'],
  right: TrafficLedgerEntry['observation']['bytes']
): TrafficLedgerEntry['observation']['bytes'] {
  if (!left && !right) {
    return undefined;
  }
  return {
    transfer: (left?.transfer ?? 0) + (right?.transfer ?? 0),
    encoded: (left?.encoded ?? 0) + (right?.encoded ?? 0),
    decoded: (left?.decoded ?? 0) + (right?.decoded ?? 0)
  };
}

function normalizeByteCount(value: number | undefined): number {
  return value === undefined || !Number.isFinite(value) ? 0 : Math.max(0, Math.trunc(value));
}

function inferAccess(
  requestHeaderNames: string[],
  requestBodyFieldNames: string[]
): TrafficAccess {
  if (
    requestHeaderNames.some((name) =>
      /^(?:authorization|proxy-authorization|cookie|x-api-key|x-auth-token)$/.test(name)
    ) ||
    requestBodyFieldNames.some((name) =>
      /(?:access.?token|api.?key|credential|password|session)/.test(name)
    )
  ) {
    return 'authenticated';
  }
  return 'unknown';
}

function normalizeMetadataNames(
  values: string[] | undefined,
  kind: 'header' | 'field'
): string[] | undefined {
  if (!values) {
    return undefined;
  }
  const names = values.flatMap((value) => {
    const delimiterIndex = kind === 'header' ? value.indexOf(':') : value.search(/[:=]/);
    const candidate = (delimiterIndex < 0 ? value : value.slice(0, delimiterIndex))
      .trim()
      .toLowerCase();
    const valid =
      candidate.length > 0 &&
      candidate.length <= 128 &&
      (kind === 'header'
        ? /^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(candidate)
        : /^[a-z0-9_.\[\]/-]+$/.test(candidate));
    return valid ? [candidate] : [];
  });
  return uniqueSorted(names);
}

function templatePath(pathname: string): string {
  const segments = pathname.split('/');
  let previousLabel = '';
  const templated = segments.map((rawSegment) => {
    const decoded = safeDecode(rawSegment);
    const normalized = decoded.toLowerCase();
    let output = rawSegment;
    if (
      /^[^/@\s]+@[^/@\s]+\.[^/@\s]+$/.test(decoded) ||
      /^\+?\d[\d(). -]{6,}\d$/.test(decoded)
    ) {
      output = '{secret}';
    } else if (/^\d+$/.test(decoded)) {
      output = '{int}';
    } else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(decoded)) {
      output = '{uuid}';
    } else if (/^[0-9a-f]{16,}$/i.test(decoded)) {
      output = '{hex}';
    } else if (
      (decoded.length >= 20 && /^[a-z0-9_~+/=-]+$/i.test(decoded)) ||
      /^[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}$/i.test(decoded)
    ) {
      output = '{token}';
    } else if (
      rawSegment &&
      SENSITIVE_PATH_LABELS.has(previousLabel) &&
      !SAFE_ROUTE_PATH_SEGMENTS.has(normalized)
    ) {
      output = '{secret}';
    }
    previousLabel = normalized;
    return output;
  });
  return templated.join('/') || '/';
}

function parseTrafficUrl(rawUrl: string): URL {
  const url = new URL(rawUrl);
  normalizeTrafficScheme(url.protocol);
  return url;
}

function normalizeTrafficScheme(rawScheme: string): TrafficScheme {
  const scheme = rawScheme.trim().toLowerCase().replace(/:$/, '');
  switch (scheme) {
    case 'http':
    case 'https':
    case 'ws':
    case 'wss':
      return scheme;
    default:
      throw new Error(`Unsupported traffic URL scheme: ${rawScheme}`);
  }
}

function normalizeHost(rawHost: string): string {
  return rawHost.trim().toLowerCase().replace(/\.$/, '');
}

function normalizeMethod(rawMethod?: string): string {
  if (!rawMethod?.trim()) {
    return 'UNKNOWN';
  }
  const method = rawMethod.trim().toUpperCase();
  if (!/^[A-Z][A-Z0-9._-]*$/.test(method)) {
    throw new Error(`Invalid HTTP method: ${rawMethod}`);
  }
  return method;
}

function effectivePort(url: URL): number {
  if (url.port) {
    return Number(url.port);
  }
  return url.protocol === 'https:' || url.protocol === 'wss:' ? 443 : 80;
}

async function endpointEntryId(endpoint: TrafficEndpointV1): Promise<string> {
  const identity = [
    endpoint.method,
    endpoint.scheme,
    endpoint.host,
    String(endpoint.port),
    endpoint.pathTemplate,
    endpoint.queryParameterNames.join('&')
  ].join('\n');
  return `traffic_${await sha256Hex(identity)}`;
}

async function sha256Hex(value: string): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto SHA-256 is unavailable in this runtime.');
  }
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function resolveTargetOrigin(context: ScopeOriginContext): string | undefined {
  const rawTarget = context.targetOrigin ?? context.targetUrl;
  if (!rawTarget) {
    return undefined;
  }
  try {
    return parseTrafficUrl(rawTarget).origin;
  } catch {
    return undefined;
  }
}

function normalizeOrigin(rawOrigin: string): string {
  return parseTrafficUrl(rawOrigin).origin;
}

function normalizeTimestamp(value: string): string {
  const timestamp = new Date(value);
  if (!Number.isFinite(timestamp.getTime())) {
    throw new Error(`Invalid traffic observation timestamp: ${value}`);
  }
  return timestamp.toISOString();
}

function isStateChangingOperation(operation: TrafficOperation): boolean {
  return ['create', 'update', 'delete', 'execute', 'upload'].includes(operation);
}

function evidenceConfidenceForSources(sources: TrafficObservationSource[]): ConfidenceLevel {
  if (sources.some((source) => source === 'burp-proxy' || source === 'chromium-web-request')) {
    return 'high';
  }
  if (
    sources.some(
      (source) => source === 'chromium-performance' || source === 'chromium-instrumentation'
    )
  ) {
    return 'medium';
  }
  return 'low';
}

function priorityBandRank(band: TrafficPriorityBand): number {
  return { urgent: 4, high: 3, medium: 2, low: 1 }[band];
}

function compareEntries(left: TrafficLedgerEntry, right: TrafficLedgerEntry): number {
  return (
    right.priority.score - left.priority.score ||
    priorityBandRank(right.priority.band) - priorityBandRank(left.priority.band) ||
    left.entryId.localeCompare(right.entryId)
  );
}

function selectBoundary(left: TrafficBoundary, right: TrafficBoundary): TrafficBoundary {
  const rank: Record<TrafficBoundary, number> = {
    'cross-site': 4,
    'same-site': 3,
    'same-origin': 2,
    unknown: 1
  };
  return rank[right] > rank[left] ? right : left;
}

function selectKnownValue<T extends string>(left: T, right: T): T {
  if (left === 'unknown') return right;
  return left;
}

function selectAccess(left: TrafficAccess, right: TrafficAccess): TrafficAccess {
  const rank: Record<TrafficAccess, number> = {
    privileged: 5,
    authenticated: 4,
    service: 3,
    anonymous: 2,
    unknown: 1
  };
  return rank[right] > rank[left] ? right : left;
}

function strongerConfidence(left: ConfidenceLevel, right: ConfidenceLevel): ConfidenceLevel {
  const rank: Record<ConfidenceLevel, number> = { high: 3, medium: 2, low: 1 };
  return rank[right] > rank[left] ? right : left;
}

function dedupeEvidence(entries: TrafficEvidenceReferenceV1[]): TrafficEvidenceReferenceV1[] {
  const seen = new Set<string>();
  return entries.filter((entry) => {
    const key = `${entry.kind}:${entry.source}:${entry.id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function clampScore(score: number): number {
  if (!Number.isFinite(score)) return 0;
  return Math.max(0, Math.min(100, Math.round(score)));
}

function earlierTimestamp(left: string, right: string): string {
  return new Date(left).getTime() <= new Date(right).getTime() ? left : right;
}

function laterTimestamp(left: string, right: string): string {
  return new Date(left).getTime() >= new Date(right).getTime() ? left : right;
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))].sort((left, right) =>
    left.localeCompare(right)
  );
}

function uniqueSortedNumbers(values: number[]): number[] {
  return [...new Set(values)].sort((left, right) => left - right);
}

function uniqueSortedValues<T extends string>(values: T[]): T[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function isPrivateIpv4(host: string): boolean {
  const parts = host.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) {
    return false;
  }
  const first = parts[0] ?? -1;
  const second = parts[1] ?? -1;
  return (
    first === 10 ||
    first === 127 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  );
}

function toReasonSegment(value: string): string {
  return value.toUpperCase().replace(/[^A-Z0-9]+/g, '_');
}
