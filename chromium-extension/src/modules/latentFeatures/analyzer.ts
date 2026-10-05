import type { JsonValue } from '../../../../shared-schema/src';
import type {
  LatentFeatureCandidate,
  LatentFeatureConfidence,
  LatentFeatureEvidence,
  LatentFeatureStorageArea,
  LatentFeatureStorageLocation
} from '../../shared/latentFeatureWorkbench';

export interface LatentFeatureTextSource {
  sourceKind: 'bundle' | 'inline-script' | 'document';
  label: string;
  sourceUrl?: string;
  contentType?: string;
  truncated?: boolean;
  text: string;
}

export interface LatentFeatureStorageEntry {
  area: LatentFeatureStorageArea;
  key: string;
  value: string;
}

export interface LatentFeatureStructuredSource {
  sourceKind: 'runtime-global' | 'dom';
  label: string;
  value: JsonValue;
}

export interface RuntimeObservedFeatureCandidate {
  key: string;
  currentValue?: JsonValue;
  suggestedValue?: JsonValue;
  confidence?: LatentFeatureConfidence;
  sourceUrl?: string;
  detail?: string;
}

export interface LatentFeatureAnalysisInput {
  textSources: LatentFeatureTextSource[];
  storageEntries: LatentFeatureStorageEntry[];
  structuredSources: LatentFeatureStructuredSource[];
  runtimeObservedCandidates: RuntimeObservedFeatureCandidate[];
  maxCandidates: number;
}

interface ToggleValues {
  currentValue: JsonValue;
  suggestedValue: JsonValue;
  enabledValue: JsonValue;
  disabledValue: JsonValue;
}

const FLAG_NAME_PATTERN =
  /(?:^|[-_.:/])(?:feature|features|flag|flags|experiment|experiments|variant|variation|rollout|beta|preview|labs?|gate|gates|toggle|toggles|enabled?|disabled?)(?:$|[-_.:/])/i;
const CAMEL_FLAG_PATTERN =
  /(?:feature|flag|experiment|variant|variation|rollout|preview|beta|labs?|gate|toggle|enabled|disabled|new[A-Z]|legacy[A-Z])/;
const SENSITIVE_NAME_PATTERN =
  /(?:^|[-_.:/])(?:auth(?:entication)?|authorization|cookies?|api[-_]?keys?|private[-_]?keys?|access[-_]?tokens?|refresh[-_]?tokens?|jwt|csrf|passwords?|passwd|secrets?|credentials?|sessions?|session[-_]?ids?|licenses?|subscriptions?|permissions?|roles?)(?:$|[-_.:/])/i;
const HASH_PATTERN = /^[a-f0-9]{8,64}$/i;

export function analyzeLatentFeatures(
  input: LatentFeatureAnalysisInput
): LatentFeatureCandidate[] {
  const candidates = new Map<string, LatentFeatureCandidate>();
  const ambiguousStorageCandidates = new Set<string>();

  const observe = (candidate: Omit<LatentFeatureCandidate, 'id' | 'normalizedKey' | 'status'>) => {
    const key = cleanKey(candidate.key);
    if (!key || isSensitiveKey(key)) {
      return;
    }

    const normalizedKey = normalizeKey(key);
    const existing = candidates.get(normalizedKey);
    if (!existing) {
      candidates.set(normalizedKey, {
        ...candidate,
        id: stableCandidateId(normalizedKey),
        key,
        normalizedKey,
        status: 'discovered'
      });
      return;
    }

    existing.evidence = mergeEvidence(existing.evidence, candidate.evidence);
    existing.confidence = strongerConfidence(existing.confidence, candidate.confidence);
    const storageConflict =
      existing.storageLocation !== undefined &&
      candidate.storageLocation !== undefined &&
      !sameStorageLocation(existing.storageLocation, candidate.storageLocation);
    if (storageConflict) {
      ambiguousStorageCandidates.add(normalizedKey);
      existing.storageLocation = undefined;
      existing.probeable = false;
    } else if (ambiguousStorageCandidates.has(normalizedKey)) {
      existing.storageLocation = undefined;
      existing.probeable = false;
    } else {
      existing.probeable = existing.probeable || candidate.probeable;
      if (!existing.storageLocation && candidate.storageLocation) {
        existing.storageLocation = candidate.storageLocation;
        existing.controlSurface = candidate.controlSurface;
        existing.currentValue = candidate.currentValue;
        existing.suggestedValue = candidate.suggestedValue;
        existing.enabledValue = candidate.enabledValue;
        existing.disabledValue = candidate.disabledValue;
      }
    }
    if (existing.currentValue === undefined && candidate.currentValue !== undefined) {
      existing.currentValue = candidate.currentValue;
    }
    if (existing.suggestedValue === undefined && candidate.suggestedValue !== undefined) {
      existing.suggestedValue = candidate.suggestedValue;
    }
    if (existing.enabledValue === undefined && candidate.enabledValue !== undefined) {
      existing.enabledValue = candidate.enabledValue;
    }
    if (existing.disabledValue === undefined && candidate.disabledValue !== undefined) {
      existing.disabledValue = candidate.disabledValue;
    }
  };

  for (const entry of input.storageEntries) {
    analyzeStorageEntry(entry, observe);
  }

  for (const source of input.structuredSources) {
    analyzeStructuredValue(source, observe);
  }

  for (const source of input.textSources) {
    analyzeTextSource(source, observe);
  }

  for (const observed of input.runtimeObservedCandidates) {
    if (!observed.key || isSensitiveKey(observed.key)) {
      continue;
    }

    observe({
      key: observed.key,
      currentValue: observed.currentValue,
      suggestedValue: observed.suggestedValue,
      confidence: observed.confidence ?? 'medium',
      probeable: false,
      controlSurface: 'runtime-response',
      evidence: [
        {
          sourceKind: 'runtime-response',
          label: observed.sourceUrl ?? 'runtime response',
          sourceUrl: observed.sourceUrl,
          detail: observed.detail ?? 'Flag-shaped value observed in an already-delivered response.'
        }
      ]
    });
  }

  return [...candidates.values()]
    .sort(compareCandidates)
    .slice(0, Math.max(1, input.maxCandidates));
}

function analyzeStorageEntry(
  entry: LatentFeatureStorageEntry,
  observe: (
    candidate: Omit<LatentFeatureCandidate, 'id' | 'normalizedKey' | 'status'>
  ) => void
): void {
  if (isSensitiveKey(entry.key)) {
    return;
  }
  const sourceKind = entry.area;
  const directToggle = parseToggleValue(entry.value);
  if (directToggle && looksLikeFlagName(entry.key)) {
    observe({
      key: entry.key,
      ...directToggle,
      confidence: 'high',
      probeable: true,
      controlSurface: entry.area,
      storageLocation: {
        area: entry.area,
        storageKey: entry.key,
        jsonPath: [],
        format: 'direct'
      },
      evidence: [
        {
          sourceKind,
          label: `${entry.area}.${entry.key}`,
          detail: 'Flag-shaped key and toggle value are present in browser storage.'
        }
      ]
    });
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(entry.value);
  } catch {
    return;
  }

  if (typeof parsed !== 'object' || parsed === null) {
    return;
  }

  walkStructuredValue({
    value: parsed,
    rootLabel: entry.key,
    path: [],
    inheritedFlagContext: looksLikeFlagName(entry.key),
    maxNodes: 500,
    onToggle(path, key, toggle) {
      const storageLocation: LatentFeatureStorageLocation = {
        area: entry.area,
        storageKey: entry.key,
        jsonPath: path,
        format: 'json'
      };
      observe({
        key,
        ...toggle,
        confidence: looksLikeFlagName(key) ? 'high' : 'medium',
        probeable: true,
        controlSurface: entry.area,
        storageLocation,
        evidence: [
          {
            sourceKind,
            label: `${entry.area}.${entry.key}`,
            detail: `Toggle value is stored at JSON path ${path.join('.')}.`
          }
        ]
      });
    }
  });
}

function analyzeStructuredValue(
  source: LatentFeatureStructuredSource,
  observe: (
    candidate: Omit<LatentFeatureCandidate, 'id' | 'normalizedKey' | 'status'>
  ) => void
): void {
  walkStructuredValue({
    value: source.value,
    rootLabel: source.label,
    path: [],
    inheritedFlagContext: looksLikeFlagName(source.label),
    maxNodes: 500,
    onToggle(path, key, toggle) {
      observe({
        key,
        ...toggle,
        confidence: looksLikeFlagName(key) ? 'high' : 'medium',
        probeable: false,
        controlSurface: source.sourceKind,
        evidence: [
          {
            sourceKind: source.sourceKind,
            label: source.label,
            detail: `Flag-shaped runtime value observed at ${path.join('.')}.`
          }
        ]
      });
    }
  });
}

function walkStructuredValue(input: {
  value: unknown;
  rootLabel: string;
  path: string[];
  inheritedFlagContext: boolean;
  maxNodes: number;
  onToggle(path: string[], key: string, toggle: ToggleValues): void;
}): void {
  let visited = 0;

  const visit = (value: unknown, path: string[], inheritedFlagContext: boolean) => {
    if (visited >= input.maxNodes) {
      return;
    }
    visited += 1;

    if (Array.isArray(value)) {
      for (const [index, entry] of value.slice(0, 100).entries()) {
        visit(entry, [...path, String(index)], inheritedFlagContext);
      }
      return;
    }

    if (!value || typeof value !== 'object') {
      return;
    }

    const record = value as Record<string, unknown>;
    const identity = ['featureKey', 'flagKey', 'key', 'feature', 'name', 'id']
      .map((key) => record[key])
      .find((entry): entry is string => typeof entry === 'string' && entry.length >= 2);
    const stateEntry = ['enabled', 'isEnabled', 'value', 'variation', 'variant', 'state']
      .map((key) => [key, record[key]] as const)
      .find((entry) => parseToggleValue(entry[1]) !== undefined);
    if (identity && stateEntry && !isSensitiveKey(identity)) {
      const toggle = parseToggleValue(stateEntry[1]);
      if (toggle) {
        input.onToggle([...path, stateEntry[0]], identity, toggle);
      }
    }

    for (const [key, entry] of Object.entries(record).slice(0, 200)) {
      if (isSensitiveKey(key)) {
        continue;
      }
      const nextPath = [...path, key];
      const flagContext = inheritedFlagContext || looksLikeFlagName(key);
      const toggle = parseToggleValue(entry);
      if (
        toggle &&
        flagContext &&
        !isSensitiveKey(key) &&
        (!identity || stateEntry?.[0] !== key)
      ) {
        input.onToggle(nextPath, key, toggle);
      }

      if (entry && typeof entry === 'object') {
        visit(entry, nextPath, flagContext);
      }
    }
  };

  visit(input.value, input.path, input.inheritedFlagContext);
}

function analyzeTextSource(
  source: LatentFeatureTextSource,
  observe: (
    candidate: Omit<LatentFeatureCandidate, 'id' | 'normalizedKey' | 'status'>
  ) => void
): void {
  const providerCallPattern =
    /(?:isEnabled|isFeatureEnabled|featureEnabled|hasFeature|useFeature|variation|getFeatureFlag|getBooleanValue|checkGate|isGateEnabled)\s*\(\s*["'`]([^"'`]{2,160})["'`]/g;
  for (const match of source.text.matchAll(providerCallPattern)) {
    const key = match[1];
    if (!key || isSensitiveKey(key)) {
      continue;
    }
    observe({
      key,
      suggestedValue: true,
      confidence: 'high',
      probeable: false,
      controlSurface: 'bundle',
      evidence: [textEvidence(source, match.index, match[0].length, 'Flag-client callsite in shipped code.')]
    });
  }

  const storagePattern =
    /(localStorage|sessionStorage)\.(?:getItem|setItem)\(\s*["'`]([^"'`]{2,160})["'`]/g;
  for (const match of source.text.matchAll(storagePattern)) {
    const key = match[2];
    if (!key || !looksLikeFlagName(key) || isSensitiveKey(key)) {
      continue;
    }
    observe({
      key,
      suggestedValue: true,
      confidence: 'medium',
      probeable: false,
      controlSurface: match[1] as LatentFeatureStorageArea,
      evidence: [
        textEvidence(
          source,
          match.index,
          match[0].length,
          `Shipped code reads or writes the ${match[1]} key.`
        )
      ]
    });
  }

  const objectTogglePattern =
    /(?:["'`]([^"'`]{2,160})["'`]|([A-Za-z_$][\w$.-]{1,159}))\s*:\s*(true|false|!0|!1|0|1|["'`](?:enabled|disabled|on|off|control|treatment|yes|no)["'`])/g;
  for (const match of source.text.matchAll(objectTogglePattern)) {
    const key = match[1] ?? match[2];
    const rawValue = unquote(match[3] ?? '');
    const toggle = parseToggleValue(rawValue === '!0' ? true : rawValue === '!1' ? false : rawValue);
    const nearby = source.text.slice(Math.max(0, (match.index ?? 0) - 120), (match.index ?? 0) + 240);
    const flagContext = Boolean(key && looksLikeFlagName(key)) || /feature|flag|experiment|variant|gate/i.test(nearby);
    if (!key || !toggle || !flagContext || isSensitiveKey(key)) {
      continue;
    }
    observe({
      key,
      ...toggle,
      confidence: looksLikeFlagName(key) ? 'high' : 'medium',
      probeable: false,
      controlSurface: 'bundle',
      evidence: [
        textEvidence(
          source,
          match.index,
          match[0].length,
          'Toggle-shaped key/value pair in shipped code.'
        )
      ]
    });
  }

  const assignmentPattern =
    /\.([A-Za-z_$][\w$]{1,159})\s*=\s*(true|false|!0|!1|0|1)(?![\w$])/g;
  for (const match of source.text.matchAll(assignmentPattern)) {
    const key = match[1];
    if (!key || !looksLikeFlagName(key) || isSensitiveKey(key)) {
      continue;
    }
    const rawValue = match[2];
    const toggle = parseToggleValue(rawValue === '!0' ? true : rawValue === '!1' ? false : rawValue);
    if (!toggle) {
      continue;
    }
    observe({
      key,
      ...toggle,
      confidence: 'medium',
      probeable: false,
      controlSurface: 'bundle',
      evidence: [
        textEvidence(source, match.index, match[0].length, 'Toggle assignment in shipped code.')
      ]
    });
  }

  const opaquePairPattern =
    /["'`]([a-f0-9]{8,64})["'`]\s*:\s*["'`]([a-f0-9]{8,64})["'`]/gi;
  for (const match of source.text.matchAll(opaquePairPattern)) {
    const key = match[1];
    const value = match[2];
    if (!key || !value) {
      continue;
    }
    observe({
      key,
      currentValue: value,
      confidence: 'low',
      probeable: false,
      controlSurface: 'opaque-pair',
      evidence: [
        textEvidence(
          source,
          match.index,
          match[0].length,
          'Opaque hash-like key/value pair retained for runtime correlation; no reversal attempted.'
        )
      ]
    });
  }
}

function textEvidence(
  source: LatentFeatureTextSource,
  index: number | undefined,
  length: number,
  detail: string
): LatentFeatureEvidence {
  const start = Math.max(0, (index ?? 0) - 80);
  const end = Math.min(source.text.length, (index ?? 0) + length + 80);
  return {
    sourceKind: source.sourceKind,
    label: source.label,
    sourceUrl: source.sourceUrl,
    detail,
    snippet: source.text.slice(start, end).replace(/\s+/g, ' ').slice(0, 240)
  };
}

function parseToggleValue(value: unknown): ToggleValues | undefined {
  if (value === true) {
    return {
      currentValue: true,
      suggestedValue: false,
      enabledValue: true,
      disabledValue: false
    };
  }
  if (value === false) {
    return {
      currentValue: false,
      suggestedValue: true,
      enabledValue: true,
      disabledValue: false
    };
  }
  if (value === 0 || value === '0') {
    return {
      currentValue: value === 0 ? 0 : '0',
      suggestedValue: value === 0 ? 1 : '1',
      enabledValue: value === 0 ? 1 : '1',
      disabledValue: value === 0 ? 0 : '0'
    };
  }
  if (value === 1 || value === '1') {
    return {
      currentValue: value === 1 ? 1 : '1',
      suggestedValue: value === 1 ? 0 : '0',
      enabledValue: value === 1 ? 1 : '1',
      disabledValue: value === 1 ? 0 : '0'
    };
  }
  if (typeof value !== 'string') {
    return undefined;
  }

  const normalized = value.trim().toLowerCase();
  const pairs: Record<string, { enabled: string; disabled: string }> = {
    false: { enabled: 'true', disabled: 'false' },
    true: { enabled: 'true', disabled: 'false' },
    off: { enabled: 'on', disabled: 'off' },
    on: { enabled: 'on', disabled: 'off' },
    disabled: { enabled: 'enabled', disabled: 'disabled' },
    enabled: { enabled: 'enabled', disabled: 'disabled' },
    no: { enabled: 'yes', disabled: 'no' },
    yes: { enabled: 'yes', disabled: 'no' },
    control: { enabled: 'treatment', disabled: 'control' },
    treatment: { enabled: 'treatment', disabled: 'control' }
  };
  const pair = pairs[normalized];
  if (!pair) {
    return undefined;
  }
  const currentlyEnabled = normalized === pair.enabled;
  return {
    currentValue: value,
    suggestedValue: currentlyEnabled ? pair.disabled : pair.enabled,
    enabledValue: currentlyEnabled ? value : pair.enabled,
    disabledValue: currentlyEnabled ? pair.disabled : value
  };
}

function looksLikeFlagName(value: string): boolean {
  if (!value || value.length > 180) {
    return false;
  }
  return FLAG_NAME_PATTERN.test(value) || CAMEL_FLAG_PATTERN.test(value);
}

function isSensitiveKey(value: string): boolean {
  return SENSITIVE_NAME_PATTERN.test(value);
}

function sameStorageLocation(
  left: LatentFeatureStorageLocation,
  right: LatentFeatureStorageLocation
): boolean {
  return (
    left.area === right.area &&
    left.storageKey === right.storageKey &&
    left.format === right.format &&
    left.jsonPath.length === right.jsonPath.length &&
    left.jsonPath.every((segment, index) => segment === right.jsonPath[index])
  );
}

function cleanKey(value: string): string | undefined {
  const normalized = value.trim().slice(0, 180);
  if (normalized.length < 2) {
    return undefined;
  }
  return normalized;
}

function normalizeKey(value: string): string {
  return value.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function stableCandidateId(normalizedKey: string): string {
  let hash = 2166136261;
  for (let index = 0; index < normalizedKey.length; index += 1) {
    hash ^= normalizedKey.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `latent_${(hash >>> 0).toString(36)}`;
}

function strongerConfidence(
  left: LatentFeatureConfidence,
  right: LatentFeatureConfidence
): LatentFeatureConfidence {
  const rank: Record<LatentFeatureConfidence, number> = {
    high: 3,
    medium: 2,
    low: 1
  };
  return rank[right] > rank[left] ? right : left;
}

function mergeEvidence(
  left: LatentFeatureEvidence[],
  right: LatentFeatureEvidence[]
): LatentFeatureEvidence[] {
  const merged = new Map<string, LatentFeatureEvidence>();
  for (const evidence of [...left, ...right]) {
    const signature = `${evidence.sourceKind}:${evidence.label}:${evidence.detail}:${evidence.snippet ?? ''}`;
    merged.set(signature, evidence);
  }
  return [...merged.values()].slice(0, 8);
}

function compareCandidates(left: LatentFeatureCandidate, right: LatentFeatureCandidate): number {
  if (left.probeable !== right.probeable) {
    return left.probeable ? -1 : 1;
  }
  const rank: Record<LatentFeatureConfidence, number> = {
    high: 3,
    medium: 2,
    low: 1
  };
  const confidenceDelta = rank[right.confidence] - rank[left.confidence];
  if (confidenceDelta !== 0) {
    return confidenceDelta;
  }
  return right.evidence.length - left.evidence.length || left.key.localeCompare(right.key);
}

function unquote(value: string): string {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'")) ||
    (value.startsWith('`') && value.endsWith('`'))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

export function isHashLikeFeatureKey(value: string): boolean {
  return HASH_PATTERN.test(value);
}
