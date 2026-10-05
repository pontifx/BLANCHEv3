import type { JsonObject, JsonValue } from '../../../shared-schema/src';
import {
  SCRIPT_ANALYSIS_HARD_LIMITS,
  SCRIPT_PURPOSE_ANALYSIS_KIND,
  SCRIPT_PURPOSE_RUBRIC_VERSION,
  SCRIPT_PURPOSE_SCORE_MODEL,
  SCRIPT_PURPOSE_SCORE_THRESHOLDS,
  type ScriptBehaviorAxis,
  type ScriptCoverageGapCode,
  type ScriptEvidenceClass,
  type ScriptEvidenceDisposition,
  type ScriptIndicatorKind,
  type ScriptPurposeAnalysisResult,
  type ScriptPurposeCategory,
  type ScriptPurposeConfidence,
  type ScriptPurposeRole,
  type ScriptPurposeRubricVersion,
  type ScriptTestStageMode,
  type ScriptTestStageStatus,
  type ScriptTestTerminationReason
} from '../modules/latentFeatures/scriptPurposeRubric';

const MAX_SCRIPT_ASSESSMENTS = 64;
const MAX_SCRIPT_TRANSFORM_SIGNALS = 32;
const MAX_SCRIPT_COVERAGE_GAPS = 32;
const MAX_SCRIPT_PRIORITY_FACTORS = 64;
const MAX_SCRIPT_TEST_STAGES = 4;
const MAX_JAVASCRIPT_TEST_CELLS = 64;
const MAX_JAVASCRIPT_TEST_EVIDENCE = 200;
const MAX_JAVASCRIPT_TEST_GAPS = 100;
const MAX_JAVASCRIPT_TEST_ARTIFACTS = 64;
const MAX_ACTIVE_PROBE_ORIGINAL_VALUE_CHARACTERS = 65_536;
const MAX_ACTIVE_PROBE_JSON_PATH_SEGMENTS = 32;
const MAX_LATENT_CANDIDATES = 1_000;
const MAX_NEW_CANDIDATE_IDS = 200;
const MAX_LATENT_EVIDENCE_PER_CANDIDATE = 64;
const MAX_MUTATION_CODE_CHARACTERS = 2_000;
const MAX_MUTATION_DIFF_RECORDS = 100;
const MAX_MUTATION_HIGHLIGHTED_COUNT = 1_000;
const MAX_MUTATION_LIMITATIONS = 20;
const MAX_EVIDENCE_ATTRIBUTES_DEPTH = 4;
const MAX_EVIDENCE_ATTRIBUTES_NODES = 200;
const MAX_EVIDENCE_ATTRIBUTES_KEYS = 64;
const MAX_EVIDENCE_ATTRIBUTES_ARRAY = 64;
const MAX_IDENTIFIER_LENGTH = 256;
const MAX_LABEL_LENGTH = 500;
const MAX_DETAIL_LENGTH = 2_000;
const MAX_URL_LENGTH = 2_048;
const MAX_TIMESTAMP_LENGTH = 64;
const MAX_METADATA_STRING_LENGTH = 500;
const MAX_SAFE_PERSISTED_COUNT = 1_000_000_000_000;

export type LatentFeatureConfidence = 'high' | 'medium' | 'low';
export type LatentFeatureCandidateStatus = 'discovered' | 'active' | 'restored';
export type LatentFeatureStorageArea = 'localStorage' | 'sessionStorage';

export interface LatentFeatureEvidence {
  sourceKind:
    | 'bundle'
    | 'document'
    | 'inline-script'
    | 'runtime-response'
    | 'runtime-global'
    | 'localStorage'
    | 'sessionStorage'
    | 'dom';
  label: string;
  sourceUrl?: string;
  detail: string;
  snippet?: string;
}

export interface LatentFeatureStorageLocation {
  area: LatentFeatureStorageArea;
  storageKey: string;
  jsonPath: string[];
  format: 'direct' | 'json';
}

export interface LatentFeatureCandidate {
  id: string;
  key: string;
  normalizedKey: string;
  currentValue?: JsonValue;
  suggestedValue?: JsonValue;
  enabledValue?: JsonValue;
  disabledValue?: JsonValue;
  confidence: LatentFeatureConfidence;
  probeable: boolean;
  status: LatentFeatureCandidateStatus;
  controlSurface:
    | LatentFeatureStorageArea
    | 'bundle'
    | 'runtime-response'
    | 'runtime-global'
    | 'dom'
    | 'opaque-pair';
  storageLocation?: LatentFeatureStorageLocation;
  evidence: LatentFeatureEvidence[];
}

export interface LatentFeatureScanStats {
  pageSignalCount: number;
  inlineScriptCount: number;
  runtimeObservationCount: number;
  loadedLibraryCount: number;
  libraryReadCount: number;
  libraryFailureCount: number;
  libraryBytesRead: number;
  libraryThreadCount: number;
  libraryDelayMs: number;
}

export interface LatentFeatureScanRecord {
  scanId: string;
  scannedAt: string;
  tabId: number;
  pageUrl: string;
  origin: string;
  title?: string;
  candidates: LatentFeatureCandidate[];
  newCandidateIds: string[];
  scriptAssessments: ScriptPurposeAnalysisResult[];
  stats: LatentFeatureScanStats;
  warnings: string[];
}

export type JavascriptTestCellStatus =
  | 'passed'
  | 'static-only'
  | 'observed'
  | 'observed-unverified'
  | 'not-observed'
  | 'blocked'
  | 'manual-required'
  | 'failed';

export interface JavascriptTestCell {
  testId: string;
  stage: 'static' | 'instrumented' | 'active';
  title: string;
  status: JavascriptTestCellStatus;
  detail: string;
  evidenceRefs: string[];
  artifactIds: string[];
}

export interface JavascriptTestRuntimeStats {
  eventCount: number;
  lifecycleCount: number;
  trafficEntryCount: number;
  networkRequestCount: number;
  domMutationCount: number;
  storageWriteCount: number;
  routeChangeCount: number;
  workerCount: number;
  realtimeCount: number;
  runtimeErrorCount: number;
}

export type JavascriptTestEvidenceType =
  | 'blob-created'
  | 'blob-revoked'
  | 'script-added'
  | 'stylesheet-added'
  | 'image-added'
  | 'iframe-added'
  | 'worker-constructed'
  | 'shared-worker-constructed'
  | 'websocket-constructed'
  | 'eventsource-constructed'
  | 'network-request'
  | 'beacon-sent'
  | 'storage-write'
  | 'route-change'
  | 'runtime-error'
  | 'unhandled-rejection'
  | 'dom-mutation'
  | 'feature-candidates-observed'
  | 'lifecycle'
  | 'traffic-ledger-entry';

export interface JavascriptTestEvidenceRecord {
  evidenceId: string;
  type: JavascriptTestEvidenceType;
  observedAt: string;
  url?: string;
  attributes: JsonObject;
}

export interface JavascriptFullTestRun {
  testRunId: string;
  rubricVersion: ScriptPurposeRubricVersion;
  startedAt: string;
  completedAt: string;
  tabId: number;
  pageUrl: string;
  origin: string;
  scopeDisposition: 'in-scope' | 'out-of-scope' | 'review' | 'unknown';
  scopePolicyId?: string;
  scopePolicyVersion?: string;
  reloadTriggered: boolean;
  instrumentationAvailable: boolean;
  instrumentationIntegrity: 'extension-verified' | 'page-world-unverified' | 'none';
  overallStatus: 'complete' | 'partial' | 'failed';
  scanId: string;
  artifactIds: string[];
  artifactFingerprints: string[];
  cells: JavascriptTestCell[];
  evidence: JavascriptTestEvidenceRecord[];
  runtimeStats: JavascriptTestRuntimeStats;
  gaps: string[];
}

export interface LatentFeatureProbeChange {
  candidateId: string;
  key: string;
  area: LatentFeatureStorageArea;
  storageKey: string;
  jsonPath: string[];
  hadOriginalValue: boolean;
  originalValue?: string;
  originalCandidateValue?: JsonValue;
  appliedValue: JsonValue;
}

export interface LatentFeatureProbeRecord {
  probeId: string;
  createdAt: string;
  tabId: number;
  pageUrl: string;
  origin: string;
  changes: LatentFeatureProbeChange[];
  reloadTriggered: boolean;
}

export interface LatentFeatureMutationPageDiffEntry {
  selector: string;
  parentSelector?: string;
  tagName: string;
}

export interface LatentFeatureMutationRecord {
  mutationId: string;
  observedAt: string;
  tabId: number;
  pageUrl: string;
  origin: string;
  candidateId: string;
  key: string;
  requestedState: 'enabled' | 'disabled';
  previousValue: JsonValue;
  appliedValue: JsonValue;
  reloadTriggered: boolean;
  outcome: 'applied' | 'applied-with-warnings';
  codeDiff: {
    before: string;
    after: string;
  };
  pageDiff: {
    added: LatentFeatureMutationPageDiffEntry[];
    changed: LatentFeatureMutationPageDiffEntry[];
    removed: LatentFeatureMutationPageDiffEntry[];
    highlightedCount: number;
    truncated: boolean;
    limitations: string[];
  };
}

export interface LatentFeatureWorkbenchState {
  lastScan?: LatentFeatureScanRecord;
  activeProbe?: LatentFeatureProbeRecord;
  lastJavascriptTest?: JavascriptFullTestRun;
  lastMutation?: LatentFeatureMutationRecord;
}

export function createDefaultLatentFeatureWorkbenchState(): LatentFeatureWorkbenchState {
  return {};
}

export function normalizeLatentFeatureWorkbenchState(
  value: unknown
): LatentFeatureWorkbenchState {
  if (!isRecord(value)) {
    return createDefaultLatentFeatureWorkbenchState();
  }

  const lastScan = normalizeScan(value.lastScan);
  const lastJavascriptTest = normalizeJavascriptTest(value.lastJavascriptTest);
  return {
    lastScan,
    activeProbe: normalizeProbe(value.activeProbe),
    lastMutation: normalizeMutation(value.lastMutation),
    lastJavascriptTest:
      lastJavascriptTest &&
      (lastJavascriptTest.overallStatus === 'failed' ||
        javascriptTestMatchesScan(lastJavascriptTest, lastScan))
        ? lastJavascriptTest
        : undefined
  };
}

function normalizeScan(value: unknown): LatentFeatureScanRecord | undefined {
  if (
    !isRecord(value) ||
    typeof value.tabId !== 'number' ||
    !Number.isSafeInteger(value.tabId) ||
    value.tabId < 0
  ) {
    return undefined;
  }
  const scanId = boundedRequiredString(value.scanId, MAX_IDENTIFIER_LENGTH);
  const scannedAt = boundedRequiredString(value.scannedAt, MAX_TIMESTAMP_LENGTH);
  const pageUrl = normalizeSanitizedUrl(value.pageUrl);
  const origin = normalizeOrigin(value.origin);
  if (!scanId || !scannedAt || !pageUrl || !origin) return undefined;

  const candidates = Array.isArray(value.candidates)
    ? value.candidates
        .slice(0, MAX_LATENT_CANDIDATES)
        .map(normalizeCandidate)
        .filter(isDefined)
    : [];
  const candidateIds = new Set(candidates.map((candidate) => candidate.id));

  return {
    scanId,
    scannedAt,
    tabId: value.tabId,
    pageUrl,
    origin,
    title: boundedOptionalString(
      sanitizePersistedText(value.title, MAX_LABEL_LENGTH),
      MAX_LABEL_LENGTH
    ),
    candidates,
    newCandidateIds: uniqueBoundedStrings(
      value.newCandidateIds,
      MAX_NEW_CANDIDATE_IDS,
      MAX_IDENTIFIER_LENGTH
    ).filter((candidateId) => candidateIds.has(candidateId)),
    scriptAssessments: Array.isArray(value.scriptAssessments)
      ? value.scriptAssessments
          .slice(0, MAX_SCRIPT_ASSESSMENTS)
          .map(normalizeScriptAssessment)
          .filter(isDefined)
      : [],
    stats: normalizeStats(value.stats),
    warnings: uniqueBoundedStrings(value.warnings, 50, MAX_DETAIL_LENGTH).map((warning) =>
      sanitizePersistedText(warning, MAX_DETAIL_LENGTH)
    )
  };
}

function normalizeScriptAssessment(value: unknown): ScriptPurposeAnalysisResult | undefined {
  if (
    !isRecord(value) ||
    value.kind !== SCRIPT_PURPOSE_ANALYSIS_KIND ||
    value.rubricVersion !== SCRIPT_PURPOSE_RUBRIC_VERSION
  ) {
    return undefined;
  }

  const artifact = normalizeScriptArtifact(value.artifact);
  if (!artifact) return undefined;
  const evidence = normalizeScriptEvidence(value.evidence);
  const evidenceIds = new Set(evidence.map((entry) => entry.evidenceId));

  return {
    kind: SCRIPT_PURPOSE_ANALYSIS_KIND,
    rubricVersion: SCRIPT_PURPOSE_RUBRIC_VERSION,
    artifact,
    transform: normalizeTransformAssessment(value.transform, evidenceIds),
    coverage: normalizeScriptCoverage(value.coverage),
    purposeClaims: normalizePurposeClaims(value.purposeClaims, evidenceIds),
    behaviorClaims: normalizeBehaviorClaims(value.behaviorClaims, evidenceIds),
    indicators: normalizeScriptIndicators(value.indicators, evidenceIds),
    evidence,
    reviewPriority: normalizeReviewPriority(value.reviewPriority, evidenceIds),
    testPlan: normalizeScriptTestPlan(value.testPlan)
  };
}

function normalizeJavascriptTest(value: unknown): JavascriptFullTestRun | undefined {
  if (
    !isRecord(value) ||
    value.rubricVersion !== SCRIPT_PURPOSE_RUBRIC_VERSION ||
    !boundedRequiredString(value.testRunId, MAX_IDENTIFIER_LENGTH) ||
    !boundedRequiredString(value.scanId, MAX_IDENTIFIER_LENGTH) ||
    !boundedRequiredString(value.startedAt, MAX_TIMESTAMP_LENGTH) ||
    !boundedRequiredString(value.completedAt, MAX_TIMESTAMP_LENGTH) ||
    typeof value.tabId !== 'number' ||
    !Number.isSafeInteger(value.tabId) ||
    value.tabId < 0 ||
    !Array.isArray(value.artifactFingerprints)
  ) {
    // Pre-binding records cannot be safely paired to a scan and are intentionally discarded.
    return undefined;
  }

  const artifactFingerprints = canonicalArtifactFingerprints(
    uniqueBoundedStrings(
      value.artifactFingerprints,
      MAX_JAVASCRIPT_TEST_ARTIFACTS,
      MAX_IDENTIFIER_LENGTH + 65
    )
      .map(normalizeArtifactFingerprint)
      .filter(isDefined)
  );
  const artifactIds = artifactFingerprints.map(artifactIdFromFingerprint);
  const artifactIdSet = new Set(artifactIds);
  const evidence = normalizeJavascriptTestEvidence(value.evidence);
  const evidenceIds = new Set(evidence.map((entry) => entry.evidenceId));
  const instrumentationIntegrity = oneOf(
    value.instrumentationIntegrity,
    JAVASCRIPT_INSTRUMENTATION_INTEGRITIES,
    'none'
  );
  const normalizedOverallStatus = oneOf(
    value.overallStatus,
    JAVASCRIPT_TEST_OVERALL_STATUSES,
    'failed'
  );
  const cells = enforceJavascriptTestIntegrity(
    normalizeJavascriptTestCells(value.cells, artifactIdSet, evidenceIds),
    evidence,
    instrumentationIntegrity
  );

  return {
    testRunId: boundedRequiredString(value.testRunId, MAX_IDENTIFIER_LENGTH)!,
    rubricVersion: SCRIPT_PURPOSE_RUBRIC_VERSION,
    startedAt: boundedRequiredString(value.startedAt, MAX_TIMESTAMP_LENGTH)!,
    completedAt: boundedRequiredString(value.completedAt, MAX_TIMESTAMP_LENGTH)!,
    tabId: value.tabId,
    pageUrl: normalizeSanitizedUrl(value.pageUrl) ?? '',
    origin: normalizeOrigin(value.origin) ?? '',
    scopeDisposition: oneOf(value.scopeDisposition, SCRIPT_SCOPE_DISPOSITIONS, 'unknown'),
    scopePolicyId: boundedOptionalString(value.scopePolicyId, MAX_IDENTIFIER_LENGTH),
    scopePolicyVersion: boundedOptionalString(value.scopePolicyVersion, MAX_IDENTIFIER_LENGTH),
    reloadTriggered: value.reloadTriggered === true,
    instrumentationAvailable: value.instrumentationAvailable === true,
    instrumentationIntegrity,
    overallStatus:
      instrumentationIntegrity === 'page-world-unverified' && normalizedOverallStatus === 'complete'
        ? 'partial'
        : normalizedOverallStatus,
    scanId: boundedRequiredString(value.scanId, MAX_IDENTIFIER_LENGTH)!,
    artifactIds,
    artifactFingerprints,
    cells,
    evidence,
    runtimeStats: normalizeJavascriptRuntimeStats(value.runtimeStats),
    gaps: uniqueBoundedStrings(value.gaps, MAX_JAVASCRIPT_TEST_GAPS, MAX_DETAIL_LENGTH)
  };
}

export function createScriptArtifactFingerprint(
  assessment: ScriptPurposeAnalysisResult
): string | undefined {
  const artifactId = boundedRequiredString(
    assessment.artifact.artifactId,
    MAX_IDENTIFIER_LENGTH
  );
  const sha256 = normalizeSha256(assessment.artifact.sha256);
  return artifactId && sha256 ? `${artifactId}:${sha256}` : undefined;
}

export function javascriptTestMatchesScan(
  test: JavascriptFullTestRun | undefined,
  scan: LatentFeatureScanRecord | undefined
): boolean {
  if (!test || !scan || test.scanId !== scan.scanId) return false;
  const rawScanFingerprints = scan.scriptAssessments.map(createScriptArtifactFingerprint);
  if (rawScanFingerprints.some((fingerprint) => fingerprint === undefined)) return false;
  const scanFingerprints = canonicalArtifactFingerprints(rawScanFingerprints.filter(isDefined));
  const testFingerprints = canonicalArtifactFingerprints(test.artifactFingerprints);
  return (
    scanFingerprints.length === testFingerprints.length &&
    scanFingerprints.every((fingerprint, index) => fingerprint === testFingerprints[index])
  );
}

function canonicalArtifactFingerprints(values: string[]): string[] {
  return [...new Set(values)].sort();
}

const SCRIPT_CONFIDENCES = ['high', 'medium', 'low'] as const;
const SCRIPT_TRANSFORMS = [
  'readable',
  'minified',
  'bundled',
  'packed',
  'obfuscated',
  'unknown'
] as const;
const SCRIPT_PURPOSE_CATEGORIES = [
  'loader-runtime',
  'app-shell-ui',
  'api-data',
  'identity-access',
  'feature-configuration',
  'telemetry-analytics',
  'storage-offline',
  'realtime-messaging',
  'file-media-crypto-payment',
  'developer-debug-admin',
  'third-party-integration',
  'unknown'
] as const;
const SCRIPT_PURPOSE_ROLES = ['primary', 'secondary', 'candidate'] as const;
const SCRIPT_BEHAVIOR_AXES = [
  'network',
  'dom-ui',
  'data-handling',
  'identity-session-authorization',
  'server-state-change',
  'client-storage',
  'dynamic-code-loading',
  'persistence-background-realtime',
  'cross-origin-transfer',
  'latent-debug-admin'
] as const;
const SCRIPT_EVIDENCE_CLASSES = [
  'content-metric',
  'literal',
  'structural-pattern',
  'component-signature',
  'source-map',
  'runtime'
] as const;
const SCRIPT_EVIDENCE_DISPOSITIONS = ['observed', 'inferred'] as const;
const SCRIPT_INDICATOR_KINDS = [
  'endpoint',
  'host',
  'storage-key',
  'feature-key',
  'event-name',
  'source-map'
] as const;
const SCRIPT_COVERAGE_STATUSES = ['complete', 'partial', 'limited'] as const;
const SCRIPT_COVERAGE_GAP_CODES = [
  'EMPTY_SOURCE',
  'TRUNCATED_SOURCE',
  'MISSING_CONTENT_HASH',
  'HEURISTIC_STATIC_ANALYSIS',
  'SOURCE_MAP_UNAVAILABLE',
  'SOURCE_MAP_MISMATCH',
  'UNRESOLVED_DYNAMIC_IMPORT',
  'UNRESOLVED_PACKED_PAYLOAD',
  'UNRESOLVED_WASM',
  'RUNTIME_NOT_OBSERVED'
] as const;
const SCRIPT_SCOPE_DISPOSITIONS = ['in-scope', 'out-of-scope', 'review', 'unknown'] as const;
const SCRIPT_OWNERSHIPS = [
  'target',
  'same-organization',
  'delegated',
  'third-party',
  'shared',
  'unknown'
] as const;
const SCRIPT_TEST_STAGE_MODES = [
  'offline-static',
  'isolated-sandbox',
  'passive-observation',
  'authorized-active'
] as const;
const SCRIPT_TEST_STAGE_STATUSES = ['ready', 'conditional', 'blocked', 'complete'] as const;
const SCRIPT_TEST_TERMINATION_REASONS = [
  'NONE',
  'NO_SOURCE',
  'STATIC_COVERAGE_GAP',
  'ISOLATION_REQUIRED',
  'RUNTIME_EVIDENCE_REQUIRED',
  'EXPLICIT_SCOPE_REQUIRED',
  'THIRD_PARTY_ACTIVE_TEST_BLOCKED',
  'STATE_CHANGE_REVIEW_REQUIRED'
] as const;
const JAVASCRIPT_TEST_CELL_STATUSES = [
  'passed',
  'static-only',
  'observed',
  'observed-unverified',
  'not-observed',
  'blocked',
  'manual-required',
  'failed'
] as const;
const JAVASCRIPT_TEST_CELL_STAGES = ['static', 'instrumented', 'active'] as const;
const JAVASCRIPT_TEST_OVERALL_STATUSES = ['complete', 'partial', 'failed'] as const;
const JAVASCRIPT_TEST_EVIDENCE_TYPES = [
  'blob-created',
  'blob-revoked',
  'script-added',
  'stylesheet-added',
  'image-added',
  'iframe-added',
  'worker-constructed',
  'shared-worker-constructed',
  'websocket-constructed',
  'eventsource-constructed',
  'network-request',
  'beacon-sent',
  'storage-write',
  'route-change',
  'runtime-error',
  'unhandled-rejection',
  'dom-mutation',
  'feature-candidates-observed',
  'lifecycle',
  'traffic-ledger-entry'
] as const;
const JAVASCRIPT_INSTRUMENTATION_INTEGRITIES = [
  'extension-verified',
  'page-world-unverified',
  'none'
] as const;

function normalizeScriptArtifact(
  value: unknown
): ScriptPurposeAnalysisResult['artifact'] | undefined {
  if (!isRecord(value)) return undefined;
  const artifactId = boundedRequiredString(value.artifactId, MAX_IDENTIFIER_LENGTH);
  if (!artifactId) return undefined;
  const scope = isRecord(value.scope) ? value.scope : {};
  return {
    artifactId,
    sourceKind: oneOf(value.sourceKind, ['external', 'inline', 'document'] as const, 'external'),
    label:
      sanitizePersistedText(
        boundedRequiredString(value.label, MAX_LABEL_LENGTH) ?? artifactId,
        MAX_LABEL_LENGTH
      ) || artifactId,
    sourceUrl: normalizeSanitizedUrl(value.sourceUrl),
    finalUrl: normalizeSanitizedUrl(value.finalUrl),
    contentType: boundedOptionalString(value.contentType, MAX_LABEL_LENGTH),
    sha256: normalizeSha256(value.sha256),
    acquiredAt: boundedOptionalString(value.acquiredAt, MAX_TIMESTAMP_LENGTH),
    scope: {
      disposition: oneOf(scope.disposition, SCRIPT_SCOPE_DISPOSITIONS, 'unknown'),
      ownership: oneOf(scope.ownership, SCRIPT_OWNERSHIPS, 'unknown'),
      policyId: boundedOptionalString(scope.policyId, MAX_IDENTIFIER_LENGTH),
      policyVersion: boundedOptionalString(scope.policyVersion, MAX_IDENTIFIER_LENGTH),
      matchedRuleIds: uniqueBoundedStrings(
        scope.matchedRuleIds,
        64,
        MAX_IDENTIFIER_LENGTH
      )
    }
  };
}

function normalizeTransformAssessment(
  value: unknown,
  evidenceIds: Set<string>
): ScriptPurposeAnalysisResult['transform'] {
  const source = isRecord(value) ? value : {};
  const primary = oneOf(source.primary, SCRIPT_TRANSFORMS, 'unknown');
  const detected = uniqueEnumValues(source.detected, SCRIPT_TRANSFORMS, 6);
  if (!detected.includes(primary)) detected.unshift(primary);
  const metrics = isRecord(source.metrics) ? source.metrics : {};
  return {
    primary,
    detected,
    complexityScore: boundedNumber(source.complexityScore, 0, 100, 0),
    confidence: oneOf(source.confidence, SCRIPT_CONFIDENCES, 'low'),
    metrics: {
      characterCount: boundedCount(metrics.characterCount),
      byteLength: boundedCount(metrics.byteLength),
      lineCount: boundedCount(metrics.lineCount),
      nonEmptyLineCount: boundedCount(metrics.nonEmptyLineCount),
      longestLineLength: boundedCount(metrics.longestLineLength),
      meanNonEmptyLineLength: boundedCount(metrics.meanNonEmptyLineLength),
      whitespaceRatio: boundedNumber(metrics.whitespaceRatio, 0, 1, 0)
    },
    signals: Array.isArray(source.signals)
      ? source.signals
          .slice(0, MAX_SCRIPT_TRANSFORM_SIGNALS)
          .map((entry) => normalizeTransformSignal(entry, evidenceIds))
          .filter(isDefined)
      : []
  };
}

function normalizeTransformSignal(
  value: unknown,
  evidenceIds: Set<string>
): ScriptPurposeAnalysisResult['transform']['signals'][number] | undefined {
  if (!isRecord(value)) return undefined;
  const code = boundedRequiredString(value.code, MAX_IDENTIFIER_LENGTH);
  const detail = boundedRequiredString(value.detail, MAX_DETAIL_LENGTH);
  if (!code || !detail) return undefined;
  return {
    code,
    kind: oneOf(value.kind, SCRIPT_TRANSFORMS, 'unknown'),
    weight: boundedNumber(value.weight, -100, 100, 0),
    detail: sanitizePersistedText(detail, MAX_DETAIL_LENGTH),
    evidenceRefs: normalizeEvidenceRefs(value.evidenceRefs, evidenceIds)
  };
}

function normalizeScriptCoverage(value: unknown): ScriptPurposeAnalysisResult['coverage'] {
  const source = isRecord(value) ? value : {};
  return {
    status: oneOf(source.status, SCRIPT_COVERAGE_STATUSES, 'limited'),
    analyzedBytes: boundedCount(source.analyzedBytes),
    declaredBytes: boundedCount(source.declaredBytes),
    byteCoverageRatio: boundedNumber(source.byteCoverageRatio, 0, 1, 0),
    runtimeObservationCount: boundedCount(source.runtimeObservationCount),
    gaps: Array.isArray(source.gaps)
      ? source.gaps
          .slice(0, MAX_SCRIPT_COVERAGE_GAPS)
          .map(normalizeCoverageGap)
          .filter(isDefined)
      : []
  };
}

function normalizeCoverageGap(
  value: unknown
): ScriptPurposeAnalysisResult['coverage']['gaps'][number] | undefined {
  if (!isRecord(value) || !isOneOf(value.code, SCRIPT_COVERAGE_GAP_CODES)) return undefined;
  const detail = boundedRequiredString(value.detail, MAX_DETAIL_LENGTH);
  if (!detail) return undefined;
  return {
    code: value.code as ScriptCoverageGapCode,
    material: value.material === true,
    detail: sanitizePersistedText(detail, MAX_DETAIL_LENGTH)
  };
}

function normalizePurposeClaims(
  value: unknown,
  evidenceIds: Set<string>
): ScriptPurposeAnalysisResult['purposeClaims'] {
  if (!Array.isArray(value)) return [];
  const output: ScriptPurposeAnalysisResult['purposeClaims'] = [];
  const seen = new Set<ScriptPurposeCategory>();
  for (const entry of value.slice(0, SCRIPT_ANALYSIS_HARD_LIMITS.maxClaims)) {
    if (!isRecord(entry) || !isOneOf(entry.category, SCRIPT_PURPOSE_CATEGORIES)) continue;
    const category = entry.category as ScriptPurposeCategory;
    if (seen.has(category)) continue;
    const reason = boundedRequiredString(entry.reason, MAX_DETAIL_LENGTH);
    if (!reason) continue;
    seen.add(category);
    output.push({
      category,
      role: oneOf(entry.role, SCRIPT_PURPOSE_ROLES, 'candidate') as ScriptPurposeRole,
      score: boundedNumber(entry.score, 0, 1_000, 0),
      confidence: oneOf(entry.confidence, SCRIPT_CONFIDENCES, 'low') as ScriptPurposeConfidence,
      reason: sanitizePersistedText(reason, MAX_DETAIL_LENGTH),
      evidenceRefs: normalizeEvidenceRefs(entry.evidenceRefs, evidenceIds)
    });
  }
  return output;
}

function normalizeBehaviorClaims(
  value: unknown,
  evidenceIds: Set<string>
): ScriptPurposeAnalysisResult['behaviorClaims'] {
  if (!Array.isArray(value)) return [];
  const output: ScriptPurposeAnalysisResult['behaviorClaims'] = [];
  const seen = new Set<ScriptBehaviorAxis>();
  for (const entry of value.slice(0, SCRIPT_BEHAVIOR_AXES.length * 2)) {
    if (!isRecord(entry) || !isOneOf(entry.axis, SCRIPT_BEHAVIOR_AXES)) continue;
    const axis = entry.axis as ScriptBehaviorAxis;
    if (seen.has(axis)) continue;
    const summary = boundedRequiredString(entry.summary, MAX_DETAIL_LENGTH);
    if (!summary) continue;
    seen.add(axis);
    output.push({
      axis,
      maturity: boundedInteger(entry.maturity, 0, 3, 0) as 0 | 1 | 2 | 3,
      confidence: oneOf(entry.confidence, SCRIPT_CONFIDENCES, 'low'),
      summary: sanitizePersistedText(summary, MAX_DETAIL_LENGTH),
      evidenceRefs: normalizeEvidenceRefs(entry.evidenceRefs, evidenceIds)
    });
  }
  return output;
}

function normalizeScriptIndicators(
  value: unknown,
  evidenceIds: Set<string>
): ScriptPurposeAnalysisResult['indicators'] {
  if (!Array.isArray(value)) return [];
  const output: ScriptPurposeAnalysisResult['indicators'] = [];
  const seen = new Set<string>();
  for (const entry of value.slice(0, SCRIPT_ANALYSIS_HARD_LIMITS.maxIndicators)) {
    if (!isRecord(entry) || !isOneOf(entry.kind, SCRIPT_INDICATOR_KINDS)) continue;
    const indicatorId = boundedRequiredString(entry.indicatorId, MAX_IDENTIFIER_LENGTH);
    const rawValue = boundedRequiredString(entry.value, MAX_URL_LENGTH);
    if (!indicatorId || !rawValue) continue;
    const kind = entry.kind as ScriptIndicatorKind;
    const normalizedValue = kind === 'endpoint' || kind === 'source-map'
      ? normalizeSanitizedUrl(rawValue) ?? sanitizePersistedText(rawValue, MAX_URL_LENGTH)
      : sanitizePersistedText(rawValue, MAX_LABEL_LENGTH);
    const signature = `${kind}:${normalizedValue}`;
    if (seen.has(signature)) continue;
    seen.add(signature);
    output.push({
      indicatorId,
      kind,
      value: normalizedValue,
      confidence: oneOf(entry.confidence, SCRIPT_CONFIDENCES, 'low'),
      evidenceRefs: normalizeEvidenceRefs(entry.evidenceRefs, evidenceIds)
    });
  }
  return output;
}

function normalizeScriptEvidence(value: unknown): ScriptPurposeAnalysisResult['evidence'] {
  if (!Array.isArray(value)) return [];
  const output: ScriptPurposeAnalysisResult['evidence'] = [];
  const seen = new Set<string>();
  for (const entry of value.slice(0, SCRIPT_ANALYSIS_HARD_LIMITS.maxEvidence)) {
    if (
      !isRecord(entry) ||
      !isOneOf(entry.evidenceClass, SCRIPT_EVIDENCE_CLASSES) ||
      !isOneOf(entry.disposition, SCRIPT_EVIDENCE_DISPOSITIONS)
    ) continue;
    const evidenceId = boundedRequiredString(entry.evidenceId, MAX_IDENTIFIER_LENGTH);
    const label = boundedRequiredString(entry.label, MAX_LABEL_LENGTH);
    const detail = boundedRequiredString(entry.detail, MAX_DETAIL_LENGTH);
    if (!evidenceId || !label || !detail || seen.has(evidenceId)) continue;
    seen.add(evidenceId);
    const startOffset = boundedOptionalInteger(entry.startOffset, 0, MAX_SAFE_PERSISTED_COUNT);
    const endOffset = boundedOptionalInteger(entry.endOffset, 0, MAX_SAFE_PERSISTED_COUNT);
    output.push({
      evidenceId,
      evidenceClass: entry.evidenceClass as ScriptEvidenceClass,
      disposition: entry.disposition as ScriptEvidenceDisposition,
      label: sanitizePersistedText(label, MAX_LABEL_LENGTH),
      detail: sanitizePersistedText(detail, MAX_DETAIL_LENGTH),
      sourceUrl: normalizeSanitizedUrl(entry.sourceUrl),
      startOffset,
      endOffset:
        endOffset !== undefined && startOffset !== undefined && endOffset < startOffset
          ? startOffset
          : endOffset,
      snippet: boundedOptionalString(
        sanitizePersistedText(entry.snippet, SCRIPT_ANALYSIS_HARD_LIMITS.maxSnippetCharacters),
        SCRIPT_ANALYSIS_HARD_LIMITS.maxSnippetCharacters
      )
    });
  }
  return output;
}

function normalizeReviewPriority(
  value: unknown,
  evidenceIds: Set<string>
): ScriptPurposeAnalysisResult['reviewPriority'] {
  const source = isRecord(value) ? value : {};
  const score = boundedNumber(source.score, 0, 100, 0);
  return {
    scoreModel: SCRIPT_PURPOSE_SCORE_MODEL,
    score,
    band:
      score >= SCRIPT_PURPOSE_SCORE_THRESHOLDS.urgent ? 'urgent' :
      score >= SCRIPT_PURPOSE_SCORE_THRESHOLDS.high ? 'high' :
      score >= SCRIPT_PURPOSE_SCORE_THRESHOLDS.medium ? 'medium' : 'low',
    isVulnerabilitySeverity: false,
    factors: Array.isArray(source.factors)
      ? source.factors
          .slice(0, MAX_SCRIPT_PRIORITY_FACTORS)
          .map((entry) => normalizePriorityFactor(entry, evidenceIds))
          .filter(isDefined)
      : []
  };
}

function normalizePriorityFactor(
  value: unknown,
  evidenceIds: Set<string>
): ScriptPurposeAnalysisResult['reviewPriority']['factors'][number] | undefined {
  if (!isRecord(value)) return undefined;
  const code = boundedRequiredString(value.code, MAX_IDENTIFIER_LENGTH);
  const reason = boundedRequiredString(value.reason, MAX_DETAIL_LENGTH);
  if (!code || !reason) return undefined;
  return {
    code,
    baseWeight: boundedNumber(value.baseWeight, -100, 100, 0),
    appliedWeight: boundedNumber(value.appliedWeight, -100, 100, 0),
    reason: sanitizePersistedText(reason, MAX_DETAIL_LENGTH),
    evidenceRefs: normalizeEvidenceRefs(value.evidenceRefs, evidenceIds)
  };
}

function normalizeScriptTestPlan(value: unknown): ScriptPurposeAnalysisResult['testPlan'] {
  const source = isRecord(value) ? value : {};
  return {
    generatedFromRubric: SCRIPT_PURPOSE_RUBRIC_VERSION,
    stages: Array.isArray(source.stages)
      ? source.stages
          .slice(0, MAX_SCRIPT_TEST_STAGES)
          .map(normalizeScriptTestStage)
          .filter(isDefined)
      : []
  };
}

function normalizeScriptTestStage(
  value: unknown
): ScriptPurposeAnalysisResult['testPlan']['stages'][number] | undefined {
  if (!isRecord(value)) return undefined;
  const stage = boundedOptionalInteger(value.stage, 0, 3);
  const objective = boundedRequiredString(value.objective, MAX_DETAIL_LENGTH);
  if (stage === undefined || !objective) return undefined;
  return {
    stage: stage as 0 | 1 | 2 | 3,
    mode: oneOf(value.mode, SCRIPT_TEST_STAGE_MODES, 'offline-static') as ScriptTestStageMode,
    status: oneOf(value.status, SCRIPT_TEST_STAGE_STATUSES, 'blocked') as ScriptTestStageStatus,
    objective: sanitizePersistedText(objective, MAX_DETAIL_LENGTH),
    actions: uniqueBoundedStrings(value.actions, 20, MAX_DETAIL_LENGTH),
    successCriteria: uniqueBoundedStrings(value.successCriteria, 20, MAX_DETAIL_LENGTH),
    stopConditions: uniqueBoundedStrings(value.stopConditions, 20, MAX_DETAIL_LENGTH),
    terminationReason: oneOf(
      value.terminationReason,
      SCRIPT_TEST_TERMINATION_REASONS,
      'STATIC_COVERAGE_GAP'
    ) as ScriptTestTerminationReason
  };
}

function normalizeJavascriptTestCells(
  value: unknown,
  artifactIds: Set<string>,
  evidenceIds: Set<string>
): JavascriptTestCell[] {
  if (!Array.isArray(value)) return [];
  const output: JavascriptTestCell[] = [];
  const seen = new Set<string>();
  for (const entry of value.slice(0, MAX_JAVASCRIPT_TEST_CELLS)) {
    if (!isRecord(entry)) continue;
    const testId = boundedRequiredString(entry.testId, MAX_IDENTIFIER_LENGTH);
    const title = boundedRequiredString(entry.title, MAX_LABEL_LENGTH);
    const detail = boundedRequiredString(entry.detail, MAX_DETAIL_LENGTH);
    if (!testId || !title || !detail || seen.has(testId)) continue;
    seen.add(testId);
    output.push({
      testId,
      stage: oneOf(entry.stage, JAVASCRIPT_TEST_CELL_STAGES, 'static'),
      title: sanitizePersistedText(title, MAX_LABEL_LENGTH),
      status: oneOf(entry.status, JAVASCRIPT_TEST_CELL_STATUSES, 'failed'),
      detail: sanitizePersistedText(detail, MAX_DETAIL_LENGTH),
      evidenceRefs: normalizeEvidenceRefs(entry.evidenceRefs, evidenceIds),
      artifactIds: uniqueBoundedStrings(
        entry.artifactIds,
        MAX_JAVASCRIPT_TEST_ARTIFACTS,
        MAX_IDENTIFIER_LENGTH
      ).filter((artifactId) => artifactIds.has(artifactId))
    });
  }
  return output;
}

function enforceJavascriptTestIntegrity(
  cells: JavascriptTestCell[],
  evidence: JavascriptTestEvidenceRecord[],
  integrity: JavascriptFullTestRun['instrumentationIntegrity']
): JavascriptTestCell[] {
  if (integrity === 'extension-verified') return cells;
  const evidenceById = new Map(evidence.map((entry) => [entry.evidenceId, entry]));
  return cells.map((cell) => {
    if (cell.status !== 'observed') return cell;
    const referencedEvidence = cell.evidenceRefs
      .map((evidenceId) => evidenceById.get(evidenceId))
      .filter(isDefined);
    if (referencedEvidence.some((entry) => entry.type === 'traffic-ledger-entry')) {
      return cell;
    }
    return {
      ...cell,
      status:
        integrity === 'page-world-unverified' && referencedEvidence.length > 0
          ? 'observed-unverified'
          : 'not-observed'
    };
  });
}

function normalizeJavascriptTestEvidence(value: unknown): JavascriptTestEvidenceRecord[] {
  if (!Array.isArray(value)) return [];
  const output: JavascriptTestEvidenceRecord[] = [];
  const seen = new Set<string>();
  for (const entry of value.slice(0, MAX_JAVASCRIPT_TEST_EVIDENCE)) {
    if (!isRecord(entry) || !isOneOf(entry.type, JAVASCRIPT_TEST_EVIDENCE_TYPES)) continue;
    const evidenceId = boundedRequiredString(entry.evidenceId, MAX_IDENTIFIER_LENGTH);
    const observedAt = boundedRequiredString(entry.observedAt, MAX_TIMESTAMP_LENGTH);
    if (!evidenceId || !observedAt || seen.has(evidenceId)) continue;
    seen.add(evidenceId);
    output.push({
      evidenceId,
      type: entry.type as JavascriptTestEvidenceType,
      observedAt,
      url: normalizeSanitizedUrl(entry.url),
      attributes: normalizeEvidenceAttributes(entry.attributes)
    });
  }
  return output;
}

function normalizeJavascriptRuntimeStats(value: unknown): JavascriptTestRuntimeStats {
  const source = isRecord(value) ? value : {};
  return {
    eventCount: boundedCount(source.eventCount),
    lifecycleCount: boundedCount(source.lifecycleCount),
    trafficEntryCount: boundedCount(source.trafficEntryCount),
    networkRequestCount: boundedCount(source.networkRequestCount),
    domMutationCount: boundedCount(source.domMutationCount),
    storageWriteCount: boundedCount(source.storageWriteCount),
    routeChangeCount: boundedCount(source.routeChangeCount),
    workerCount: boundedCount(source.workerCount),
    realtimeCount: boundedCount(source.realtimeCount),
    runtimeErrorCount: boundedCount(source.runtimeErrorCount)
  };
}

function normalizeEvidenceAttributes(value: unknown): JsonObject {
  if (!isRecord(value)) return {};
  const budget = { remaining: MAX_EVIDENCE_ATTRIBUTES_NODES };
  const normalized = normalizeEvidenceMetadata(value, 0, budget);
  return isRecord(normalized) ? normalized as JsonObject : {};
}

function normalizeEvidenceMetadata(
  value: unknown,
  depth: number,
  budget: { remaining: number },
  keyHint = ''
): JsonValue | undefined {
  if (budget.remaining <= 0 || depth > MAX_EVIDENCE_ATTRIBUTES_DEPTH) return undefined;
  budget.remaining -= 1;
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined;
  if (typeof value === 'string') {
    if (isSensitiveMetadataKey(keyHint)) return '[redacted]';
    if (isUrlMetadataKey(keyHint)) {
      return normalizeSanitizedUrl(value) ?? sanitizePersistedText(value, MAX_METADATA_STRING_LENGTH);
    }
    return sanitizePersistedText(value, MAX_METADATA_STRING_LENGTH);
  }
  if (Array.isArray(value)) {
    return value
      .slice(0, MAX_EVIDENCE_ATTRIBUTES_ARRAY)
      .map((entry) => normalizeEvidenceMetadata(entry, depth + 1, budget, keyHint))
      .filter((entry): entry is JsonValue => entry !== undefined);
  }
  if (!isRecord(value)) return undefined;
  const output: JsonObject = {};
  for (const [rawKey, entry] of Object.entries(value).slice(0, MAX_EVIDENCE_ATTRIBUTES_KEYS)) {
    const key = boundedRequiredString(rawKey, 100);
    if (!key || key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    const normalized = normalizeEvidenceMetadata(entry, depth + 1, budget, key);
    if (normalized !== undefined) output[key] = normalized;
    if (budget.remaining <= 0) break;
  }
  return output;
}

function normalizeCandidate(value: unknown): LatentFeatureCandidate | undefined {
  if (!isRecord(value)) return undefined;
  const id = boundedRequiredString(value.id, MAX_IDENTIFIER_LENGTH);
  const key = boundedRequiredString(value.key, MAX_LABEL_LENGTH);
  const normalizedKey = boundedRequiredString(value.normalizedKey, MAX_LABEL_LENGTH);
  if (!id || !key || !normalizedKey) return undefined;

  const confidence: LatentFeatureConfidence =
    value.confidence === 'high' || value.confidence === 'medium' ? value.confidence : 'low';
  const status: LatentFeatureCandidateStatus =
    value.status === 'active' || value.status === 'restored' ? value.status : 'discovered';
  const controlSurface = normalizeControlSurface(value.controlSurface);
  const currentValue = normalizeJsonValue(value.currentValue);
  const suggestedValue = normalizeJsonValue(value.suggestedValue);
  const normalizedEnabledValue = normalizeJsonValue(value.enabledValue);
  const normalizedDisabledValue = normalizeJsonValue(value.disabledValue);
  const legacyTogglePair = deriveBooleanLikeTogglePair(currentValue, suggestedValue);
  const enabledValue =
    classifyBooleanLikeValue(normalizedEnabledValue) === 'enabled'
      ? normalizedEnabledValue
      : legacyTogglePair?.enabledValue;
  const disabledValue =
    classifyBooleanLikeValue(normalizedDisabledValue) === 'disabled'
      ? normalizedDisabledValue
      : legacyTogglePair?.disabledValue;
  const normalizedStorageLocation = normalizeStorageLocation(value.storageLocation);
  const storageLocation =
    normalizedStorageLocation &&
    !isSensitiveFeatureControlKey(key) &&
    !isSensitiveFeatureControlKey(normalizedStorageLocation.storageKey) &&
    !normalizedStorageLocation.jsonPath.some(isSensitiveFeatureControlKey)
      ? normalizedStorageLocation
      : undefined;
  const reversibleStorageCandidate =
    storageLocation !== undefined &&
    classifyBooleanLikeValue(enabledValue) === 'enabled' &&
    classifyBooleanLikeValue(disabledValue) === 'disabled';

  return {
    id,
    key: sanitizePersistedText(key, MAX_LABEL_LENGTH),
    normalizedKey: sanitizePersistedText(normalizedKey, MAX_LABEL_LENGTH),
    currentValue,
    suggestedValue,
    enabledValue,
    disabledValue,
    confidence,
    probeable: reversibleStorageCandidate,
    status,
    controlSurface,
    storageLocation,
    evidence: Array.isArray(value.evidence)
      ? value.evidence
          .slice(0, MAX_LATENT_EVIDENCE_PER_CANDIDATE)
          .map(normalizeEvidence)
          .filter(isDefined)
      : []
  };
}

function deriveBooleanLikeTogglePair(
  currentValue: JsonValue | undefined,
  suggestedValue: JsonValue | undefined
): { enabledValue: JsonValue; disabledValue: JsonValue } | undefined {
  const currentState = classifyBooleanLikeValue(currentValue);
  const suggestedState = classifyBooleanLikeValue(suggestedValue);
  if (!currentState || !suggestedState || currentState === suggestedState) return undefined;
  return currentState === 'enabled'
    ? { enabledValue: currentValue!, disabledValue: suggestedValue! }
    : { enabledValue: suggestedValue!, disabledValue: currentValue! };
}

function classifyBooleanLikeValue(value: JsonValue | undefined): 'enabled' | 'disabled' | undefined {
  if (value === true || value === 1) return 'enabled';
  if (value === false || value === 0) return 'disabled';
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().toLowerCase();
  if (['1', 'true', 'on', 'enabled', 'yes', 'treatment'].includes(normalized)) return 'enabled';
  if (['0', 'false', 'off', 'disabled', 'no', 'control'].includes(normalized)) return 'disabled';
  return undefined;
}

function normalizeEvidence(value: unknown): LatentFeatureEvidence | undefined {
  if (
    !isRecord(value) ||
    typeof value.sourceKind !== 'string' ||
    typeof value.label !== 'string' ||
    typeof value.detail !== 'string'
  ) {
    return undefined;
  }

  if (
    ![
      'bundle',
      'document',
      'inline-script',
      'runtime-response',
      'runtime-global',
      'localStorage',
      'sessionStorage',
      'dom'
    ].includes(value.sourceKind)
  ) {
    return undefined;
  }

  return {
    sourceKind: value.sourceKind as LatentFeatureEvidence['sourceKind'],
    label: sanitizePersistedText(value.label, MAX_LABEL_LENGTH),
    sourceUrl: normalizeSanitizedUrl(value.sourceUrl),
    detail: sanitizePersistedText(value.detail, MAX_DETAIL_LENGTH),
    snippet: boundedOptionalString(
      sanitizePersistedText(value.snippet, SCRIPT_ANALYSIS_HARD_LIMITS.maxSnippetCharacters),
      SCRIPT_ANALYSIS_HARD_LIMITS.maxSnippetCharacters
    )
  };
}

function normalizeStorageLocation(value: unknown): LatentFeatureStorageLocation | undefined {
  if (
    !isRecord(value) ||
    (value.area !== 'localStorage' && value.area !== 'sessionStorage') ||
    typeof value.storageKey !== 'string' ||
    (value.format !== 'direct' && value.format !== 'json')
  ) {
    return undefined;
  }

  return {
    area: value.area,
    storageKey: value.storageKey.slice(0, MAX_LABEL_LENGTH),
    jsonPath: Array.isArray(value.jsonPath)
      ? value.jsonPath
          .filter((entry): entry is string => typeof entry === 'string')
          .slice(0, 32)
          .map((entry) => entry.slice(0, MAX_LABEL_LENGTH))
      : [],
    format: value.format
  };
}

function normalizeMutation(value: unknown): LatentFeatureMutationRecord | undefined {
  if (
    !isRecord(value) ||
    typeof value.tabId !== 'number' ||
    !Number.isSafeInteger(value.tabId) ||
    value.tabId < 0 ||
    (value.requestedState !== 'enabled' && value.requestedState !== 'disabled') ||
    (value.outcome !== 'applied' && value.outcome !== 'applied-with-warnings') ||
    !isRecord(value.codeDiff) ||
    !isRecord(value.pageDiff)
  ) {
    return undefined;
  }
  const mutationId = boundedRequiredString(value.mutationId, MAX_IDENTIFIER_LENGTH);
  const observedAt = boundedRequiredString(value.observedAt, MAX_TIMESTAMP_LENGTH);
  const pageUrl = normalizeSanitizedUrl(value.pageUrl);
  const origin = normalizeOrigin(value.origin);
  const candidateId = boundedRequiredString(value.candidateId, MAX_IDENTIFIER_LENGTH);
  const key = boundedRequiredString(value.key, MAX_LABEL_LENGTH);
  const previousValue = normalizeJsonValue(value.previousValue);
  const appliedValue = normalizeJsonValue(value.appliedValue);
  if (
    !mutationId ||
    !observedAt ||
    !pageUrl ||
    !origin ||
    !candidateId ||
    !key ||
    previousValue === undefined ||
    appliedValue === undefined
  ) {
    return undefined;
  }

  return {
    mutationId,
    observedAt,
    tabId: value.tabId,
    pageUrl,
    origin,
    candidateId,
    key: sanitizePersistedText(key, MAX_LABEL_LENGTH),
    requestedState: value.requestedState,
    previousValue,
    appliedValue,
    reloadTriggered: value.reloadTriggered === true,
    outcome: value.outcome,
    codeDiff: {
      before: sanitizePersistedText(value.codeDiff.before, MAX_MUTATION_CODE_CHARACTERS),
      after: sanitizePersistedText(value.codeDiff.after, MAX_MUTATION_CODE_CHARACTERS)
    },
    pageDiff: {
      added: normalizeMutationPageDiffEntries(value.pageDiff.added),
      changed: normalizeMutationPageDiffEntries(value.pageDiff.changed),
      removed: normalizeMutationPageDiffEntries(value.pageDiff.removed),
      highlightedCount: boundedInteger(
        value.pageDiff.highlightedCount,
        0,
        MAX_MUTATION_HIGHLIGHTED_COUNT,
        0
      ),
      truncated: value.pageDiff.truncated === true,
      limitations: uniqueBoundedStrings(
        value.pageDiff.limitations,
        MAX_MUTATION_LIMITATIONS,
        MAX_DETAIL_LENGTH
      ).map((limitation) => sanitizePersistedText(limitation, MAX_DETAIL_LENGTH))
    }
  };
}

function normalizeMutationPageDiffEntries(value: unknown): LatentFeatureMutationPageDiffEntry[] {
  if (!Array.isArray(value)) return [];
  return value
    .slice(0, MAX_MUTATION_DIFF_RECORDS)
    .map((entry): LatentFeatureMutationPageDiffEntry | undefined => {
      if (!isRecord(entry)) return undefined;
      const selector = boundedRequiredString(entry.selector, MAX_LABEL_LENGTH);
      const tagName = boundedRequiredString(entry.tagName, 100);
      if (!selector || !tagName) return undefined;
      const parentSelector = boundedOptionalString(entry.parentSelector, MAX_LABEL_LENGTH);
      return {
        selector: sanitizePersistedText(selector, MAX_LABEL_LENGTH),
        parentSelector: parentSelector
          ? sanitizePersistedText(parentSelector, MAX_LABEL_LENGTH)
          : undefined,
        tagName: sanitizePersistedText(tagName, 100)
      };
    })
    .filter(isDefined);
}

function normalizeProbe(value: unknown): LatentFeatureProbeRecord | undefined {
  if (
    !isRecord(value) ||
    typeof value.tabId !== 'number' ||
    !Number.isSafeInteger(value.tabId) ||
    value.tabId < 0
  ) {
    return undefined;
  }
  const probeId = boundedRequiredString(value.probeId, MAX_IDENTIFIER_LENGTH);
  const createdAt = boundedRequiredString(value.createdAt, MAX_TIMESTAMP_LENGTH);
  const pageUrl = normalizeSanitizedUrl(value.pageUrl);
  const origin = normalizeOrigin(value.origin);
  if (!probeId || !createdAt || !pageUrl || !origin) return undefined;

  return {
    probeId,
    createdAt,
    tabId: value.tabId,
    pageUrl,
    origin,
    changes: Array.isArray(value.changes)
      ? value.changes
          .slice(0, MAX_LATENT_CANDIDATES)
          .map(normalizeProbeChange)
          .filter(isDefined)
      : [],
    reloadTriggered: value.reloadTriggered === true
  };
}

function normalizeProbeChange(value: unknown): LatentFeatureProbeChange | undefined {
  if (
    !isRecord(value) ||
    !boundedRequiredString(value.candidateId, MAX_IDENTIFIER_LENGTH) ||
    typeof value.key !== 'string' ||
    (value.area !== 'localStorage' && value.area !== 'sessionStorage') ||
    typeof value.storageKey !== 'string' ||
    (typeof value.originalValue === 'string' &&
      value.originalValue.length > MAX_ACTIVE_PROBE_ORIGINAL_VALUE_CHARACTERS)
  ) {
    return undefined;
  }

  return {
    candidateId: boundedRequiredString(value.candidateId, MAX_IDENTIFIER_LENGTH)!,
    key: value.key.slice(0, MAX_LABEL_LENGTH),
    area: value.area,
    storageKey: value.storageKey.slice(0, MAX_LABEL_LENGTH),
    jsonPath: Array.isArray(value.jsonPath)
      ? value.jsonPath
          .slice(0, MAX_ACTIVE_PROBE_JSON_PATH_SEGMENTS)
          .filter((entry): entry is string => typeof entry === 'string')
          .map((entry) => entry.slice(0, MAX_LABEL_LENGTH))
      : [],
    hadOriginalValue: value.hadOriginalValue === true,
    originalValue: typeof value.originalValue === 'string' ? value.originalValue : undefined,
    originalCandidateValue: normalizeJsonValue(value.originalCandidateValue),
    appliedValue: normalizeJsonValue(value.appliedValue) ?? null
  };
}

function normalizeStats(value: unknown): LatentFeatureScanStats {
  const source = isRecord(value) ? value : {};
  return {
    pageSignalCount: toCount(source.pageSignalCount),
    inlineScriptCount: toCount(source.inlineScriptCount),
    runtimeObservationCount: toCount(source.runtimeObservationCount),
    loadedLibraryCount: toCount(source.loadedLibraryCount),
    libraryReadCount: toCount(source.libraryReadCount),
    libraryFailureCount: toCount(source.libraryFailureCount),
    libraryBytesRead: toCount(source.libraryBytesRead),
    libraryThreadCount: toCount(source.libraryThreadCount),
    libraryDelayMs: toCount(source.libraryDelayMs)
  };
}

function normalizeControlSurface(
  value: unknown
): LatentFeatureCandidate['controlSurface'] {
  if (
    value === 'localStorage' ||
    value === 'sessionStorage' ||
    value === 'bundle' ||
    value === 'runtime-response' ||
    value === 'runtime-global' ||
    value === 'dom' ||
    value === 'opaque-pair'
  ) {
    return value;
  }

  return 'bundle';
}

function normalizeJsonValue(
  value: unknown,
  depth = 0,
  budget: { remaining: number } = { remaining: 200 }
): JsonValue | undefined {
  if (budget.remaining <= 0 || depth > 4) return undefined;
  budget.remaining -= 1;
  if (
    value === null ||
    typeof value === 'boolean'
  ) {
    return value;
  }
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined;
  if (typeof value === 'string') {
    return sanitizePersistedText(value, MAX_METADATA_STRING_LENGTH);
  }

  if (Array.isArray(value)) {
    return value
      .slice(0, MAX_EVIDENCE_ATTRIBUTES_ARRAY)
      .map((entry) => normalizeJsonValue(entry, depth + 1, budget) ?? null);
  }

  if (isRecord(value)) {
    const output: JsonObject = {};
    for (const [rawKey, entry] of Object.entries(value).slice(0, MAX_EVIDENCE_ATTRIBUTES_KEYS)) {
      const key = boundedRequiredString(rawKey, 100);
      if (!key || key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
      output[key] = normalizeJsonValue(entry, depth + 1, budget) ?? null;
      if (budget.remaining <= 0) break;
    }
    return output;
  }

  return undefined;
}

function normalizeEvidenceRefs(value: unknown, retainedIds: Set<string>): string[] {
  return uniqueBoundedStrings(value, SCRIPT_ANALYSIS_HARD_LIMITS.maxEvidence, MAX_IDENTIFIER_LENGTH)
    .filter((evidenceId) => retainedIds.has(evidenceId));
}

function boundedRequiredString(value: unknown, maximum: number): string | undefined {
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().slice(0, maximum);
  return normalized.length > 0 ? normalized : undefined;
}

function boundedOptionalString(value: unknown, maximum: number): string | undefined {
  return boundedRequiredString(value, maximum);
}

function uniqueBoundedStrings(value: unknown, maximumEntries: number, maximumLength: number): string[] {
  if (!Array.isArray(value)) return [];
  const output: string[] = [];
  const seen = new Set<string>();
  for (const entry of value.slice(0, maximumEntries)) {
    const normalized = boundedRequiredString(entry, maximumLength);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    output.push(normalized);
  }
  return output;
}

function uniqueEnumValues<T extends string>(
  value: unknown,
  allowed: readonly T[],
  maximumEntries: number
): T[] {
  if (!Array.isArray(value)) return [];
  const output: T[] = [];
  for (const entry of value.slice(0, maximumEntries)) {
    if (isOneOf(entry, allowed) && !output.includes(entry)) output.push(entry);
  }
  return output;
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return isOneOf(value, allowed) ? value : fallback;
}

function isOneOf<T extends string>(value: unknown, allowed: readonly T[]): value is T {
  return typeof value === 'string' && allowed.includes(value as T);
}

function boundedNumber(
  value: unknown,
  minimum: number,
  maximum: number,
  fallback: number
): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback;
  return Math.max(minimum, Math.min(maximum, value));
}

function boundedInteger(
  value: unknown,
  minimum: number,
  maximum: number,
  fallback: number
): number {
  return Math.round(boundedNumber(value, minimum, maximum, fallback));
}

function boundedOptionalInteger(
  value: unknown,
  minimum: number,
  maximum: number
): number | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value)) return undefined;
  return Math.round(Math.max(minimum, Math.min(maximum, value)));
}

function boundedCount(value: unknown): number {
  return boundedInteger(value, 0, MAX_SAFE_PERSISTED_COUNT, 0);
}

function normalizeSha256(value: unknown): string | undefined {
  const normalized = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return /^[a-f0-9]{64}$/.test(normalized) ? normalized : undefined;
}

function normalizeArtifactFingerprint(value: string): string | undefined {
  const separator = value.lastIndexOf(':');
  if (separator <= 0) return undefined;
  const artifactId = boundedRequiredString(value.slice(0, separator), MAX_IDENTIFIER_LENGTH);
  const sha256 = normalizeSha256(value.slice(separator + 1));
  return artifactId && sha256 ? `${artifactId}:${sha256}` : undefined;
}

function artifactIdFromFingerprint(value: string): string {
  return value.slice(0, value.lastIndexOf(':'));
}

function normalizeOrigin(value: unknown): string | undefined {
  const raw = boundedRequiredString(value, MAX_URL_LENGTH);
  if (!raw) return undefined;
  try {
    const parsed = new URL(raw);
    return parsed.origin === 'null' ? undefined : parsed.origin;
  } catch {
    return undefined;
  }
}

function normalizeSanitizedUrl(value: unknown): string | undefined {
  const raw = boundedRequiredString(value, MAX_URL_LENGTH);
  if (!raw) return undefined;
  if (/^(?:data:\[inline-source-map\]|\[unparseable-url\])$/i.test(raw)) return raw;
  try {
    const parsed = new URL(raw);
    if (!['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol)) {
      return `${parsed.protocol}[redacted]`;
    }
    parsed.username = '';
    parsed.password = '';
    parsed.hash = '';
    const names = [...new Set([...parsed.searchParams.keys()])]
      .filter((name) => /^[A-Za-z0-9_.~-]{1,80}$/.test(name))
      .sort()
      .slice(0, 30);
    parsed.search = names.length > 0
      ? `?${names.map((name) => `${encodeURIComponent(name)}=`).join('&')}`
      : '';
    parsed.pathname = parsed.pathname
      .split('/')
      .map((segment) =>
        /^\d{2,}$/.test(segment) ||
        /^[A-Fa-f0-9]{8,}$/.test(segment) ||
        /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(segment) ||
        /^[A-Za-z0-9_-]{20,}$/.test(segment) ||
        /%40|@/.test(segment)
          ? '{id}'
          : segment.slice(0, 100)
      )
      .join('/');
    return parsed.toString().slice(0, MAX_URL_LENGTH);
  } catch {
    return undefined;
  }
}

function sanitizePersistedText(value: unknown, maximum: number): string {
  if (typeof value !== 'string') return '';
  return value
    .replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/gi, ' ')
    .replace(/\b(?:https?|wss?):\/\/[^\s<>"'`()\[\]{}]+/gi, (url) =>
      normalizeSanitizedUrl(url) ?? '[redacted-url]'
    )
    .replace(/Bearer\s+[A-Za-z0-9._~+\/-]+=*/gi, 'Bearer [redacted]')
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, '[redacted-jwt]')
    .replace(/([?&][A-Za-z0-9_.~-]{1,80}=)[^&#\s"'`]*/g, '$1[redacted]')
    .replace(/((?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|cookie)\s*[:=]\s*["'`]?)\S+/gi, '$1[redacted]')
    .replace(/\b(?:[A-Fa-f0-9]{32,}|[A-Za-z0-9+/_-]{48,}={0,2})\b/g, '[redacted-long-value]')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maximum);
}

function isSensitiveMetadataKey(value: string): boolean {
  return /(?:^|[-_.:/])(?:auth|authorization|cookie|access[-_]?token|refresh[-_]?token|jwt|csrf|password|passwd|secret|credential|session[-_]?id)(?:$|[-_.:/])/i.test(value);
}

function isSensitiveFeatureControlKey(value: string): boolean {
  return /(?:^|[-_.:/])(?:auth(?:entication)?|authorization|cookies?|api[-_]?keys?|private[-_]?keys?|access[-_]?tokens?|refresh[-_]?tokens?|jwt|csrf|passwords?|passwd|secrets?|credentials?|sessions?|session[-_]?ids?|licenses?|subscriptions?|permissions?|roles?)(?:$|[-_.:/])/i.test(value);
}

function isUrlMetadataKey(value: string): boolean {
  return /(?:^|[-_.:/])(?:url|uri|href|src|endpoint|destination|responseUrl)(?:$|[-_.:/])/i.test(value);
}

function toCount(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
    ? Math.floor(value)
    : 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isDefined<T>(value: T | undefined): value is T {
  return value !== undefined;
}
