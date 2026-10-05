export const SCRIPT_PURPOSE_ANALYSIS_KIND = 'blanche.script-purpose-analysis' as const;
export const SCRIPT_PURPOSE_RUBRIC_VERSION = 'blanche.script-purpose-rubric.v1' as const;
export const SCRIPT_PURPOSE_SCORE_MODEL = 'blanche.script-review-priority.v1' as const;

export type ScriptPurposeAnalysisKind = typeof SCRIPT_PURPOSE_ANALYSIS_KIND;
export type ScriptPurposeRubricVersion = typeof SCRIPT_PURPOSE_RUBRIC_VERSION;
export type ScriptPurposeScoreModel = typeof SCRIPT_PURPOSE_SCORE_MODEL;
export type ScriptPurposeConfidence = 'high' | 'medium' | 'low';

export type ScriptTransformKind =
  | 'readable'
  | 'minified'
  | 'bundled'
  | 'packed'
  | 'obfuscated'
  | 'unknown';

export type ScriptPurposeCategory =
  | 'loader-runtime'
  | 'app-shell-ui'
  | 'api-data'
  | 'identity-access'
  | 'feature-configuration'
  | 'telemetry-analytics'
  | 'storage-offline'
  | 'realtime-messaging'
  | 'file-media-crypto-payment'
  | 'developer-debug-admin'
  | 'third-party-integration'
  | 'unknown';

export type ScriptPurposeRole = 'primary' | 'secondary' | 'candidate';

export type ScriptBehaviorAxis =
  | 'network'
  | 'dom-ui'
  | 'data-handling'
  | 'identity-session-authorization'
  | 'server-state-change'
  | 'client-storage'
  | 'dynamic-code-loading'
  | 'persistence-background-realtime'
  | 'cross-origin-transfer'
  | 'latent-debug-admin';

/**
 * 0: not observed; 1: a reference/signature exists; 2: a static call or registration links the
 * capability to executable code; 3: an attributable runtime observation was supplied.
 */
export type ScriptBehaviorMaturity = 0 | 1 | 2 | 3;

export type ScriptEvidenceClass =
  | 'content-metric'
  | 'literal'
  | 'structural-pattern'
  | 'component-signature'
  | 'source-map'
  | 'runtime';

export type ScriptEvidenceDisposition = 'observed' | 'inferred';

export type ScriptCoverageGapCode =
  | 'EMPTY_SOURCE'
  | 'TRUNCATED_SOURCE'
  | 'MISSING_CONTENT_HASH'
  | 'HEURISTIC_STATIC_ANALYSIS'
  | 'SOURCE_MAP_UNAVAILABLE'
  | 'SOURCE_MAP_MISMATCH'
  | 'UNRESOLVED_DYNAMIC_IMPORT'
  | 'UNRESOLVED_PACKED_PAYLOAD'
  | 'UNRESOLVED_WASM'
  | 'RUNTIME_NOT_OBSERVED';

export type ScriptCoverageStatus = 'complete' | 'partial' | 'limited';
export type ScriptIndicatorKind =
  | 'endpoint'
  | 'host'
  | 'storage-key'
  | 'feature-key'
  | 'event-name'
  | 'source-map';
export type ScriptScopeDisposition = 'in-scope' | 'out-of-scope' | 'review' | 'unknown';
export type ScriptOwnership =
  | 'target'
  | 'same-organization'
  | 'delegated'
  | 'third-party'
  | 'shared'
  | 'unknown';

export interface ScriptPurposeSourceInput {
  sourceKind: 'external' | 'inline' | 'document';
  label: string;
  sourceUrl?: string;
  finalUrl?: string;
  text: string;
  contentType?: string;
  sha256?: string;
  declaredByteLength?: number;
  acquiredAt?: string;
  truncated?: boolean;
  /** Zero-based occurrence among delivered sources with the same source locator. */
  deliveryIndex?: number;
}

export interface ScriptSourceMapInput {
  status: 'matched' | 'mismatch' | 'unavailable';
  url?: string;
  sha256?: string;
  sourceCount?: number;
  symbols?: string[];
}

export interface ScriptScopeInput {
  disposition: ScriptScopeDisposition;
  ownership: ScriptOwnership;
  policyId?: string;
  policyVersion?: string;
  matchedRuleIds?: string[];
}

export interface ScriptRuntimeObservationInput {
  axis: ScriptBehaviorAxis;
  detail: string;
  targetUrl?: string;
  method?: string;
  evidenceId?: string;
  purposeHints?: ScriptPurposeCategory[];
}

export interface ScriptPurposeAnalysisOptions {
  maxEvidence?: number;
  maxIndicators?: number;
  maxClaims?: number;
  maxSnippetCharacters?: number;
}

export interface ScriptPurposeAnalysisContext {
  sourceMap?: ScriptSourceMapInput;
  scope?: ScriptScopeInput;
  runtimeObservations?: ScriptRuntimeObservationInput[];
  options?: ScriptPurposeAnalysisOptions;
}

export interface ScriptPurposeAnalysisInput extends ScriptPurposeAnalysisContext {
  source: ScriptPurposeSourceInput;
}

export interface ScriptEvidenceRecord {
  evidenceId: string;
  evidenceClass: ScriptEvidenceClass;
  disposition: ScriptEvidenceDisposition;
  label: string;
  detail: string;
  sourceUrl?: string;
  startOffset?: number;
  endOffset?: number;
  snippet?: string;
}

export interface ScriptTransformMetrics {
  characterCount: number;
  byteLength: number;
  lineCount: number;
  nonEmptyLineCount: number;
  longestLineLength: number;
  meanNonEmptyLineLength: number;
  whitespaceRatio: number;
}

export interface ScriptTransformSignal {
  code: string;
  kind: ScriptTransformKind;
  weight: number;
  detail: string;
  evidenceRefs: string[];
}

export interface ScriptTransformAssessment {
  primary: ScriptTransformKind;
  detected: ScriptTransformKind[];
  complexityScore: number;
  confidence: ScriptPurposeConfidence;
  metrics: ScriptTransformMetrics;
  signals: ScriptTransformSignal[];
}

export interface ScriptCoverageGap {
  code: ScriptCoverageGapCode;
  material: boolean;
  detail: string;
}

export interface ScriptAnalysisCoverage {
  status: ScriptCoverageStatus;
  analyzedBytes: number;
  declaredBytes: number;
  byteCoverageRatio: number;
  runtimeObservationCount: number;
  gaps: ScriptCoverageGap[];
}

export interface ScriptPurposeClaim {
  category: ScriptPurposeCategory;
  role: ScriptPurposeRole;
  score: number;
  confidence: ScriptPurposeConfidence;
  reason: string;
  evidenceRefs: string[];
}

export interface ScriptBehaviorClaim {
  axis: ScriptBehaviorAxis;
  maturity: ScriptBehaviorMaturity;
  confidence: ScriptPurposeConfidence;
  summary: string;
  evidenceRefs: string[];
}

export interface ScriptSanitizedIndicator {
  indicatorId: string;
  kind: ScriptIndicatorKind;
  value: string;
  confidence: ScriptPurposeConfidence;
  evidenceRefs: string[];
}

export interface ScriptReviewPriorityFactor {
  code: string;
  baseWeight: number;
  appliedWeight: number;
  reason: string;
  evidenceRefs: string[];
}

export interface ScriptReviewPriority {
  scoreModel: ScriptPurposeScoreModel;
  score: number;
  band: 'low' | 'medium' | 'high' | 'urgent';
  isVulnerabilitySeverity: false;
  factors: ScriptReviewPriorityFactor[];
}

export type ScriptTestStageMode =
  | 'offline-static'
  | 'isolated-sandbox'
  | 'passive-observation'
  | 'authorized-active';
export type ScriptTestStageStatus = 'ready' | 'conditional' | 'blocked' | 'complete';
export type ScriptTestTerminationReason =
  | 'NONE'
  | 'NO_SOURCE'
  | 'STATIC_COVERAGE_GAP'
  | 'ISOLATION_REQUIRED'
  | 'RUNTIME_EVIDENCE_REQUIRED'
  | 'EXPLICIT_SCOPE_REQUIRED'
  | 'THIRD_PARTY_ACTIVE_TEST_BLOCKED'
  | 'STATE_CHANGE_REVIEW_REQUIRED';

export interface ScriptTestPlanStage {
  stage: 0 | 1 | 2 | 3;
  mode: ScriptTestStageMode;
  status: ScriptTestStageStatus;
  objective: string;
  actions: string[];
  successCriteria: string[];
  stopConditions: string[];
  terminationReason: ScriptTestTerminationReason;
}

export interface ScriptTestPlan {
  generatedFromRubric: ScriptPurposeRubricVersion;
  stages: ScriptTestPlanStage[];
}

export interface ScriptPurposeAnalysisArtifact {
  artifactId: string;
  sourceKind: ScriptPurposeSourceInput['sourceKind'];
  label: string;
  sourceUrl?: string;
  finalUrl?: string;
  contentType?: string;
  sha256?: string;
  acquiredAt?: string;
  scope: ScriptScopeInput;
}

export interface ScriptPurposeAnalysisResult {
  kind: ScriptPurposeAnalysisKind;
  rubricVersion: ScriptPurposeRubricVersion;
  artifact: ScriptPurposeAnalysisArtifact;
  transform: ScriptTransformAssessment;
  coverage: ScriptAnalysisCoverage;
  purposeClaims: ScriptPurposeClaim[];
  behaviorClaims: ScriptBehaviorClaim[];
  indicators: ScriptSanitizedIndicator[];
  evidence: ScriptEvidenceRecord[];
  reviewPriority: ScriptReviewPriority;
  testPlan: ScriptTestPlan;
}

export interface ScriptPatternRule {
  code: string;
  label: string;
  patterns: readonly string[];
  flags?: string;
  evidenceClass: Extract<
    ScriptEvidenceClass,
    'literal' | 'structural-pattern' | 'component-signature'
  >;
  detail: string;
}

export interface ScriptPurposePatternRule extends ScriptPatternRule {
  category: Exclude<ScriptPurposeCategory, 'unknown'>;
  points: 1 | 2 | 3;
}

export interface ScriptBehaviorPatternRule extends ScriptPatternRule {
  axis: ScriptBehaviorAxis;
  maturity: 1 | 2;
  summary: string;
}

export interface ScriptTransformPatternRule extends ScriptPatternRule {
  kind: Exclude<ScriptTransformKind, 'readable' | 'minified' | 'unknown'>;
  weight: number;
}

export const SCRIPT_TRANSFORM_PATTERN_RULES: readonly ScriptTransformPatternRule[] = [
  {
    code: 'TRANSFORM_WEBPACK_BUNDLE',
    label: 'Webpack bundle runtime',
    kind: 'bundled',
    weight: 28,
    evidenceClass: 'component-signature',
    patterns: ['__webpack_require__', 'webpackChunk[A-Za-z0-9_$]*\\s*='],
    detail: 'Webpack module or chunk runtime markers are present.'
  },
  {
    code: 'TRANSFORM_BUNDLER_RUNTIME',
    label: 'Bundler module runtime',
    kind: 'bundled',
    weight: 22,
    evidenceClass: 'structural-pattern',
    patterns: [
      '\\bparcelRequire\\b',
      '\\b__commonJS\\b',
      '\\bdefine\\s*\\(\\s*\\[[^\\]]*\\]\\s*,',
      '\\bmodules\\s*:\\s*\\{'
    ],
    detail: 'A module registry or bundler bootstrap is present.'
  },
  {
    code: 'TRANSFORM_PACKER_EVAL',
    label: 'Packer decoder',
    kind: 'packed',
    weight: 68,
    evidenceClass: 'structural-pattern',
    patterns: [
      'eval\\s*\\(\\s*function\\s*\\(\\s*p\\s*,\\s*a\\s*,\\s*c\\s*,\\s*k',
      '(?:eval|Function)\\s*\\(\\s*(?:atob|decodeURIComponent)\\s*\\('
    ],
    detail: 'Code passes a decoded payload into a dynamic execution primitive.'
  },
  {
    code: 'TRANSFORM_STRING_DECODER',
    label: 'Encoded string decoder',
    kind: 'packed',
    weight: 42,
    evidenceClass: 'structural-pattern',
    patterns: [
      'String\\.fromCharCode\\s*\\([^)]{24,}\\)',
      '\\batob\\s*\\(\\s*["\'`][A-Za-z0-9+/=_-]{80,}'
    ],
    detail: 'A substantial encoded string is decoded at runtime.'
  },
  {
    code: 'TRANSFORM_HEX_IDENTIFIERS',
    label: 'Generated hexadecimal identifiers',
    kind: 'obfuscated',
    weight: 45,
    evidenceClass: 'structural-pattern',
    patterns: ['(?:\\b_0x[a-f0-9]{4,}\\b[^\\n]*){3,}'],
    detail: 'Repeated generated hexadecimal identifiers suggest identifier obfuscation.'
  },
  {
    code: 'TRANSFORM_CONTROL_FLOW_FLATTENING',
    label: 'Control-flow flattening',
    kind: 'obfuscated',
    weight: 55,
    evidenceClass: 'structural-pattern',
    patterns: ['while\\s*\\(\\s*(?:true|!!\\[\\]|!0)\\s*\\)\\s*\\{[^{}]{0,400}switch\\s*\\('],
    detail: 'A constant loop and switch dispatcher resemble control-flow flattening.'
  },
  {
    code: 'TRANSFORM_JSFUCK',
    label: 'Punctuation-only encoding',
    kind: 'obfuscated',
    weight: 72,
    evidenceClass: 'structural-pattern',
    patterns: ['(?:!\\[\\]|\\+\\[\\]|\\[\\]\\[\\]\\+){8,}'],
    detail: 'Dense punctuation-only expressions resemble JSFuck-style encoding.'
  }
] as const;

export const SCRIPT_PURPOSE_PATTERN_RULES: readonly ScriptPurposePatternRule[] = [
  {
    code: 'PURPOSE_LOADER_RUNTIME', label: 'Module loader runtime', category: 'loader-runtime', points: 2,
    evidenceClass: 'component-signature', patterns: ['__webpack_require__|webpackChunk|parcelRequire|\\bdefine\\s*\\(\\s*\\[|\\bSystem\\.register\\s*\\('],
    detail: 'A recognized module-loader or chunk runtime is present.'
  },
  {
    code: 'PURPOSE_DYNAMIC_IMPORT', label: 'Dynamic module loading', category: 'loader-runtime', points: 3,
    evidenceClass: 'structural-pattern', patterns: ['\\bimport\\s*\\(|document\\.createElement\\s*\\(\\s*["\'`]script'],
    detail: 'Executable code loads another module or script.'
  },
  {
    code: 'PURPOSE_UI_RENDER', label: 'UI rendering', category: 'app-shell-ui', points: 3,
    evidenceClass: 'structural-pattern', patterns: ['createRoot\\s*\\(|ReactDOM\\.render\\s*\\(|createApp\\s*\\(|\\.mount\\s*\\(|customElements\\.define\\s*\\('],
    detail: 'The artifact registers or mounts application UI.'
  },
  {
    code: 'PURPOSE_UI_ROUTING', label: 'Client routing', category: 'app-shell-ui', points: 2,
    evidenceClass: 'component-signature', patterns: ['createBrowserRouter|BrowserRouter|RouterProvider|vue-router|history\\.pushState'],
    detail: 'Client-side navigation or routing markers are present.'
  },
  {
    code: 'PURPOSE_API_CLIENT', label: 'API client', category: 'api-data', points: 3,
    evidenceClass: 'structural-pattern', patterns: ['\\bfetch\\s*\\(|new\\s+XMLHttpRequest\\s*\\(|\\baxios(?:\\.|\\s*\\()|\\.request\\s*\\('],
    detail: 'Executable code constructs application-facing HTTP requests.'
  },
  {
    code: 'PURPOSE_GRAPHQL', label: 'GraphQL client', category: 'api-data', points: 3,
    evidenceClass: 'structural-pattern', patterns: ['ApolloClient|\\bgql\\s*`|\\bquery\\s+[A-Za-z_$]|\\bmutation\\s+[A-Za-z_$]'],
    detail: 'GraphQL client or operation markers are present.'
  },
  {
    code: 'PURPOSE_IDENTITY_PROVIDER', label: 'Identity client', category: 'identity-access', points: 3,
    evidenceClass: 'structural-pattern', patterns: ['loginWithRedirect\\s*\\(|acquireTokenSilent\\s*\\(|signIn\\s*\\(|signOut\\s*\\(|refreshToken\\s*\\('],
    detail: 'Executable identity-provider operations are present.'
  },
  {
    code: 'PURPOSE_IDENTITY_TERMS', label: 'Identity semantics', category: 'identity-access', points: 1,
    evidenceClass: 'literal', patterns: ['authorization|access[_-]?token|refresh[_-]?token|oauth|openid|pkce|session'],
    detail: 'Identity, token, or session terms are present.'
  },
  {
    code: 'PURPOSE_FEATURE_CLIENT', label: 'Feature-control client', category: 'feature-configuration', points: 3,
    evidenceClass: 'structural-pattern', patterns: ['isFeatureEnabled\\s*\\(|getFeatureFlag\\s*\\(|checkGate\\s*\\(|getBooleanValue\\s*\\(|variation\\s*\\('],
    detail: 'Executable code queries a feature-control provider.'
  },
  {
    code: 'PURPOSE_CONFIG_TERMS', label: 'Configuration semantics', category: 'feature-configuration', points: 1,
    evidenceClass: 'literal', patterns: ['feature[_-]?flags?|experiment|rollout|remote[_-]?config|bootstrapConfig'],
    detail: 'Feature, experiment, or configuration terms are present.'
  },
  {
    code: 'PURPOSE_TELEMETRY', label: 'Telemetry client', category: 'telemetry-analytics', points: 3,
    evidenceClass: 'structural-pattern', patterns: ['sendBeacon\\s*\\(|\\.track\\s*\\(|captureException\\s*\\(|gtag\\s*\\(|analytics\\.'],
    detail: 'Executable telemetry or analytics calls are present.'
  },
  {
    code: 'PURPOSE_STORAGE_OFFLINE', label: 'Client persistence', category: 'storage-offline', points: 3,
    evidenceClass: 'structural-pattern', patterns: ['localStorage\\.(?:getItem|setItem)|sessionStorage\\.(?:getItem|setItem)|indexedDB\\.open|caches\\.open'],
    detail: 'Executable code uses browser persistence or offline storage.'
  },
  {
    code: 'PURPOSE_SERVICE_WORKER', label: 'Service worker', category: 'storage-offline', points: 3,
    evidenceClass: 'structural-pattern', patterns: ['serviceWorker\\.register\\s*\\(|self\\.addEventListener\\s*\\(\\s*["\'`](?:fetch|install|activate)'],
    detail: 'A service worker is registered or handles lifecycle events.'
  },
  {
    code: 'PURPOSE_REALTIME', label: 'Realtime messaging', category: 'realtime-messaging', points: 3,
    evidenceClass: 'structural-pattern', patterns: ['new\\s+WebSocket\\s*\\(|new\\s+EventSource\\s*\\(|socket\\.emit\\s*\\(|subscribe\\s*\\('],
    detail: 'Executable realtime connection or subscription code is present.'
  },
  {
    code: 'PURPOSE_FILE_MEDIA', label: 'File or media processing', category: 'file-media-crypto-payment', points: 3,
    evidenceClass: 'structural-pattern', patterns: ['new\\s+FileReader\\s*\\(|createObjectURL\\s*\\(|MediaRecorder\\s*\\(|subtle\\.(?:encrypt|decrypt|sign|verify)\\s*\\('],
    detail: 'Executable file, media, or cryptographic processing is present.'
  },
  {
    code: 'PURPOSE_PAYMENT', label: 'Payment workflow', category: 'file-media-crypto-payment', points: 2,
    evidenceClass: 'component-signature', patterns: ['PaymentRequest\\s*\\(|Stripe\\s*\\(|confirmCardPayment|paypal\\.Buttons'],
    detail: 'A recognized payment workflow or provider signature is present.'
  },
  {
    code: 'PURPOSE_DEBUG_ADMIN', label: 'Developer or administrative tooling', category: 'developer-debug-admin', points: 2,
    evidenceClass: 'component-signature', patterns: ['__REDUX_DEVTOOLS_EXTENSION__|eruda\\.init|vConsole|admin(?:Panel|Console)|debugMode'],
    detail: 'Developer, debug, or administrative tooling markers are present.'
  },
  {
    code: 'PURPOSE_THIRD_PARTY', label: 'Third-party integration', category: 'third-party-integration', points: 2,
    evidenceClass: 'component-signature', patterns: ['stripe\\.com|paypal\\.com|sentry\\.io|segment\\.(?:com|io)|google-analytics\\.com|intercom'],
    detail: 'A recognized external service integration is referenced.'
  }
] as const;

export const SCRIPT_BEHAVIOR_PATTERN_RULES: readonly ScriptBehaviorPatternRule[] = [
  {
    code: 'BEHAVIOR_NETWORK_CALL', label: 'Network request call', axis: 'network', maturity: 2,
    evidenceClass: 'structural-pattern', patterns: ['\\bfetch\\s*\\(|new\\s+XMLHttpRequest\\s*\\(|\\baxios(?:\\.|\\s*\\()|sendBeacon\\s*\\('],
    detail: 'Executable code can initiate HTTP requests.', summary: 'The artifact contains executable network request code.'
  },
  {
    code: 'BEHAVIOR_NETWORK_LITERAL', label: 'Network endpoint reference', axis: 'network', maturity: 1,
    evidenceClass: 'literal', patterns: ['["\'`](?:https?|wss?)://|["\'`]/(?:api|graphql|v[0-9]+|auth|admin)/'],
    detail: 'A network endpoint literal is present.', summary: 'The artifact references network destinations.'
  },
  {
    code: 'BEHAVIOR_DOM_UI', label: 'DOM mutation', axis: 'dom-ui', maturity: 2,
    evidenceClass: 'structural-pattern', patterns: ['innerHTML\\s*=|insertAdjacentHTML\\s*\\(|appendChild\\s*\\(|createElement\\s*\\(|createRoot\\s*\\('],
    detail: 'Executable code reads or changes the document UI.', summary: 'The artifact contains executable DOM or UI behavior.'
  },
  {
    code: 'BEHAVIOR_DATA', label: 'Sensitive-data semantics', axis: 'data-handling', maturity: 1,
    evidenceClass: 'literal', patterns: ['credential|password|access[_-]?token|personalData|cardNumber|accountNumber|patient|healthRecord'],
    detail: 'Potentially sensitive data field semantics are referenced.', summary: 'The artifact references potentially sensitive data classes.'
  },
  {
    code: 'BEHAVIOR_IDENTITY', label: 'Identity or session operation', axis: 'identity-session-authorization', maturity: 2,
    evidenceClass: 'structural-pattern', patterns: ['loginWithRedirect\\s*\\(|acquireTokenSilent\\s*\\(|refreshToken\\s*\\(|Authorization["\'`]?\\s*[:=]|credentials\\s*:\\s*["\'`]include'],
    detail: 'Executable code participates in identity, token, or session handling.', summary: 'The artifact contains identity, session, or authorization behavior.'
  },
  {
    code: 'BEHAVIOR_STATE_CHANGE', label: 'State-changing request', axis: 'server-state-change', maturity: 2,
    evidenceClass: 'structural-pattern', patterns: ['method\\s*:\\s*["\'`](?:POST|PUT|PATCH|DELETE)["\'`]|\\bmutation\\s+[A-Za-z_$]|\\.(?:post|put|patch|delete)\\s*\\('],
    detail: 'Executable request code names a state-changing method or mutation.', summary: 'The artifact contains code for a potentially state-changing server operation.'
  },
  {
    code: 'BEHAVIOR_STORAGE', label: 'Client storage access', axis: 'client-storage', maturity: 2,
    evidenceClass: 'structural-pattern', patterns: ['localStorage\\.(?:getItem|setItem|removeItem)|sessionStorage\\.(?:getItem|setItem|removeItem)|indexedDB\\.open|document\\.cookie'],
    detail: 'Executable code accesses client-side storage.', summary: 'The artifact contains client storage behavior.'
  },
  {
    code: 'BEHAVIOR_DYNAMIC_CODE', label: 'Dynamic code or module loading', axis: 'dynamic-code-loading', maturity: 2,
    evidenceClass: 'structural-pattern', patterns: ['\\beval\\s*\\(|new\\s+Function\\s*\\(|\\bimport\\s*\\(|document\\.createElement\\s*\\(\\s*["\'`]script'],
    detail: 'Executable code evaluates or loads code dynamically.', summary: 'The artifact contains dynamic code or module loading behavior.'
  },
  {
    code: 'BEHAVIOR_BACKGROUND', label: 'Persistent or realtime execution', axis: 'persistence-background-realtime', maturity: 2,
    evidenceClass: 'structural-pattern', patterns: ['serviceWorker\\.register\\s*\\(|new\\s+Worker\\s*\\(|new\\s+WebSocket\\s*\\(|new\\s+EventSource\\s*\\(|setInterval\\s*\\('],
    detail: 'Executable code starts background, persistent, or realtime work.', summary: 'The artifact contains background, persistent, or realtime behavior.'
  },
  {
    code: 'BEHAVIOR_LATENT_ADMIN', label: 'Latent, debug, or admin control', axis: 'latent-debug-admin', maturity: 1,
    evidenceClass: 'literal', patterns: ['feature[_-]?flags?|experiment|debugMode|admin(?:Panel|Console)|internalOnly|developerMode'],
    detail: 'A feature, debug, internal, or administrative control is referenced.', summary: 'The artifact references latent, debug, or administrative controls.'
  }
] as const;

export const SCRIPT_PURPOSE_SCORE_THRESHOLDS = {
  primary: 7,
  secondary: 4,
  urgent: 75,
  high: 50,
  medium: 25
} as const;

export const SCRIPT_REVIEW_PRIORITY_WEIGHTS = {
  STATE_CHANGE: 25,
  IDENTITY_ACCESS: 20,
  PRIVILEGED_ADMIN: 20,
  SENSITIVE_DATA: 15,
  DYNAMIC_EXECUTION: 15,
  CROSS_ORIGIN: 10,
  PERSISTENCE_REALTIME: 10,
  LATENT_CONTROL: 10,
  NETWORK_FANOUT: 5,
  VENDOR_ONLY: -15,
  TELEMETRY_ONLY: -10,
  STATIC_UI_ONLY: -10
} as const;

export const SCRIPT_ANALYSIS_DEFAULT_LIMITS = {
  maxEvidence: 160,
  maxIndicators: 80,
  maxClaims: 12,
  maxSnippetCharacters: 240
} as const;

export const SCRIPT_ANALYSIS_HARD_LIMITS = {
  maxEvidence: 500,
  maxIndicators: 250,
  maxClaims: 32,
  maxSnippetCharacters: 500
} as const;
