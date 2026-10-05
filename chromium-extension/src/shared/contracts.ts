import type {
  ArtifactDescriptor,
  BlancheTrafficLedgerV1,
  BlancheExportV1,
  CollectionMetadata,
  CollectionMode,
  CollectorResult,
  ExportError,
  ExportWarning,
  JsonObject,
  JsonValue,
  PageMetadata,
  PermissionsState,
  ScopeDecision,
  TrafficLedgerEntryV1,
  TrafficLedgerSummary,
  TrafficScopeDisposition,
  VisibilityGap
} from '../../../shared-schema/src';
import type { SearchWorkbenchState } from './searchWorkbench';
import type { InterestWorkbenchState } from './interestWorkbench';
import type { DocumentWorkbenchState } from './documentWorkbench';
import type { EngagementProfilesState } from './engagementProfiles';
import type { LatentFeatureWorkbenchState } from './latentFeatureWorkbench';
import type { SearchExecutionState } from './searchExecution';
import type { FindingsWorkbenchState } from './findingsWorkbench';
import type { FindingInput } from './findingsWorkbench';

export type ExecutionSurface = 'background' | 'content' | 'devtools' | 'sidepanel' | 'offscreen';
export type RuntimeCallerSurface = 'background' | 'devtools' | 'sidepanel';
export type ModuleActionStatus = 'ok' | 'partial' | 'error';
export type SessionStatus = 'running' | 'completed' | 'failed';

export interface SelectOptionDefinition {
  label: string;
  value: string;
}

export interface ModuleSettingsFieldDefinition {
  key: string;
  title: string;
  description?: string;
  type: 'boolean' | 'number' | 'string' | 'select';
  defaultValue: JsonValue;
  options?: SelectOptionDefinition[];
}

export interface ModuleCommandDefinition {
  id: string;
  title: string;
  description: string;
  requiresTab: boolean;
}

export interface CollectorDefinition {
  id: string;
  name: string;
  description: string;
  mode: CollectionMode | 'both';
  surface: ExecutionSurface;
}

export interface ExporterDefinition {
  id: string;
  name: string;
  format: 'json' | 'html';
  schemaVersion: string;
}

export interface UIContributionDefinition {
  surface: 'sidepanel' | 'devtools';
  title: string;
  description?: string;
}

export interface ManifestContributionDefinition {
  contentScripts?: chrome.runtime.ManifestV3['content_scripts'];
  webAccessibleResources?: chrome.runtime.ManifestV3['web_accessible_resources'];
}

export interface ModuleDescriptor {
  id: string;
  name: string;
  version: string;
  description: string;
  requiredPermissions: string[];
  requiredHostPermissions: string[];
  executionSurfaces: ExecutionSurface[];
  commands: ModuleCommandDefinition[];
  settingsSchema: ModuleSettingsFieldDefinition[];
  collectors: CollectorDefinition[];
  exporters: ExporterDefinition[];
  uiContributions: UIContributionDefinition[];
  manifestContributions?: ManifestContributionDefinition;
}

export interface ModulePersistedState {
  enabled: boolean;
  settings: Record<string, JsonValue>;
}

export interface CollectionSessionRecord {
  sessionId: string;
  moduleId: string;
  tabId: number;
  mode: CollectionMode;
  reloadTriggered: boolean;
  startedAt: string;
  finishedAt?: string;
  status: SessionStatus;
  note?: string;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: 'debug' | 'info' | 'warn' | 'error';
  source: string;
  message: string;
  context?: JsonObject;
}

export type FeedEntryKind =
  | 'burp-capture'
  | 'osint-seed'
  | 'osint-report'
  | 'document-hit'
  | 'interest-score'
  | 'javascript-analysis'
  | 'latent-feature';
export type FeedEntrySeverity = 'info' | 'notice' | 'warning';

export interface FeedEntry {
  id: string;
  kind: FeedEntryKind;
  sourceModuleId: string;
  createdAt: string;
  host?: string;
  severity?: FeedEntrySeverity;
  title: string;
  detail?: string;
  context?: JsonObject;
}

export type FeedEntryInput = Omit<FeedEntry, 'id' | 'createdAt'>;

export interface FeedManager {
  add(entry: FeedEntryInput): FeedEntry;
  list(): FeedEntry[];
}

export interface ModuleStateSnapshot {
  descriptor: ModuleDescriptor;
  enabled: boolean;
  settings: Record<string, JsonValue>;
}

export interface HostStateSnapshot {
  modules: ModuleStateSnapshot[];
  sessions: CollectionSessionRecord[];
  logs: LogEntry[];
  searchWorkbench: SearchWorkbenchState;
  searchExecution: SearchExecutionState;
  findingsWorkbench: FindingsWorkbenchState;
  interestWorkbench: InterestWorkbenchState;
  documentWorkbench: DocumentWorkbenchState;
  engagementProfiles: EngagementProfilesState;
  latentFeatureWorkbench: LatentFeatureWorkbenchState;
  feed: FeedEntry[];
  trafficLedgerSummary: TrafficLedgerSummary;
  lastExport?: BlancheExportV1;
}

export interface TrafficLedgerQuery {
  tabId?: number;
  sourceOrigin?: string;
  targetOrigin?: string;
  scope?: TrafficScopeDisposition;
  minScore?: number;
  limit?: number;
}

export interface TrafficLedgerQueryResult {
  entries: TrafficLedgerEntryV1[];
  summary: TrafficLedgerSummary;
  totalMatchedEntries?: number;
  truncated?: boolean;
  observationWindowStart?: string;
}

export interface ExportBuildInput {
  component: string;
  hostVersion: string;
  module: {
    id: string;
    name: string;
    version: string;
  };
  page: PageMetadata;
  collection: CollectionMetadata;
  permissions: PermissionsState;
  collectors: CollectorResult[];
  artifacts: ArtifactDescriptor[];
  trafficLedger: BlancheTrafficLedgerV1;
  warnings: ExportWarning[];
  errors: ExportError[];
  visibilityGaps: VisibilityGap[];
}

export interface ModuleActionRequest {
  actionId: string;
  tabId?: number;
  caller: RuntimeCallerSurface;
  input?: JsonObject;
}

export interface ModuleActionResult {
  status: ModuleActionStatus;
  message: string;
  sessionId?: string;
  export?: BlancheExportV1;
  data?: JsonObject;
  warnings?: ExportWarning[];
  errors?: ExportError[];
}

export interface ModuleHostServices {
  buildExport(input: ExportBuildInput): BlancheExportV1;
  getTrafficLedgerExport(input: {
    sourceSessionId: string;
    tabId?: number;
    targetOrigin?: string;
    since?: string;
    limit?: number;
  }): Promise<BlancheTrafficLedgerV1>;
  evaluateTrafficScope(rawUrl: string, method?: string): ScopeDecision;
  getModuleStates(): ModuleStateSnapshot[];
  getDocumentWorkbenchState(): DocumentWorkbenchState;
  getLatentFeatureWorkbenchState(): LatentFeatureWorkbenchState;
  getPermissionsState(): Promise<PermissionsState>;
  getProductVersion(): string;
  getRecentLogs(limit?: number): LogEntry[];
  saveLastExport(payload: BlancheExportV1): Promise<void>;
  updateDocumentWorkbenchState(state: DocumentWorkbenchState): Promise<void>;
  updateLatentFeatureWorkbenchState(state: LatentFeatureWorkbenchState): Promise<void>;
  updateModulePersistedState(moduleId: string, state: ModulePersistedState): Promise<void>;
  /** Lets one module trigger another module's action (e.g. auto-chaining a capture into an OSINT seed). */
  runModuleAction(
    moduleId: string,
    actionId: string,
    tabId?: number,
    input?: JsonObject
  ): Promise<ModuleActionResult>;
  /** Appends a normalized entry to the cross-module finding feed. */
  recordFinding(entry: FeedEntryInput): Promise<void>;
  /** Records a tester-facing, scored finding and may create an artifact-derived question. */
  recordIntelligenceFinding(entry: FindingInput): Promise<void>;
}

export interface SessionManager {
  begin(input: {
    moduleId: string;
    tabId: number;
    mode: CollectionMode;
    reloadTriggered: boolean;
    note?: string;
  }): CollectionSessionRecord;
  complete(sessionId: string, note?: string): CollectionSessionRecord | undefined;
  fail(sessionId: string, note?: string): CollectionSessionRecord | undefined;
  list(): CollectionSessionRecord[];
}

export interface Logger {
  debug(message: string, context?: JsonObject): void;
  info(message: string, context?: JsonObject): void;
  warn(message: string, context?: JsonObject): void;
  error(message: string, context?: JsonObject): void;
  child(segment: string): Logger;
}

export interface ModuleActionContext {
  descriptor: ModuleDescriptor;
  settings: Record<string, JsonValue>;
  logger: Logger;
  sessions: SessionManager;
  services: ModuleHostServices;
}

export interface ModuleBackgroundController {
  onHostStart?(): Promise<void>;
  onModuleEnabled?(): Promise<void>;
  onModuleDisabled?(): Promise<void>;
  runAction(request: ModuleActionRequest, context: ModuleActionContext): Promise<ModuleActionResult>;
}

export interface ModuleDefinition {
  descriptor: ModuleDescriptor;
  createBackgroundController(services: {
    logger: Logger;
    sessions: SessionManager;
    host: ModuleHostServices;
  }): ModuleBackgroundController;
}
