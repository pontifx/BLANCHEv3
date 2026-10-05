import type { SearchEngineId, SearchQueryDraft } from './searchWorkbench';
import type {
  NerdFormSubmission,
  NerdSearchProviderFingerprint,
  NerdSearchSurface,
  NerdSearchSurfaceMode
} from './nerdSearch';

export type SearchExecutionEngineId = SearchEngineId | 'nerd';

export type SearchExecutionMode =
  | 'classic'
  | 'default-recipe'
  | 'dork-suite'
  | 'nerd';

/**
 * A deliberately reduced copy of a user-captured NERD surface. Runtime-only values such as
 * hidden form parameters and DOM selectors live outside this reporting snapshot.
 */
export interface NerdSearchSurfaceSnapshot {
  id: string;
  name: string;
  mode: NerdSearchSurfaceMode;
  pageUrl: string;
  actionUrl: string;
  method: NerdSearchSurface['method'];
  queryParam?: string;
  providerFingerprint?: NerdSearchProviderFingerprint;
}

export type SearchTaskStatus =
  | 'queued'
  | 'throttled'
  | 'running'
  | 'parsing'
  | 'completed-results'
  | 'completed-no-results'
  | 'manual-required'
  | 'failed';

export type SearchCategory =
  | 'public-footprint'
  | 'indexed-files'
  | 'archives'
  | 'javascript'
  | 'libraries'
  | 'extracted-urls'
  | 'infrastructure'
  | 'client-features'
  | 'custom';

export interface SearchResultRecord {
  id: string;
  url: string;
  title?: string;
  snippet?: string;
  engineId: SearchExecutionEngineId;
  query: string;
  rank: number;
  firstSeenAt: string;
}

export interface SearchTaskRecord {
  id: string;
  sessionId: string;
  category: SearchCategory;
  engineId: SearchExecutionEngineId;
  engineName: string;
  mode?: SearchExecutionMode;
  target?: string;
  targets?: string[];
  query: string;
  searchUrl: string;
  catalogReviewedAt?: string;
  dorkId?: string;
  dorkTitle?: string;
  operatorIds?: string[];
  dialect?: string;
  warnings?: string[];
  nerdSurface?: NerdSearchSurfaceSnapshot;
  nerdFormSubmission?: NerdFormSubmission;
  status: SearchTaskStatus;
  tabId?: number;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  resultCount: number;
  results: SearchResultRecord[];
  manualReason?: string;
  error?: string;
}

export interface SearchSessionRecord {
  id: string;
  label: string;
  createdAt: string;
  updatedAt: string;
  mode?: SearchExecutionMode;
  target?: string;
  targets?: string[];
  catalogReviewedAt?: string;
  warnings?: string[];
  draft: SearchQueryDraft;
  automatic: boolean;
  tasks: SearchTaskRecord[];
}

export interface SearchExecutionSettings {
  sameEngineLaunchDelayMs: number;
  sameQueryRepeatCooldownMs: number;
  maxConcurrentTasks: number;
  libraryProbeConcurrency: number;
  libraryProbeDelayMs: number;
  closeCompletedSearchTabs: boolean;
  maxResultsPerTask: number;
}

export interface SearchExecutionState {
  settings: SearchExecutionSettings;
  sessions: SearchSessionRecord[];
  activeSessionId?: string;
}

export const DEFAULT_SEARCH_EXECUTION_SETTINGS: SearchExecutionSettings = {
  sameEngineLaunchDelayMs: 300,
  sameQueryRepeatCooldownMs: 300,
  maxConcurrentTasks: 1,
  libraryProbeConcurrency: 1,
  libraryProbeDelayMs: 750,
  closeCompletedSearchTabs: true,
  maxResultsPerTask: 100
};

export function createDefaultSearchExecutionState(): SearchExecutionState {
  return {
    settings: { ...DEFAULT_SEARCH_EXECUTION_SETTINGS },
    sessions: []
  };
}

export function createNerdSearchSurfaceSnapshot(
  surface: NerdSearchSurface | NerdSearchSurfaceSnapshot
): NerdSearchSurfaceSnapshot {
  const snapshot = normalizeNerdSurfaceSnapshot(surface);
  if (!snapshot) {
    throw new Error('The Site Search surface could not be reduced to a safe execution trace.');
  }
  return snapshot;
}

export function sanitizeNerdFormSubmission(
  submission: NerdFormSubmission
): NerdFormSubmission {
  const sanitized = normalizeNerdFormSubmission(submission);
  if (!sanitized) {
    throw new Error('The Site Search form submission trace is invalid.');
  }
  return sanitized;
}

export function normalizeSearchExecutionState(value: unknown): SearchExecutionState {
  const fallback = createDefaultSearchExecutionState();
  if (!isRecord(value)) {
    return fallback;
  }

  const rawSettings = isRecord(value.settings) ? value.settings : {};
  const sessions = Array.isArray(value.sessions)
    ? value.sessions.map(normalizeSession).filter(isDefined).slice(0, 30)
    : [];
  return {
    settings: {
      sameEngineLaunchDelayMs: clampNumber(
        rawSettings.sameEngineLaunchDelayMs,
        DEFAULT_SEARCH_EXECUTION_SETTINGS.sameEngineLaunchDelayMs,
        0,
        60000
      ),
      sameQueryRepeatCooldownMs: clampNumber(
        rawSettings.sameQueryRepeatCooldownMs,
        DEFAULT_SEARCH_EXECUTION_SETTINGS.sameQueryRepeatCooldownMs,
        0,
        86400000
      ),
      maxConcurrentTasks: clampNumber(
        rawSettings.maxConcurrentTasks,
        DEFAULT_SEARCH_EXECUTION_SETTINGS.maxConcurrentTasks,
        1,
        8
      ),
      libraryProbeConcurrency: clampNumber(
        rawSettings.libraryProbeConcurrency,
        DEFAULT_SEARCH_EXECUTION_SETTINGS.libraryProbeConcurrency,
        1,
        4
      ),
      libraryProbeDelayMs: clampNumber(
        rawSettings.libraryProbeDelayMs,
        DEFAULT_SEARCH_EXECUTION_SETTINGS.libraryProbeDelayMs,
        100,
        60000
      ),
      closeCompletedSearchTabs:
        rawSettings.closeCompletedSearchTabs !== false,
      maxResultsPerTask: clampNumber(
        rawSettings.maxResultsPerTask,
        DEFAULT_SEARCH_EXECUTION_SETTINGS.maxResultsPerTask,
        1,
        500
      )
    },
    sessions,
    activeSessionId:
      typeof value.activeSessionId === 'string' &&
      sessions.some((session) => session.id === value.activeSessionId)
        ? value.activeSessionId
        : sessions[0]?.id
  };
}

function normalizeSession(value: unknown): SearchSessionRecord | undefined {
  if (
    !isRecord(value) ||
    typeof value.id !== 'string' ||
    typeof value.label !== 'string' ||
    typeof value.createdAt !== 'string' ||
    typeof value.updatedAt !== 'string' ||
    !isRecord(value.draft)
  ) {
    return undefined;
  }
  const draft = value.draft as unknown as SearchQueryDraft;
  const automatic = value.automatic === true;
  const target = typeof value.target === 'string' ? value.target : undefined;
  const targets = normalizeStringArray(value.targets, 100);
  return {
    id: value.id,
    label: value.label,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    mode: normalizeExecutionMode(value.mode) ?? (automatic ? 'default-recipe' : 'classic'),
    target,
    targets: targets.length > 0 ? targets : target ? [target] : undefined,
    catalogReviewedAt: normalizeOptionalString(value.catalogReviewedAt, 80),
    warnings: normalizeOptionalStringArray(value.warnings, 100, 2000),
    draft,
    automatic,
    tasks: Array.isArray(value.tasks)
      ? value.tasks.map(normalizeTask).filter(isDefined)
      : []
  };
}

function normalizeTask(value: unknown): SearchTaskRecord | undefined {
  if (
    !isRecord(value) ||
    typeof value.id !== 'string' ||
    typeof value.sessionId !== 'string' ||
    typeof value.engineId !== 'string' ||
    typeof value.engineName !== 'string' ||
    typeof value.query !== 'string' ||
    typeof value.searchUrl !== 'string' ||
    typeof value.createdAt !== 'string'
  ) {
    return undefined;
  }
  const status = normalizeTaskStatus(value.status);
  const target = typeof value.target === 'string' ? value.target : undefined;
  const targets = normalizeStringArray(value.targets, 100);
  return {
    id: value.id,
    sessionId: value.sessionId,
    category: normalizeCategory(value.category),
    engineId: value.engineId as SearchExecutionEngineId,
    engineName: value.engineName,
    mode: normalizeExecutionMode(value.mode),
    target,
    targets: targets.length > 0 ? targets : target ? [target] : undefined,
    query: value.query,
    searchUrl: value.searchUrl,
    catalogReviewedAt: normalizeOptionalString(value.catalogReviewedAt, 80),
    dorkId: normalizeOptionalString(value.dorkId, 240),
    dorkTitle:
      normalizeOptionalString(value.dorkTitle, 240) ??
      normalizeOptionalString(value.title, 240),
    operatorIds: normalizeOptionalStringArray(value.operatorIds, 100, 240),
    dialect: normalizeOptionalString(value.dialect, 120),
    warnings: normalizeOptionalStringArray(value.warnings, 100, 2000),
    nerdSurface: normalizeNerdSurfaceSnapshot(value.nerdSurface),
    nerdFormSubmission: normalizeNerdFormSubmission(value.nerdFormSubmission),
    status,
    tabId: typeof value.tabId === 'number' ? value.tabId : undefined,
    createdAt: value.createdAt,
    startedAt: typeof value.startedAt === 'string' ? value.startedAt : undefined,
    finishedAt: typeof value.finishedAt === 'string' ? value.finishedAt : undefined,
    resultCount: typeof value.resultCount === 'number' ? value.resultCount : 0,
    results: Array.isArray(value.results)
      ? value.results.map(normalizeResult).filter(isDefined)
      : [],
    manualReason: typeof value.manualReason === 'string' ? value.manualReason : undefined,
    error: typeof value.error === 'string' ? value.error : undefined
  };
}

function normalizeResult(value: unknown): SearchResultRecord | undefined {
  if (
    !isRecord(value) ||
    typeof value.id !== 'string' ||
    typeof value.url !== 'string' ||
    typeof value.engineId !== 'string' ||
    typeof value.query !== 'string' ||
    typeof value.firstSeenAt !== 'string'
  ) {
    return undefined;
  }
  return {
    id: value.id,
    url: value.url,
    title: typeof value.title === 'string' ? value.title : undefined,
    snippet: typeof value.snippet === 'string' ? value.snippet : undefined,
    engineId: value.engineId as SearchExecutionEngineId,
    query: value.query,
    rank: typeof value.rank === 'number' ? value.rank : 0,
    firstSeenAt: value.firstSeenAt
  };
}

function normalizeTaskStatus(value: unknown): SearchTaskStatus {
  if (
    value === 'queued' ||
    value === 'throttled' ||
    value === 'running' ||
    value === 'parsing' ||
    value === 'completed-results' ||
    value === 'completed-no-results' ||
    value === 'manual-required' ||
    value === 'failed'
  ) {
    return value;
  }
  return 'queued';
}

function normalizeExecutionMode(value: unknown): SearchExecutionMode | undefined {
  return value === 'classic' ||
    value === 'default-recipe' ||
    value === 'dork-suite' ||
    value === 'nerd'
    ? value
    : undefined;
}

function normalizeNerdSurfaceSnapshot(value: unknown): NerdSearchSurfaceSnapshot | undefined {
  if (!isRecord(value)) return undefined;
  const id = normalizeOptionalString(value.id, 240);
  const name = normalizeOptionalString(value.name, 240);
  const mode = value.mode === 'get' || value.mode === 'form' || value.mode === 'template'
    ? value.mode
    : undefined;
  const pageUrl = sanitizeTraceUrl(value.pageUrl);
  const actionUrl = sanitizeTraceUrl(value.actionUrl);
  const method = value.method === 'post' || value.method === 'dynamic' ? value.method : 'get';
  if (!id || !name || !mode || !pageUrl || !actionUrl) return undefined;
  return {
    id,
    name,
    mode,
    pageUrl,
    actionUrl,
    method,
    queryParam: normalizeOptionalString(value.queryParam, 160),
    providerFingerprint: normalizeNerdProviderFingerprint(value.providerFingerprint)
  };
}

function normalizeNerdProviderFingerprint(
  value: unknown
): NerdSearchProviderFingerprint | undefined {
  if (!isRecord(value)) return undefined;
  const providers: NerdSearchProviderFingerprint['provider'][] = [
    'google-programmable-search',
    'algolia',
    'elastic-app-search',
    'azure-search',
    'solr',
    'typesense',
    'meilisearch',
    'swiftype',
    'custom'
  ];
  const provider = providers.includes(value.provider as NerdSearchProviderFingerprint['provider'])
    ? (value.provider as NerdSearchProviderFingerprint['provider'])
    : undefined;
  const label = normalizeOptionalString(value.label, 120);
  const confidence =
    value.confidence === 'high' || value.confidence === 'medium' || value.confidence === 'low'
      ? value.confidence
      : undefined;
  if (!provider || !label || !confidence) return undefined;
  return {
    provider,
    label,
    confidence,
    evidence: normalizeStringArray(value.evidence, 6, 180)
  };
}

function normalizeNerdFormSubmission(value: unknown): NerdFormSubmission | undefined {
  if (!isRecord(value)) return undefined;
  const surfaceId = normalizeOptionalString(value.surfaceId, 240);
  const surfaceName = normalizeOptionalString(value.surfaceName, 240);
  const pageUrl = sanitizeTraceUrl(value.pageUrl);
  const inputSelector = normalizeOptionalString(value.inputSelector, 1024);
  if (!surfaceId || !surfaceName || !pageUrl || !inputSelector) return undefined;
  return {
    surfaceId,
    surfaceName,
    pageUrl,
    inputSelector,
    formSelector: normalizeOptionalString(value.formSelector, 1024),
    submitSelector: normalizeOptionalString(value.submitSelector, 1024)
  };
}

function sanitizeTraceUrl(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return undefined;
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.toString();
  } catch {
    return undefined;
  }
}

function normalizeOptionalString(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().slice(0, maxLength);
  return normalized || undefined;
}

function normalizeOptionalStringArray(
  value: unknown,
  maxEntries: number,
  maxEntryLength: number
): string[] | undefined {
  const normalized = normalizeStringArray(value, maxEntries, maxEntryLength);
  return normalized.length > 0 ? normalized : undefined;
}

function normalizeStringArray(
  value: unknown,
  maxEntries: number,
  maxEntryLength = 500
): string[] {
  if (!Array.isArray(value)) return [];
  const output: string[] = [];
  const seen = new Set<string>();
  for (const entry of value) {
    const normalized = normalizeOptionalString(entry, maxEntryLength);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    output.push(normalized);
    if (output.length >= maxEntries) break;
  }
  return output;
}

function normalizeCategory(value: unknown): SearchCategory {
  if (
    value === 'public-footprint' ||
    value === 'indexed-files' ||
    value === 'archives' ||
    value === 'javascript' ||
    value === 'libraries' ||
    value === 'extracted-urls' ||
    value === 'infrastructure' ||
    value === 'client-features'
  ) {
    return value;
  }
  return 'custom';
}

function clampNumber(value: unknown, fallback: number, min: number, max: number): number {
  const numeric = typeof value === 'number' && Number.isFinite(value) ? value : fallback;
  return Math.min(max, Math.max(min, Math.floor(numeric)));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isDefined<T>(value: T | undefined): value is T {
  return value !== undefined;
}
