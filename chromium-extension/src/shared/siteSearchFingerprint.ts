import type {
  SearchSessionRecord,
  SearchTaskRecord,
  SearchTaskStatus
} from './searchExecution';
import type { NerdSearchProviderFingerprint } from './nerdSearch';

export type SiteSearchSignalAssessment =
  | 'results-observed'
  | 'no-results-observed'
  | 'mixed'
  | 'inconclusive';

export interface SiteSearchOutcomeCounts {
  tasks: number;
  results: number;
  resultTasks: number;
  noResultTasks: number;
  manualRequiredTasks: number;
  failedTasks: number;
  inProgressTasks: number;
}

export interface SiteSearchSignal {
  id: string;
  assessment: SiteSearchSignalAssessment;
  counts: SiteSearchOutcomeCounts;
}

export interface SiteSearchSurfaceIdentity {
  id: string;
  name: string;
  mode: 'get' | 'form' | 'template';
  method: 'get' | 'post' | 'dynamic';
  pageUrl: string;
  actionUrl: string;
  queryParam?: string;
  providerFingerprint?: NerdSearchProviderFingerprint;
}

export interface SiteSearchCoverage {
  observedTasks: number;
  terminalTasks: number;
  pendingTasks: number;
  coverageRate: number;
  completionRate: number;
}

export interface SiteSearchFingerprint {
  sessionId: string;
  target?: string;
  surface?: SiteSearchSurfaceIdentity;
  assessment: SiteSearchSignalAssessment;
  totals: SiteSearchOutcomeCounts;
  coverage: SiteSearchCoverage;
  categories: SiteSearchSignal[];
  operators: SiteSearchSignal[];
  truncated: boolean;
}

export const MAX_SITE_SEARCH_FINGERPRINT_TASKS = 500;

const MAX_RESULTS_PER_TASK = 10_000;
const MAX_TOTAL_RESULTS = 1_000_000;
const MAX_OPERATOR_IDS_PER_TASK = 50;
const MAX_SIGNALS = 250;
const MAX_ID_LENGTH = 240;
const MAX_NAME_LENGTH = 240;
const MAX_URL_LENGTH = 4096;

const IN_PROGRESS_STATUSES = new Set<SearchTaskStatus>([
  'queued',
  'throttled',
  'running',
  'parsing'
]);

/**
 * Reduces a completed or active NERD session to bounded behavior signals for the UI.
 * Query text and result records are deliberately excluded. Observations describe only
 * recorded outcomes; they do not identify or guess the search implementation behind a site.
 */
export function buildSiteSearchFingerprint(
  session: SearchSessionRecord | undefined
): SiteSearchFingerprint | undefined {
  if (!session || session.mode !== 'nerd') {
    return undefined;
  }

  const sourceTasks = Array.isArray(session.tasks) ? session.tasks : [];
  const tasks = sourceTasks.slice(0, MAX_SITE_SEARCH_FINGERPRINT_TASKS);
  const categoryCounts = new Map<string, MutableCounts>();
  const operatorCounts = new Map<string, MutableCounts>();
  const totals = createMutableCounts();
  let signalLimitReached = false;

  for (const task of tasks) {
    addTask(totals, task);

    const category = boundedString(task.category, MAX_ID_LENGTH);
    if (category) {
      const counts = getOrCreateSignal(categoryCounts, category);
      if (counts) addTask(counts, task);
      else signalLimitReached = true;
    }

    const operatorIds = Array.isArray(task.operatorIds)
      ? task.operatorIds.slice(0, MAX_OPERATOR_IDS_PER_TASK)
      : [];
    if (Array.isArray(task.operatorIds) && task.operatorIds.length > operatorIds.length) {
      signalLimitReached = true;
    }
    const uniqueOperatorIds = new Set<string>();
    for (const operatorIdValue of operatorIds) {
      const operatorId = boundedString(operatorIdValue, MAX_ID_LENGTH);
      if (!operatorId || uniqueOperatorIds.has(operatorId)) continue;
      uniqueOperatorIds.add(operatorId);
      const counts = getOrCreateSignal(operatorCounts, operatorId);
      if (counts) addTask(counts, task);
      else signalLimitReached = true;
    }
  }

  const finalTotals = finalizeCounts(totals);
  const observedTasks = finalTotals.resultTasks + finalTotals.noResultTasks;
  const terminalTasks =
    observedTasks + finalTotals.manualRequiredTasks + finalTotals.failedTasks;

  return {
    sessionId: boundedString(session.id, MAX_ID_LENGTH) ?? '',
    target: boundedString(session.target, MAX_URL_LENGTH),
    surface: findSurface(tasks),
    assessment: assess(finalTotals),
    totals: finalTotals,
    coverage: {
      observedTasks,
      terminalTasks,
      pendingTasks: finalTotals.inProgressTasks,
      coverageRate: ratio(observedTasks, finalTotals.tasks),
      completionRate: ratio(terminalTasks, finalTotals.tasks)
    },
    categories: finalizeSignals(categoryCounts),
    operators: finalizeSignals(operatorCounts),
    truncated:
      sourceTasks.length > tasks.length ||
      signalLimitReached
  };
}

interface MutableCounts extends SiteSearchOutcomeCounts {}

function createMutableCounts(): MutableCounts {
  return {
    tasks: 0,
    results: 0,
    resultTasks: 0,
    noResultTasks: 0,
    manualRequiredTasks: 0,
    failedTasks: 0,
    inProgressTasks: 0
  };
}

function addTask(counts: MutableCounts, task: SearchTaskRecord): void {
  counts.tasks += 1;
  counts.results = Math.min(
    MAX_TOTAL_RESULTS,
    counts.results + boundedResultCount(task.resultCount)
  );
  switch (task.status) {
    case 'completed-results':
      counts.resultTasks += 1;
      break;
    case 'completed-no-results':
      counts.noResultTasks += 1;
      break;
    case 'manual-required':
      counts.manualRequiredTasks += 1;
      break;
    case 'failed':
      counts.failedTasks += 1;
      break;
    default:
      if (IN_PROGRESS_STATUSES.has(task.status)) {
        counts.inProgressTasks += 1;
      } else {
        // Unknown runtime values cannot support a behavior conclusion.
        counts.inProgressTasks += 1;
      }
  }
}

function getOrCreateSignal(
  map: Map<string, MutableCounts>,
  id: string
): MutableCounts | undefined {
  const existing = map.get(id);
  if (existing) return existing;
  if (map.size >= MAX_SIGNALS) return undefined;
  const counts = createMutableCounts();
  map.set(id, counts);
  return counts;
}

function finalizeSignals(map: Map<string, MutableCounts>): SiteSearchSignal[] {
  return [...map.entries()]
    .sort(([left], [right]) => compareText(left, right))
    .map(([id, mutableCounts]) => {
      const counts = finalizeCounts(mutableCounts);
      return { id, assessment: assess(counts), counts };
    });
}

function finalizeCounts(counts: MutableCounts): SiteSearchOutcomeCounts {
  return { ...counts };
}

function assess(counts: SiteSearchOutcomeCounts): SiteSearchSignalAssessment {
  if (counts.resultTasks > 0 && counts.noResultTasks > 0) return 'mixed';
  if (counts.resultTasks > 0) return 'results-observed';
  if (counts.noResultTasks > 0) return 'no-results-observed';
  return 'inconclusive';
}

function findSurface(tasks: readonly SearchTaskRecord[]): SiteSearchSurfaceIdentity | undefined {
  for (const task of tasks) {
    const surface = task.nerdSurface;
    if (!surface) continue;
    const id = boundedString(surface.id, MAX_ID_LENGTH);
    const name = boundedString(surface.name, MAX_NAME_LENGTH);
    const pageUrl = boundedString(surface.pageUrl, MAX_URL_LENGTH);
    const actionUrl = boundedString(surface.actionUrl, MAX_URL_LENGTH);
    if (!id || !name || !pageUrl || !actionUrl) continue;
    if (
      surface.mode !== 'get' &&
      surface.mode !== 'form' &&
      surface.mode !== 'template'
    ) continue;
    if (
      surface.method !== 'get' &&
      surface.method !== 'post' &&
      surface.method !== 'dynamic'
    ) continue;
    return {
      id,
      name,
      mode: surface.mode,
      method: surface.method,
      pageUrl,
      actionUrl,
      queryParam: boundedString(surface.queryParam, MAX_ID_LENGTH),
      providerFingerprint: normalizeProviderFingerprint(surface.providerFingerprint)
    };
  }
  return undefined;
}

function normalizeProviderFingerprint(value: unknown): NerdSearchProviderFingerprint | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
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
  const provider = providers.includes(record.provider as NerdSearchProviderFingerprint['provider'])
    ? (record.provider as NerdSearchProviderFingerprint['provider'])
    : undefined;
  const label = boundedString(record.label, 120);
  const confidence =
    record.confidence === 'high' || record.confidence === 'medium' || record.confidence === 'low'
      ? record.confidence
      : undefined;
  if (!provider || !label || !confidence) return undefined;
  const evidence = Array.isArray(record.evidence)
    ? record.evidence
        .map((entry) => boundedString(entry, 180))
        .filter((entry): entry is string => Boolean(entry))
        .slice(0, 6)
    : [];
  return { provider, label, confidence, evidence };
}

function boundedResultCount(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 0;
  return Math.min(MAX_RESULTS_PER_TASK, Math.max(0, Math.floor(value)));
}

function boundedString(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim();
  return normalized ? normalized.slice(0, maxLength) : undefined;
}

function ratio(numerator: number, denominator: number): number {
  if (denominator <= 0) return 0;
  return Math.round((numerator / denominator) * 10_000) / 10_000;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
