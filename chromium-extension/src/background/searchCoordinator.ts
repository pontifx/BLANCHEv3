import {
  buildSearchLaunchPlans,
  normalizeSearchDraft,
  parseTargets,
  type SearchEngineId,
  type SearchLaunchPlan,
  type SearchQueryDraft
} from '../shared/searchWorkbench';
import {
  createNerdSearchSurfaceSnapshot,
  normalizeSearchExecutionState,
  sanitizeNerdFormSubmission,
  type SearchCategory,
  type SearchExecutionEngineId,
  type SearchExecutionMode,
  type SearchExecutionSettings,
  type SearchExecutionState,
  type NerdSearchSurfaceSnapshot,
  type SearchResultRecord,
  type SearchSessionRecord,
  type SearchTaskRecord
} from '../shared/searchExecution';
import {
  submitNerdSearchForm,
  type NerdFormSubmission,
  type NerdSearchSurface
} from '../shared/nerdSearch';
import type { FindingInput } from '../shared/findingsWorkbench';

interface RenderedSearchInspection {
  outcome: 'results' | 'empty' | 'manual';
  reason?: string;
  results: Array<{ url: string; title?: string; snippet?: string }>;
}

export interface GeneratedSearchTaskInput {
  category: SearchCategory;
  engineId: SearchExecutionEngineId;
  engineName: string;
  target?: string;
  targets?: string[];
  query: string;
  searchUrl: string;
  mode?: SearchExecutionMode;
  catalogReviewedAt?: string;
  dorkId?: string;
  /** A generated suite entry's user-facing title. Persisted as `dorkTitle`. */
  title?: string;
  dorkTitle?: string;
  operatorIds?: string[];
  dialect?: string;
  warnings?: string[];
  nerdSurface?: NerdSearchSurface | NerdSearchSurfaceSnapshot;
  nerdFormSubmission?: NerdFormSubmission;
  /** Backward-compatible caller alias; persisted canonically as `nerdFormSubmission`. */
  nerdSubmission?: NerdFormSubmission;
}

export interface GeneratedSearchStartInput {
  draft: SearchQueryDraft;
  mode: Extract<SearchExecutionMode, 'dork-suite' | 'nerd'>;
  tasks: GeneratedSearchTaskInput[];
  label?: string;
  targets?: string[];
  catalogReviewedAt?: string;
  warnings?: string[];
}

/** Alias kept descriptive for callers that import the coordinator's start argument by name. */
export type StartGeneratedSearchSuiteInput = GeneratedSearchStartInput;

export class SearchCoordinator {
  private state: SearchExecutionState;
  private readonly activeSessionIds = new Set<string>();
  private readonly lastEngineStart = new Map<SearchExecutionEngineId, number>();
  private readonly lastQueryStart = new Map<string, number>();
  private readonly engineStartGateTails = new Map<SearchExecutionEngineId, Promise<void>>();

  constructor(
    initialState: SearchExecutionState,
    private readonly onChange: (state: SearchExecutionState) => Promise<void>,
    private readonly recordFinding: (input: FindingInput) => Promise<void>,
    private readonly logError: (message: string, context?: Record<string, unknown>) => void
  ) {
    const normalized = normalizeSearchExecutionState(initialState);
    this.state = {
      ...normalized,
      sessions: normalized.sessions.map((session) => ({
        ...session,
        tasks: session.tasks.map((task) =>
          task.status === 'running' || task.status === 'parsing' || task.status === 'throttled'
            ? { ...task, status: 'queued' as const }
            : task
        )
      }))
    };
    for (const session of this.state.sessions) {
      for (const task of session.tasks) {
        if (!task.startedAt) continue;
        const started = Date.parse(task.startedAt);
        if (!Number.isFinite(started)) continue;
        this.lastEngineStart.set(task.engineId, Math.max(this.lastEngineStart.get(task.engineId) ?? 0, started));
        this.lastQueryStart.set(queryKey(task), Math.max(this.lastQueryStart.get(queryKey(task)) ?? 0, started));
      }
    }
  }

  snapshot(): SearchExecutionState {
    return this.state;
  }

  resumePending(): void {
    for (const session of this.state.sessions) {
      if (session.tasks.some((task) => task.status === 'queued' || task.status === 'throttled')) {
        void this.processSession(session.id);
      }
    }
  }

  async updateSettings(settings: Partial<SearchExecutionSettings>): Promise<void> {
    this.state = normalizeSearchExecutionState({
      ...this.state,
      settings: { ...this.state.settings, ...settings }
    });
    await this.commit();
  }

  async start(draftInput: SearchQueryDraft, useDefaultRecipe: boolean): Promise<SearchSessionRecord> {
    const draft = normalizeSearchDraft(draftInput);
    const categorizedPlans = useDefaultRecipe
      ? buildDefaultRecipe(draft)
      : buildSearchLaunchPlans(draft).map((plan) => ({ category: 'custom' as const, plan }));
    if (categorizedPlans.length === 0) {
      throw new Error('Add a target or query before running the search.');
    }

    const now = new Date().toISOString();
    const sessionId = createId('search');
    const targets = parseTargets(draft.targetsText);
    const target = targets[0];
    const mode: SearchExecutionMode = useDefaultRecipe ? 'default-recipe' : 'classic';
    const session: SearchSessionRecord = {
      id: sessionId,
      label: draft.name.trim() || (useDefaultRecipe ? `Advanced sweep: ${target ?? 'query'}` : `Search: ${target ?? 'query'}`),
      createdAt: now,
      updatedAt: now,
      mode,
      target,
      targets,
      draft,
      automatic: useDefaultRecipe,
      tasks: categorizedPlans.map(({ category, plan }) => ({
        id: createId('task'),
        sessionId,
        category,
        engineId: plan.engine.id,
        engineName: plan.engine.name,
        mode,
        target: plan.target ?? target,
        targets: plan.target
          ? [plan.target]
          : category === 'archives' && target
            ? [target]
            : targets,
        query: plan.query,
        searchUrl: plan.url,
        status: 'queued',
        createdAt: now,
        resultCount: 0,
        results: []
      }))
    };
    this.state = {
      ...this.state,
      activeSessionId: sessionId,
      sessions: [session, ...this.state.sessions].slice(0, 30)
    };
    await this.commit();
    void this.processSession(sessionId);
    return session;
  }

  /**
   * Starts a pre-generated dork or NERD suite without rebuilding its queries. The complete task
   * trace is committed first so a service-worker suspension cannot lose the generated suite.
   */
  async startGeneratedSuite(input: GeneratedSearchStartInput): Promise<SearchSessionRecord> {
    if (input.mode !== 'dork-suite' && input.mode !== 'nerd') {
      throw new Error('Generated searches must use dork-suite or nerd mode.');
    }
    if (!Array.isArray(input.tasks) || input.tasks.length === 0) {
      throw new Error('Generate at least one search task before starting the suite.');
    }

    const draft = normalizeSearchDraft(input.draft);
    const draftTargets = parseTargets(draft.targetsText);
    const inputTargets = uniqueStrings(input.targets ?? []);
    const generatedTargets = uniqueStrings(
      input.tasks.flatMap((task) => [
        ...(task.targets ?? []),
        ...(task.target ? [task.target] : [])
      ])
    );
    const targets = inputTargets.length > 0
      ? inputTargets
      : draftTargets.length > 0
        ? draftTargets
        : generatedTargets;
    const target = targets[0];
    const now = new Date().toISOString();
    const sessionId = createId('search');
    const tasks = input.tasks.map((task, index): SearchTaskRecord => {
      validateGeneratedTask(task, index);
      const nerdFormSubmission = task.nerdFormSubmission ?? task.nerdSubmission;
      const taskTargets = uniqueStrings(
        task.targets && task.targets.length > 0
          ? task.targets
          : task.target
            ? [task.target]
            : targets
      );
      const taskTarget = task.target ?? taskTargets[0] ?? target;
      return {
        id: createId('task'),
        sessionId,
        category: task.category,
        engineId: task.engineId,
        engineName: task.engineName,
        mode: task.mode ?? input.mode,
        target: taskTarget,
        targets: taskTargets.length > 0 ? taskTargets : undefined,
        query: task.query,
        searchUrl: task.searchUrl,
        catalogReviewedAt: task.catalogReviewedAt ?? input.catalogReviewedAt,
        dorkId: task.dorkId,
        dorkTitle: task.dorkTitle ?? task.title,
        operatorIds: copyStrings(task.operatorIds),
        dialect: task.dialect,
        warnings: copyStrings(task.warnings),
        nerdSurface: task.nerdSurface
          ? createNerdSearchSurfaceSnapshot(task.nerdSurface)
          : undefined,
        nerdFormSubmission: nerdFormSubmission
          ? sanitizeNerdFormSubmission(nerdFormSubmission)
          : undefined,
        status: 'queued',
        createdAt: now,
        resultCount: 0,
        results: []
      };
    });

    const session: SearchSessionRecord = {
      id: sessionId,
      label:
        input.label?.trim() ||
        draft.name.trim() ||
        (input.mode === 'nerd' ? `NERD suite: ${target ?? 'query'}` : `Dork suite: ${target ?? 'query'}`),
      createdAt: now,
      updatedAt: now,
      mode: input.mode,
      target,
      targets: targets.length > 0 ? targets : undefined,
      catalogReviewedAt: input.catalogReviewedAt,
      warnings: copyStrings(input.warnings),
      draft,
      automatic: true,
      tasks
    };
    this.state = {
      ...this.state,
      activeSessionId: sessionId,
      sessions: [session, ...this.state.sessions].slice(0, 30)
    };
    await this.commit();
    void this.processSession(sessionId);
    return session;
  }

  private async processSession(sessionId: string): Promise<void> {
    if (this.activeSessionIds.has(sessionId)) return;
    this.activeSessionIds.add(sessionId);
    try {
      const session = this.findSession(sessionId);
      if (!session) return;
      const tasks = session.tasks.filter((task) => task.status === 'queued' || task.status === 'throttled');
      let cursor = 0;
      const workerCount = Math.min(this.state.settings.maxConcurrentTasks, Math.max(1, tasks.length));
      await Promise.all(
        Array.from({ length: workerCount }, async () => {
          while (cursor < tasks.length) {
            const task = tasks[cursor++];
            if (task) await this.processTask(task.id);
          }
        })
      );
    } finally {
      this.activeSessionIds.delete(sessionId);
    }
  }

  private async processTask(taskId: string): Promise<void> {
    const task = this.findTask(taskId);
    if (!task) return;
    try {
      await this.waitForStartSlot(taskId, task);

      const startedAt = new Date().toISOString();
      await this.patchTask(taskId, { status: 'running', startedAt });
      const session = this.findSession(task.sessionId);
      const existingTab = typeof task.tabId === 'number'
        ? await chrome.tabs.get(task.tabId).catch(() => undefined)
        : undefined;
      let tab = existingTab ?? await chrome.tabs.create({
        url: task.searchUrl,
        active: session?.draft.openInBackground === false
      });
      if (existingTab && task.nerdFormSubmission && existingTab.url !== task.searchUrl) {
        if (typeof tab.id !== 'number') throw new Error('Search tab did not receive an id.');
        const updatedTab = await chrome.tabs.update(tab.id, { url: task.searchUrl });
        if (!updatedTab) throw new Error('The NERD search tab could not be restored.');
        tab = updatedTab;
      }
      if (typeof tab.id !== 'number') throw new Error('Search tab did not receive an id.');
      const tabId = tab.id;
      await this.patchTask(taskId, { tabId });
      await waitForTab(tabId, 20000);
      if (task.nerdFormSubmission) {
        const beforeSubmission = await chrome.tabs.get(tabId);
        const watcher = watchForTabNavigationOrSettling(
          tabId,
          beforeSubmission.url,
          20000
        );
        try {
          const formExecution = await chrome.scripting.executeScript({
            target: { tabId },
            func: submitNerdSearchForm,
            args: [task.nerdFormSubmission, task.query]
          });
          const submission = formExecution[0]?.result as
            | { submitted: boolean; reason?: string }
            | undefined;
          if (!submission?.submitted) {
            throw new Error(
              submission?.reason ?? 'The captured NERD search form could not be submitted.'
            );
          }
          await watcher.promise;
        } catch (error) {
          watcher.cancel();
          throw error;
        }
      }
      await wait(task.category === 'libraries' ? this.state.settings.libraryProbeDelayMs : 650);
      await this.patchTask(taskId, { status: 'parsing' });

      const execution = await chrome.scripting.executeScript({
        target: { tabId },
        func: inspectRenderedSearchPage,
        args: [this.state.settings.maxResultsPerTask, task.engineId === 'nerd']
      });
      const inspection = execution[0]?.result as RenderedSearchInspection | undefined;
      if (!inspection) throw new Error('The rendered search page returned no readable state.');

      if (inspection.outcome === 'manual') {
        await this.patchTask(taskId, {
          status: 'manual-required',
          manualReason: inspection.reason ?? 'The engine requested human verification.',
          finishedAt: new Date().toISOString()
        });
        await this.recordFinding({
          kind: 'diagnostic',
          score: 35,
          title: `${task.engineName} needs a manual search`,
          summary: inspection.reason ?? 'Anti-automation interrupted this search; the exact query is ready to copy.',
          host: task.target,
          evidence: [{ label: 'Copyable query', detail: task.query, url: task.searchUrl }]
        });
        return;
      }

      const results = normalizeResults(inspection.results, task);
      const status = results.length > 0 ? 'completed-results' : 'completed-no-results';
      await this.patchTask(taskId, {
        status,
        results,
        resultCount: results.length,
        finishedAt: new Date().toISOString()
      });
      if (results.length > 0) await this.recordSearchFinding(task, results);
      if (this.state.settings.closeCompletedSearchTabs) await chrome.tabs.remove(tabId).catch(() => undefined);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logError('Search task failed', { taskId, error: message });
      await this.patchTask(taskId, { status: 'failed', error: message, finishedAt: new Date().toISOString() });
      await this.recordFinding({
        kind: 'diagnostic',
        score: 30,
        title: 'A search task failed',
        summary: message,
        host: task.target,
        evidence: [{ label: `${task.engineName} query`, detail: task.query, url: task.searchUrl }]
      });
    }
  }

  private requiredDelay(task: SearchTaskRecord): number {
    const now = Date.now();
    const engineWait = (this.lastEngineStart.get(task.engineId) ?? 0) + this.state.settings.sameEngineLaunchDelayMs - now;
    const queryWait = (this.lastQueryStart.get(queryKey(task)) ?? 0) + this.state.settings.sameQueryRepeatCooldownMs - now;
    const libraryWait = task.category === 'libraries'
      ? (this.lastEngineStart.get(task.engineId) ?? 0) + this.state.settings.libraryProbeDelayMs - now
      : 0;
    return Math.max(0, engineWait, queryWait, libraryWait);
  }

  /**
   * Serializes only the launch boundary for one engine. Processing and result parsing can still
   * run concurrently, but two workers cannot calculate the same stale delay and launch together.
   */
  private async waitForStartSlot(taskId: string, task: SearchTaskRecord): Promise<void> {
    const previousTail = this.engineStartGateTails.get(task.engineId) ?? Promise.resolve();
    let release!: () => void;
    const ownGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const currentTail = previousTail.catch(() => undefined).then(() => ownGate);
    this.engineStartGateTails.set(task.engineId, currentTail);

    await previousTail.catch(() => undefined);
    try {
      const delay = this.requiredDelay(task);
      if (delay > 0) {
        await this.patchTask(taskId, { status: 'throttled' });
        await wait(delay);
      }
      const started = Date.now();
      this.lastEngineStart.set(task.engineId, started);
      this.lastQueryStart.set(queryKey(task), started);
    } finally {
      release();
      if (this.engineStartGateTails.get(task.engineId) === currentTail) {
        this.engineStartGateTails.delete(task.engineId);
      }
    }
  }

  private async recordSearchFinding(task: SearchTaskRecord, results: SearchResultRecord[]): Promise<void> {
    const scores: Partial<Record<SearchCategory, number>> = {
      'libraries': 82,
      'client-features': 86,
      'archives': 78,
      'indexed-files': 70,
      'extracted-urls': 72,
      'infrastructure': 62,
      'public-footprint': 48,
      'javascript': 68,
      'custom': 45
    };
    const score = scores[task.category] ?? 45;
    const label = task.category.replaceAll('-', ' ');
    await this.recordFinding({
      kind: task.category === 'libraries' ? 'library' : task.category === 'archives' ? 'archive-drift' : task.category === 'client-features' ? 'client-feature' : 'search-result',
      score,
      title: `${results.length} ${label} result${results.length === 1 ? '' : 's'} found`,
      summary: `${task.engineName} returned indexed evidence for ${task.target ?? 'the current query'}.`,
      host: task.target,
      evidence: results.slice(0, 12).map((result) => ({ label: result.title || result.url, detail: result.snippet || result.url, url: result.url })),
      question: score >= 75
        ? {
            prompt: task.category === 'libraries'
              ? 'This search found library/version evidence. Inspect it for an old or vulnerable dependency?'
              : task.category === 'client-features'
                ? 'Client bundles expose possible feature switches. Review the evidence before attempting an in-scope activation?'
                : 'The archived footprint differs enough to inspect alongside the current site. Compare them now?',
            reason: `Raised from ${results.length} rendered ${task.engineName} result${results.length === 1 ? '' : 's'}, not a generic prompt.`
          }
        : undefined
    });
  }

  private findSession(sessionId: string): SearchSessionRecord | undefined {
    return this.state.sessions.find((entry) => entry.id === sessionId);
  }

  private findTask(taskId: string): SearchTaskRecord | undefined {
    return this.state.sessions.flatMap((entry) => entry.tasks).find((entry) => entry.id === taskId);
  }

  private async patchTask(taskId: string, patch: Partial<SearchTaskRecord>): Promise<void> {
    const updatedAt = new Date().toISOString();
    this.state = {
      ...this.state,
      sessions: this.state.sessions.map((session) =>
        session.tasks.some((task) => task.id === taskId)
          ? { ...session, updatedAt, tasks: session.tasks.map((task) => task.id === taskId ? { ...task, ...patch } : task) }
          : session
      )
    };
    await this.commit();
  }

  private async commit(): Promise<void> {
    await this.onChange(this.state);
  }
}

function buildDefaultRecipe(draft: SearchQueryDraft): Array<{ category: SearchCategory; plan: SearchLaunchPlan }> {
  const targets = parseTargets(draft.targetsText);
  if (targets.length === 0) return [];
  const targetText = targets.join('\n');
  const selected = new Set(draft.selectedEngineIds);
  const webEngine = (['google', 'bing', 'yahoo'] as SearchEngineId[]).find((id) => selected.has(id)) ?? 'google';
  const patterns: Array<[SearchCategory, string]> = [
    ['public-footprint', '("login" OR "admin" OR "portal" OR "vpn" OR "sso" OR "remote access")'],
    ['indexed-files', '(filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:csv OR filetype:txt) (internal OR confidential OR credential OR token)'],
    ['archives', `site:web.archive.org/web/ "${targets[0]}"`],
    ['javascript', '(filetype:js OR filetype:map OR inurl:.js) (sourceMappingURL OR webpack OR chunk)'],
    ['libraries', '(jquery OR bootstrap OR lodash OR react OR angular OR vue) (version OR min.js OR bundle)'],
    ['extracted-urls', '(inurl:api OR inurl:graphql OR inurl:swagger OR inurl:openapi OR inurl:callback)'],
    ['client-features', '("feature flag" OR featureFlags OR enabledFeatures OR rollout OR experiment OR remoteConfig) (filetype:js OR filetype:json)']
  ];
  const recipe = patterns.flatMap(([category, queryText]) =>
    buildSearchLaunchPlans({ ...draft, targetsText: category === 'archives' ? '' : targetText, queryText, selectedEngineIds: [webEngine], launchMode: 'combined', openInBackground: true })
      .map((plan) => ({ category, plan }))
  );
  const infraEngines = (['shodan', 'crtsh'] as SearchEngineId[]).filter((id) => selected.has(id));
  recipe.push(...buildSearchLaunchPlans({ ...draft, targetsText: targetText, queryText: '', selectedEngineIds: infraEngines, launchMode: 'per-target', openInBackground: true })
    .map((plan) => ({ category: 'infrastructure' as const, plan })));
  return recipe;
}

function validateGeneratedTask(task: GeneratedSearchTaskInput, index: number): void {
  const taskNumber = index + 1;
  const nerdFormSubmission = task.nerdFormSubmission ?? task.nerdSubmission;
  if (!task.engineName.trim()) {
    throw new Error(`Generated search task ${taskNumber} is missing its destination name.`);
  }
  if (!task.query.trim()) {
    throw new Error(`Generated search task ${taskNumber} has an empty query.`);
  }
  try {
    const url = new URL(task.searchUrl);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new Error('unsupported protocol');
    }
  } catch {
    throw new Error(`Generated search task ${taskNumber} has an invalid HTTP search URL.`);
  }
  if (nerdFormSubmission && task.engineId !== 'nerd') {
    throw new Error(`Generated search task ${taskNumber} attaches a NERD form to a non-NERD destination.`);
  }
  if (task.engineId === 'nerd' && task.nerdSurface?.mode === 'form' && !nerdFormSubmission) {
    throw new Error(`Generated search task ${taskNumber} is missing its NERD form submission trace.`);
  }
}

function copyStrings(values: string[] | undefined): string[] | undefined {
  return values && values.length > 0 ? [...values] : undefined;
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function normalizeResults(entries: RenderedSearchInspection['results'], task: SearchTaskRecord): SearchResultRecord[] {
  const seen = new Set<string>();
  const now = new Date().toISOString();
  const results: SearchResultRecord[] = [];
  const scopedTargets = uniqueStrings([
    ...(task.targets ?? []),
    ...(task.target ? [task.target] : [])
  ]);
  const query = task.query.toLowerCase();
  const hasSiteScope = scopedTargets.some((target) =>
    query.includes(`site:${target.toLowerCase()}`)
  );
  for (const entry of entries) {
    let url: URL;
    try { url = new URL(entry.url); } catch { continue; }
    if (!/^https?:$/.test(url.protocol)) continue;
    url.hash = '';
    if (
      hasSiteScope &&
      !['archives', 'infrastructure'].includes(task.category) &&
      !scopedTargets.some((target) =>
        url.hostname === target.toLowerCase() ||
        url.hostname.endsWith(`.${target.toLowerCase()}`)
      )
    ) continue;
    const key = url.toString();
    if (seen.has(key) || key === task.searchUrl) continue;
    seen.add(key);
    results.push({ id: createId('result'), url: key, title: entry.title?.trim() || undefined, snippet: entry.snippet?.trim() || undefined, engineId: task.engineId, query: task.query, rank: results.length + 1, firstSeenAt: now });
  }
  return results;
}

function inspectRenderedSearchPage(
  maxResults: number,
  includeGenericSiteResults = false
): RenderedSearchInspection {
  const text = `${document.title}\n${document.body?.innerText ?? ''}`.toLowerCase();
  const antiPatterns = ['unusual traffic', 'verify you are human', 'captcha', 'security check', 'automated queries', 'access denied', 'challenge-platform'];
  const matchedAnti = antiPatterns.find((pattern) => text.includes(pattern));
  if (matchedAnti) return { outcome: 'manual', reason: `Search engine page contains “${matchedAnti}”.`, results: [] };

  const selectors = ['a h3', 'li.b_algo h2 a', 'h3.title a', '.result-link', '#content a'];
  if (includeGenericSiteResults) {
    selectors.push(
      '[class*="result" i] a[href]',
      '[id*="result" i] a[href]',
      '[data-testid*="result" i] a[href]',
      '[role="listitem"] a[href]'
    );
  }
  const anchors = new Set<HTMLAnchorElement>();
  for (const selector of selectors) {
    for (const node of Array.from(document.querySelectorAll(selector))) {
      const anchor = node instanceof HTMLAnchorElement ? node : node.closest('a');
      if (anchor) anchors.add(anchor);
    }
  }
  if (anchors.size === 0) {
    for (const anchor of Array.from(document.querySelectorAll<HTMLAnchorElement>('main a[href], #search a[href], #b_results a[href]'))) anchors.add(anchor);
  }
  const results = [...anchors].slice(0, Math.max(1, maxResults)).map((anchor) => {
    const container = anchor.closest(
      'article, li, [role="listitem"], .g, .result, .b_algo, [class*="result" i]'
    ) as HTMLElement | null;
    return { url: anchor.href, title: anchor.textContent?.trim() || undefined, snippet: container?.innerText?.trim().slice(0, 500) };
  }).filter((entry) => /^https?:/i.test(entry.url) && entry.url !== location.href);
  if (results.length > 0) return { outcome: 'results', results };
  const emptyPatterns = [
    'no results found',
    'did not match any documents',
    'there are no results',
    'no information found',
    'we did not find results',
    'no matching results',
    'did not return any results'
  ];
  const empty = emptyPatterns.some((pattern) => text.includes(pattern));
  return {
    outcome: empty ? 'empty' : 'manual',
    reason: empty ? undefined : 'The page loaded, but BLANCHE could not verify a result set or an explicit zero-result message.',
    results: []
  };
}

async function waitForTab(tabId: number, timeoutMs: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(error);
      else resolve();
    };
    const timer = setTimeout(
      () => finish(new Error('Search page load timed out.')),
      timeoutMs
    );
    const listener = (updatedTabId: number, info: { status?: string }) => {
      if (updatedTabId === tabId && info.status === 'complete') finish();
    };
    const cleanup = () => { clearTimeout(timer); chrome.tabs.onUpdated.removeListener(listener); };
    chrome.tabs.onUpdated.addListener(listener);
    void chrome.tabs.get(tabId).then((tab) => {
      if (tab.status === 'complete') finish();
    }).catch((error) => {
      finish(error instanceof Error ? error : new Error(String(error)));
    });
  });
}

function watchForTabNavigationOrSettling(
  tabId: number,
  baselineUrl: string | undefined,
  timeoutMs: number
): { promise: Promise<void>; cancel: () => void } {
  let settled = false;
  let navigationObserved = false;
  let settleTimer: ReturnType<typeof setTimeout> | undefined;
  let timeoutTimer: ReturnType<typeof setTimeout> | undefined;
  let resolvePromise!: () => void;
  let rejectPromise!: (error: Error) => void;
  const promise = new Promise<void>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });

  const cleanup = () => {
    if (settleTimer) clearTimeout(settleTimer);
    if (timeoutTimer) clearTimeout(timeoutTimer);
    chrome.tabs.onUpdated.removeListener(updatedListener);
    chrome.tabs.onRemoved.removeListener(removedListener);
  };
  const finish = () => {
    if (settled) return;
    settled = true;
    cleanup();
    resolvePromise();
  };
  const fail = (message: string) => {
    if (settled) return;
    settled = true;
    cleanup();
    rejectPromise(new Error(message));
  };
  const scheduleSettle = (delayMs: number) => {
    if (settleTimer) clearTimeout(settleTimer);
    settleTimer = setTimeout(finish, delayMs);
  };
  const updatedListener = (
    updatedTabId: number,
    info: { status?: string; url?: string }
  ) => {
    if (updatedTabId !== tabId || settled) return;
    const urlChanged = Boolean(info.url && info.url !== baselineUrl);
    if (info.status === 'loading' || urlChanged) {
      navigationObserved = true;
      if (settleTimer) clearTimeout(settleTimer);
      settleTimer = undefined;
    }
    if (info.status === 'complete') {
      scheduleSettle(650);
    } else if (urlChanged) {
      // A History API-driven result page may change URL without emitting a loading transition.
      setTimeout(() => {
        void chrome.tabs.get(tabId).then((tab) => {
          if (!settled && tab.status === 'complete') scheduleSettle(900);
        }).catch(() => undefined);
      }, 250);
    }
  };
  const removedListener = (removedTabId: number) => {
    if (removedTabId === tabId) fail('The Site Search tab closed before results could be inspected.');
  };

  chrome.tabs.onUpdated.addListener(updatedListener);
  chrome.tabs.onRemoved.addListener(removedListener);
  // Dynamic/SPA search controls may render results without a tab navigation event.
  scheduleSettle(1800);
  timeoutTimer = setTimeout(
    () => fail(
      navigationObserved
        ? 'The NERD search result page did not finish loading.'
        : 'The NERD search form did not settle after submission.'
    ),
    timeoutMs
  );
  return { promise, cancel: finish };
}

function queryKey(task: Pick<SearchTaskRecord, 'engineId' | 'query'>): string {
  return `${task.engineId}:${task.query.trim().toLowerCase()}`;
}

function wait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function createId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}
