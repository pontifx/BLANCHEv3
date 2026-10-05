import type {
  BlancheTearSheetV1,
  JsonObject,
  JsonValue,
  ScopePolicy,
  TrafficLedgerEntryV1,
  TrafficLedgerSummary,
  TrafficScopeDisposition,
  TrafficScopeRuleMatcherV1,
  TrafficScopeRuleV1,
  TrafficScheme
} from '../../../shared-schema/src';
import type {
  FeedEntry,
  FeedEntryKind,
  HostStateSnapshot,
  ModuleSettingsFieldDefinition,
  TrafficLedgerQueryResult
} from './contracts';
import type { AcquiredDocument, DocumentWorkbenchState } from './documentWorkbench';
import {
  createDefaultScopePolicy,
  createDefaultEngagementProfilesState,
  createEngagementProfile,
  type EngagementProfile,
  type EngagementProfilesState
} from './engagementProfiles';
import {
  appendScopePatternLines,
  cloneScopePolicy,
  normalizeScopePolicy
} from './scopePolicy';
import {
  createDefaultInterestWorkbenchState,
  normalizeInterestWorkbenchSettings,
  type InterestAnalysis,
  type InterestBookmarkSummary,
  type InterestPrediction,
  type InterestSignalSummary,
  type InterestWalkPath,
  type InterestWorkbenchState
} from './interestWorkbench';
import {
  SEARCH_ENGINES,
  buildSearchLaunchPlans,
  createCustomSearchOperator,
  createDefaultSearchWorkbenchState,
  createDefaultSearchDraft,
  createSavedSearchProfile,
  getSearchOperators,
  normalizeDorkSuiteDraft,
  normalizeSearchDraft,
  parseTargets,
  tryGetHostname,
  validateSearchDraft,
  type SearchEngineDefinition,
  type SearchEngineId,
  type SearchOperatorDefinition,
  type SearchWorkbenchState
} from './searchWorkbench';
import {
  DORK_SUITE_CATEGORIES,
  buildDorkSuitePlan,
  buildPortableDorkSuitePlan,
  validateDorkSuitePlan,
  type DorkSuitePlan
} from './searchDorkSuite';
import {
  createNerdSearchSurface,
  createNerdSearchSurfaceFromTemplate,
  getNerdSearchSurfaceTarget,
  type NerdSearchCandidate
} from './nerdSearch';
import {
  CORE_WEB_SEARCH_ENGINE_IDS,
  SEARCH_OPERATOR_CATALOG,
  type CoreWebSearchEngineId,
  type SearchOperatorCatalogEntry,
  type SearchOperatorSupportStatus
} from './searchOperatorCatalog';
import { sendRuntimeMessage } from './runtimeBus';
import { serializeTrafficLedgerJsonl } from './trafficLedger';
import { javascriptTestMatchesScan } from './latentFeatureWorkbench';
import {
  maskStakeholderUrl,
  renderTearSheetHtml,
  renderTearSheetStakeholderBody
} from './tearSheetHtml';
import { buildTearSheetFileStem, buildTearSheetReport } from './tearSheetReport';
import {
  buildBurpGetRequest,
  buildBurpPostRequest,
  getTargetUrlParameters
} from './targetRequestTemplates';
import {
  buildSiteSearchFingerprint,
  type SiteSearchFingerprint,
  type SiteSearchSignalAssessment
} from './siteSearchFingerprint';

interface TargetTabInfo {
  tabId: number;
  title?: string;
  url?: string;
  windowId?: number;
  index?: number;
}

interface OperatorConsoleOptions {
  container: HTMLElement;
  surfaceLabel: string;
  resolveTargetTab(): Promise<TargetTabInfo | undefined>;
}

type SearchWorkbenchTab = 'run' | 'suite' | 'nerd' | 'catalog' | 'profiles' | 'configure';
type DocumentWorkbenchTab = 'overview' | 'configure';
type ScopeRuleDraftField =
  | 'priority'
  | 'disposition'
  | 'matcherKind'
  | 'matcherValue'
  | 'schemes'
  | 'ports'
  | 'methods'
  | 'note';
type PrimaryView =
  | 'home'
  | 'traffic'
  | 'search'
  | 'documents'
  | 'findings'
  | 'report'
  | 'labs';
type ReportViewMode = 'stakeholder' | 'json';
type TargetOutputKind = 'url' | 'params' | 'get' | 'post';

interface ConsoleState {
  snapshot?: HostStateSnapshot;
  targetTab?: TargetTabInfo;
  notice?: string;
  busy: boolean;
  drafts: Map<string, Record<string, JsonValue>>;
  searchWorkbench: SearchWorkbenchState;
  searchWorkbenchDirty: boolean;
  searchTab: SearchWorkbenchTab;
  nerdCandidates: NerdSearchCandidate[];
  documentTab: DocumentWorkbenchTab;
  interestWorkbench: InterestWorkbenchState;
  interestWorkbenchDirty: boolean;
  engagementProfiles: EngagementProfilesState;
  engagementProfileDraft: {
    editingProfileId?: string;
    name: string;
    scopeNotes: string;
    scopePolicy: ScopePolicy;
    includeText: string;
    excludeText: string;
    reviewText: string;
    defaultDisposition: Exclude<TrafficScopeDisposition, 'in-scope'>;
  };
  trafficLedger: TrafficLedgerQueryResult;
  trafficScopeFilter: TrafficScopeDisposition | 'all';
  trafficMinimumScore: number;
  feedKindFilter: FeedEntryKind | 'all';
  primaryView: PrimaryView;
  reportMode: ReportViewMode;
  targetOutputKind: TargetOutputKind;
  tearSheet?: BlancheTearSheetV1;
  openDisclosureKeys: Set<string>;
  focusedDisclosureKey?: string;
  acknowledgedLatentFeatureScanId?: string;
  flashingLatentFeatureScanId?: string;
}

const SEARCH_OPERATOR_CATEGORY_ORDER: Array<SearchOperatorDefinition['category']> = [
  'scope',
  'content',
  'exclude',
  'intel',
  'certificate'
];

const SEARCH_OPERATOR_CATEGORY_LABELS: Record<SearchOperatorDefinition['category'], string> = {
  scope: 'Scope',
  content: 'Content',
  exclude: 'Exclude',
  intel: 'Service Intel',
  certificate: 'Certificates'
};

export function mountOperatorConsole(options: OperatorConsoleOptions): void {
  const state: ConsoleState = {
    busy: false,
    drafts: new Map(),
    searchWorkbench: createDefaultSearchWorkbenchState(),
    searchWorkbenchDirty: false,
    searchTab: 'run',
    nerdCandidates: [],
    documentTab: 'overview',
    interestWorkbench: createDefaultInterestWorkbenchState(),
    interestWorkbenchDirty: false,
    engagementProfiles: createDefaultEngagementProfilesState(),
    engagementProfileDraft: {
      name: '',
      scopeNotes: '',
      scopePolicy: createDefaultScopePolicy('draft'),
      includeText: '',
      excludeText: '',
      reviewText: '',
      defaultDisposition: 'review'
    },
    trafficLedger: {
      entries: [],
      summary: createEmptyTrafficLedgerSummary()
    },
    trafficScopeFilter: 'all',
    trafficMinimumScore: 0,
    feedKindFilter: 'all',
    primaryView: 'home',
    reportMode: 'stakeholder',
    targetOutputKind: 'url',
    openDisclosureKeys: new Set()
  };

  const refresh = async () => {
    state.busy = true;
    render();

    try {
      const [snapshot, targetTab] = await Promise.all([
        sendRuntimeMessage('core/getState', {
          includeLogs: true
        }),
        options.resolveTargetTab()
      ]);

      state.snapshot = snapshot;
      state.targetTab = targetTab;
      state.trafficLedger = await sendRuntimeMessage('traffic/query', {
        tabId: targetTab?.tabId,
        targetOrigin: tryParseOrigin(targetTab?.url),
        scope:
          state.trafficScopeFilter === 'all'
            ? undefined
            : state.trafficScopeFilter,
        minScore: state.trafficMinimumScore,
        limit: 250
      });
      seedDrafts(snapshot);

      if (!state.searchWorkbenchDirty) {
        state.searchWorkbench = snapshot.searchWorkbench;
      }

      if (!state.interestWorkbenchDirty) {
        state.interestWorkbench = snapshot.interestWorkbench;
      }

      state.engagementProfiles = snapshot.engagementProfiles;
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const seedDrafts = (snapshot: HostStateSnapshot) => {
    for (const module of snapshot.modules) {
      if (!state.drafts.has(module.descriptor.id)) {
        state.drafts.set(module.descriptor.id, {
          ...module.settings
        });
      }
    }
  };

  const persistSearchWorkbench = async (nextState: SearchWorkbenchState, notice: string) => {
    state.busy = true;
    render();

    try {
      state.snapshot = await sendRuntimeMessage('core/updateSearchWorkbench', {
        searchWorkbench: nextState
      });
      state.searchWorkbench = state.snapshot.searchWorkbench;
      state.searchWorkbenchDirty = false;
      state.notice = notice;
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const persistInterestWorkbench = async (nextState: InterestWorkbenchState, notice: string) => {
    state.busy = true;
    render();

    try {
      state.snapshot = await sendRuntimeMessage('core/updateInterestWorkbench', {
        interestWorkbench: nextState
      });
      state.interestWorkbench = state.snapshot.interestWorkbench;
      state.interestWorkbenchDirty = false;
      state.notice = notice;
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const setInterestWorkbench = (
    nextState: InterestWorkbenchState,
    updateOptions: {
      rerender?: boolean;
      dirty?: boolean;
      notice?: string;
    } = {}
  ) => {
    state.interestWorkbench = {
      ...nextState,
      settings: normalizeInterestWorkbenchSettings(nextState.settings)
    };
    state.interestWorkbenchDirty = updateOptions.dirty ?? true;
    if (updateOptions.notice) {
      state.notice = updateOptions.notice;
    }

    if (updateOptions.rerender !== false) {
      render();
    }
  };

  const setSearchWorkbench = (
    nextState: SearchWorkbenchState,
    updateOptions: {
      rerender?: boolean;
      dirty?: boolean;
      notice?: string;
    } = {}
  ) => {
    state.searchWorkbench = {
      ...nextState,
      draft: normalizeSearchDraft(nextState.draft)
    };
    state.searchWorkbenchDirty = updateOptions.dirty ?? true;
    if (updateOptions.notice) {
      state.notice = updateOptions.notice;
    }

    if (updateOptions.rerender !== false) {
      render();
    }
  };

  const updateSearchDraft = (
    patch: Partial<SearchWorkbenchState['draft']>,
    updateOptions: {
      rerender?: boolean;
      notice?: string;
    } = {}
  ) => {
    setSearchWorkbench(
      {
        ...state.searchWorkbench,
        draft: normalizeSearchDraft({
          ...state.searchWorkbench.draft,
          ...patch
        })
      },
      {
        rerender: updateOptions.rerender,
        dirty: true,
        notice: updateOptions.notice
      }
    );
  };

  const updateDorkSuiteDraft = (
    patch: Partial<SearchWorkbenchState['dorkSuiteDraft']>,
    updateOptions: { rerender?: boolean; notice?: string } = {}
  ) => {
    setSearchWorkbench(
      {
        ...state.searchWorkbench,
        dorkSuiteDraft: normalizeDorkSuiteDraft({
          ...state.searchWorkbench.dorkSuiteDraft,
          ...patch
        })
      },
      {
        rerender: updateOptions.rerender,
        dirty: true,
        notice: updateOptions.notice
      }
    );
  };

  const syncSearchLaunchControls = () => {
    const draft = state.searchWorkbench.draft;
    const launchPlans = buildSearchLaunchPlans(draft);
    const validationError = validateSearchDraft(draft);

    const launchButton = options.container.querySelector<HTMLButtonElement>(
      '[data-search-action="launch"]'
    );
    if (launchButton) {
      launchButton.disabled = state.busy || Boolean(validationError) || launchPlans.length === 0;
      launchButton.textContent = `Launch ${launchPlans.length || ''} Search${
        launchPlans.length === 1 ? '' : 'es'
      }`;
    }

    const summaryEl = options.container.querySelector('[data-search-preview="summary"]');
    if (summaryEl) {
      const targetCount = parseTargets(draft.targetsText).length;
      const selectedEngineCount = draft.selectedEngineIds.length;
      summaryEl.textContent = `${launchPlans.length} tab${
        launchPlans.length === 1 ? '' : 's'
      } across ${selectedEngineCount} engine${selectedEngineCount === 1 ? '' : 's'} and ${targetCount} target${
        targetCount === 1 ? '' : 's'
      }`;
    }

    const statusEl = options.container.querySelector('[data-search-preview="status"]');
    if (statusEl) {
      statusEl.innerHTML = validationError
        ? `<div class="status-error">${escapeHtml(validationError)}</div>`
        : '<div class="muted">Preview shows the exact query string that will be sent to each engine.</div>';
    }

    const listEl = options.container.querySelector('[data-search-preview="list"]');
    if (listEl) {
      listEl.innerHTML = renderLaunchPreview(launchPlans);
    }
  };

  const updateInterestSettings = (
    patch: Partial<InterestWorkbenchState['settings']>,
    updateOptions: {
      rerender?: boolean;
      notice?: string;
    } = {}
  ) => {
    setInterestWorkbench(
      {
        ...state.interestWorkbench,
        settings: normalizeInterestWorkbenchSettings({
          ...state.interestWorkbench.settings,
          ...patch
        })
      },
      {
        rerender: updateOptions.rerender,
        dirty: true,
        notice: updateOptions.notice
      }
    );
  };

  const toggleSearchEngine = (engineId: SearchEngineId) => {
    const selected = new Set(state.searchWorkbench.draft.selectedEngineIds);
    if (selected.has(engineId)) {
      selected.delete(engineId);
    } else {
      selected.add(engineId);
    }

    updateSearchDraft({
      selectedEngineIds: SEARCH_ENGINES.filter((engine) => selected.has(engine.id)).map(
        (engine) => engine.id
      )
    });
  };

  const insertOperatorTemplate = (operatorId: string) => {
    const operator = getSearchOperators(state.searchWorkbench.customOperators).find(
      (candidate) => candidate.id === operatorId
    );
    if (!operator) {
      return;
    }

    const nextQueryText = [state.searchWorkbench.draft.queryText.trim(), operator.template]
      .filter(Boolean)
      .join(' ')
      .trim();

    updateSearchDraft(
      {
        queryText: nextQueryText
      },
      {
        notice:
          operator.template.includes('{value}') || operator.template.includes('{target}')
            ? `Inserted ${operator.label}. Replace placeholder tokens before launching if needed.`
            : `Inserted ${operator.label}.`
      }
    );
  };

  const saveSettings = async (moduleId: string) => {
    const settings = state.drafts.get(moduleId);
    if (!settings) {
      return;
    }

    state.busy = true;
    render();
    try {
      state.snapshot = await sendRuntimeMessage('core/updateModuleSettings', {
        moduleId,
        settings
      });
      state.notice = `Saved settings for ${moduleId}.`;
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const toggleModule = async (moduleId: string, enabled: boolean) => {
    state.busy = true;
    render();
    try {
      state.snapshot = await sendRuntimeMessage('core/toggleModule', {
        moduleId,
        enabled
      });
      state.notice = `${enabled ? 'Enabled' : 'Disabled'} ${moduleId}.`;
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const runAction = async (moduleId: string, actionId: string, input?: JsonObject) => {
    state.busy = true;
    render();
    try {
      const result = await sendRuntimeMessage('core/runAction', {
        moduleId,
        actionId,
        tabId: state.targetTab?.tabId,
        caller: options.surfaceLabel === 'DevTools' ? 'devtools' : 'sidepanel',
        input
      });

      state.notice = result.message;
      state.snapshot = await sendRuntimeMessage('core/getState', {
        includeLogs: true
      });
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const runDocumentAction = async (actionId: string) => {
    await runAction('document-acquisition', actionId);
  };

  const runAdvancedSearch = async () => {
    state.busy = true;
    render();
    try {
      if (state.searchWorkbenchDirty) {
        state.snapshot = await sendRuntimeMessage('core/updateSearchWorkbench', {
          searchWorkbench: state.searchWorkbench
        });
        state.searchWorkbench = state.snapshot.searchWorkbench;
        state.searchWorkbenchDirty = false;
      }
      state.snapshot = await sendRuntimeMessage('core/startSearchSession', {
        useDefaultRecipe: true,
        tabId: state.targetTab?.tabId
      });
      state.primaryView = 'search';
      state.notice = 'Advanced search started quietly in the background.';
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const copyLastExport = async () => {
    if (!state.snapshot?.lastExport) {
      return;
    }

    await navigator.clipboard.writeText(JSON.stringify(state.snapshot.lastExport, null, 2));
    state.notice = 'Copied the latest export JSON to the clipboard.';
    render();
  };

  const getLatestTearSheet = (): BlancheTearSheetV1 | undefined =>
    getOrBuildTearSheet(state);

  const copyTearSheetJson = async () => {
    const report = getLatestTearSheet();
    if (!report) {
      return;
    }

    await navigator.clipboard.writeText(`${JSON.stringify(report, null, 2)}\n`);
    state.notice = 'Copied the full site tear sheet JSON. Treat it as assessment-sensitive evidence.';
    render();
  };

  const downloadTearSheet = (format: 'html' | 'json') => {
    const report = getLatestTearSheet();
    if (!report) {
      return;
    }

    const fileStem = buildTearSheetFileStem(report);
    if (format === 'html') {
      downloadTextFile(
        renderTearSheetHtml(report),
        `${fileStem}.html`,
        'text/html;charset=utf-8'
      );
      state.notice = 'Downloaded the masked stakeholder tear sheet HTML.';
    } else {
      downloadTextFile(
        `${JSON.stringify(report, null, 2)}\n`,
        `${fileStem}.json`,
        'application/json;charset=utf-8'
      );
      state.notice = 'Downloaded full JSON evidence. It may contain sensitive browser state.';
    }
    render();
  };

  const refreshTrafficLedger = async () => {
    state.busy = true;
    render();
    try {
      state.trafficLedger = await sendRuntimeMessage('traffic/query', {
        tabId: state.targetTab?.tabId,
        targetOrigin: tryParseOrigin(state.targetTab?.url),
        scope:
          state.trafficScopeFilter === 'all'
            ? undefined
            : state.trafficScopeFilter,
        minScore: state.trafficMinimumScore,
        limit: 250
      });
      state.notice = `Loaded ${state.trafficLedger.entries.length} traffic endpoints.`;
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const downloadTrafficLedger = async (format: 'json' | 'jsonl') => {
    state.busy = true;
    render();
    try {
      const ledger = await sendRuntimeMessage('traffic/export', {
        tabId: state.targetTab?.tabId,
        targetOrigin: tryParseOrigin(state.targetTab?.url),
        limit: 1000
      });
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      if (format === 'jsonl') {
        downloadTextFile(
          serializeTrafficLedgerJsonl(ledger),
          `blanche-traffic-ledger-${timestamp}.jsonl`,
          'application/x-ndjson;charset=utf-8'
        );
      } else {
        downloadTextFile(
          `${JSON.stringify(ledger, null, 2)}\n`,
          `blanche-traffic-ledger-${timestamp}.json`,
          'application/json;charset=utf-8'
        );
      }
      state.notice = `Downloaded ${ledger.summary.entryCount} sanitized traffic endpoints.`;
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const clearTrafficLedger = async () => {
    if (!window.confirm('Clear the local traffic ledger? This cannot be undone.')) {
      return;
    }
    state.busy = true;
    render();
    try {
      await sendRuntimeMessage('traffic/clear', {});
      state.trafficLedger = {
        entries: [],
        summary: createEmptyTrafficLedgerSummary()
      };
      state.notice = 'Cleared the local traffic ledger.';
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const saveInterestSettings = async () => {
    await persistInterestWorkbench(
      state.interestWorkbench,
      'Saved interest model settings.'
    );
  };

  const runInterestAction = async (
    action: 'analyze' | 'create-folder' | 'bookmark-tab',
    notice: string
  ) => {
    state.busy = true;
    render();

    try {
      state.snapshot = await sendRuntimeMessage('core/runInterestAction', {
        action,
        tabId: state.targetTab?.tabId
      });
      state.interestWorkbench = state.snapshot.interestWorkbench;
      state.interestWorkbenchDirty = false;
      state.notice = notice;
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const updateEngagementProfileDraft = (patch: Partial<ConsoleState['engagementProfileDraft']>) => {
    state.engagementProfileDraft = {
      ...state.engagementProfileDraft,
      ...patch
    };
  };

  const updateEngagementScopeRule = (
    ruleIndex: number,
    field: ScopeRuleDraftField,
    value: string,
    rerender = false
  ) => {
    const policy = state.engagementProfileDraft.scopePolicy;
    const rule = policy.rules[ruleIndex];
    if (!rule) {
      return;
    }
    const nextPolicy = cloneScopePolicy(policy);
    nextPolicy.rules[ruleIndex] = updateScopeRuleDraftField(rule, field, value);
    updateEngagementProfileDraft({ scopePolicy: nextPolicy });
    if (rerender) {
      render();
    }
  };

  const removeEngagementScopeRule = (ruleIndex: number) => {
    const policy = state.engagementProfileDraft.scopePolicy;
    if (!policy.rules[ruleIndex]) {
      return;
    }
    const nextPolicy = cloneScopePolicy(policy);
    nextPolicy.rules.splice(ruleIndex, 1);
    updateEngagementProfileDraft({ scopePolicy: nextPolicy });
    render();
  };

  const addEngagementScopeRule = () => {
    const nextPolicy = cloneScopePolicy(state.engagementProfileDraft.scopePolicy);
    nextPolicy.rules.push({
      ruleId: `operator-${crypto.randomUUID()}`,
      priority: 100,
      disposition: 'in-scope',
      source: 'operator',
      matcher: {
        kind: 'exact-host',
        hostname: tryGetHostname(state.targetTab?.url) ?? ''
      }
    });
    updateEngagementProfileDraft({ scopePolicy: nextPolicy });
    render();
  };

  const resetEngagementProfileDraft = () => {
    state.engagementProfileDraft = {
      name: '',
      scopeNotes: '',
      scopePolicy: createDefaultScopePolicy('draft'),
      includeText: '',
      excludeText: '',
      reviewText: '',
      defaultDisposition: 'review'
    };
    state.notice = 'Started a new engagement profile.';
    render();
  };

  const persistEngagementProfiles = async (
    nextState: EngagementProfilesState,
    notice: string
  ): Promise<boolean> => {
    state.busy = true;
    render();

    try {
      state.snapshot = await sendRuntimeMessage('core/updateEngagementProfiles', {
        engagementProfiles: nextState
      });
      state.engagementProfiles = state.snapshot.engagementProfiles;
      state.notice = notice;
      return true;
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
      return false;
    } finally {
      state.busy = false;
      render();
    }
  };

  const saveEngagementProfile = async () => {
    const name = state.engagementProfileDraft.name.trim();
    if (!name) {
      state.notice = 'Add a profile name before saving the current configuration.';
      render();
      return;
    }

    const modules = state.snapshot?.modules ?? [];
    const moduleSettings: Record<string, Record<string, JsonValue>> = {};
    const enabledModuleIds: string[] = [];
    for (const module of modules) {
      moduleSettings[module.descriptor.id] = { ...module.settings };
      if (module.enabled) {
        enabledModuleIds.push(module.descriptor.id);
      }
    }

    const existing = state.engagementProfileDraft.editingProfileId
      ? state.engagementProfiles.savedProfiles.find(
          (profile) => profile.id === state.engagementProfileDraft.editingProfileId
        )
      : undefined;
    if (state.engagementProfileDraft.editingProfileId && !existing) {
      state.notice = 'The engagement profile being edited no longer exists. Start a new profile.';
      render();
      return;
    }

    let scopePolicy: EngagementProfile['scopePolicy'];
    try {
      const structuredPolicy = state.engagementProfileDraft.scopePolicy;
      const currentVersion = Number(existing?.scopePolicy.version ?? '0');
      const nextVersion = Number.isFinite(currentVersion)
        ? String(currentVersion + 1)
        : new Date().toISOString();
      scopePolicy = normalizeScopePolicy({
        ...appendScopePatternLines({
          policy: structuredPolicy,
          version: nextVersion,
          includeText: state.engagementProfileDraft.includeText,
          excludeText: state.engagementProfileDraft.excludeText,
          reviewText: state.engagementProfileDraft.reviewText,
          defaultDisposition: state.engagementProfileDraft.defaultDisposition
        }),
        policyId:
          existing?.scopePolicy.policyId ??
          `engagement:${name
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-|-$/g, '')}`,
        version: nextVersion
      });
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
      render();
      return;
    }

    const nextProfile: EngagementProfile = existing
      ? {
          ...existing,
          name,
          scopeNotes: state.engagementProfileDraft.scopeNotes.trim(),
          scopePolicy,
          moduleSettings,
          enabledModuleIds,
          updatedAt: new Date().toISOString()
        }
      : createEngagementProfile({
          name,
          scopeNotes: state.engagementProfileDraft.scopeNotes,
          scopePolicy,
          moduleSettings,
          enabledModuleIds
        });

    const nextState: EngagementProfilesState = {
      savedProfiles: [
        ...state.engagementProfiles.savedProfiles.filter((profile) => profile.id !== nextProfile.id),
        nextProfile
      ],
      activeProfileId: state.engagementProfiles.activeProfileId,
      activatedAt: state.engagementProfiles.activatedAt
    };

    const persisted = await persistEngagementProfiles(
      nextState,
      existing ? `Updated engagement profile ${name}.` : `Saved engagement profile ${name}.`
    );
    if (persisted) {
      state.engagementProfileDraft = {
        ...state.engagementProfileDraft,
        editingProfileId: nextProfile.id,
        scopePolicy: cloneScopePolicy(nextProfile.scopePolicy),
        includeText: '',
        excludeText: '',
        reviewText: ''
      };
      render();
    }
  };

  const deleteEngagementProfile = async (profileId: string) => {
    const profile = state.engagementProfiles.savedProfiles.find((entry) => entry.id === profileId);
    if (!profile) {
      return;
    }

    const nextState: EngagementProfilesState = {
      savedProfiles: state.engagementProfiles.savedProfiles.filter((entry) => entry.id !== profileId),
      activeProfileId:
        state.engagementProfiles.activeProfileId === profileId
          ? undefined
          : state.engagementProfiles.activeProfileId,
      activatedAt:
        state.engagementProfiles.activeProfileId === profileId
          ? undefined
          : state.engagementProfiles.activatedAt
    };

    await persistEngagementProfiles(nextState, `Deleted engagement profile ${profile.name}.`);
  };

  const editEngagementProfile = (profileId: string) => {
    const profile = state.engagementProfiles.savedProfiles.find((entry) => entry.id === profileId);
    if (!profile) {
      return;
    }
    state.engagementProfileDraft = {
      editingProfileId: profile.id,
      name: profile.name,
      scopeNotes: profile.scopeNotes,
      scopePolicy: cloneScopePolicy(profile.scopePolicy),
      includeText: '',
      excludeText: '',
      reviewText: '',
      defaultDisposition: profile.scopePolicy.defaultDisposition
    };
    state.primaryView = 'traffic';
    state.notice = `Editing engagement profile ${profile.name}.`;
    render();
  };

  const activateEngagementProfile = async (profileId: string) => {
    state.busy = true;
    render();

    try {
      state.snapshot = await sendRuntimeMessage('core/activateEngagementProfile', {
        profileId
      });
      state.engagementProfiles = state.snapshot.engagementProfiles;
      for (const module of state.snapshot.modules) {
        state.drafts.set(module.descriptor.id, { ...module.settings });
      }

      const activated = state.engagementProfiles.savedProfiles.find((entry) => entry.id === profileId);
      state.notice = activated
        ? `Activated engagement profile ${activated.name}.`
        : 'Activated engagement profile.';
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const saveSearchDraft = async () => {
    await persistSearchWorkbench(state.searchWorkbench, 'Saved the current search draft.');
  };

  const saveSearchProfile = async () => {
    const draft = normalizeSearchDraft(state.searchWorkbench.draft);
    const name = draft.name.trim();
    if (!name) {
      state.notice = 'Add a profile name before saving the search profile.';
      render();
      return;
    }

    const existing = state.searchWorkbench.savedProfiles.find(
      (profile) => profile.name.toLowerCase() === name.toLowerCase()
    );

    const nextProfile = existing
      ? {
          ...existing,
          ...draft,
          name,
          updatedAt: new Date().toISOString()
        }
      : createSavedSearchProfile({
          ...draft,
          name
        });

    const nextState: SearchWorkbenchState = {
      ...state.searchWorkbench,
      draft: {
        ...draft,
        name
      },
      savedProfiles: sortProfiles([
        ...state.searchWorkbench.savedProfiles.filter((profile) => profile.id !== nextProfile.id),
        nextProfile
      ])
    };

    await persistSearchWorkbench(
      nextState,
      existing ? `Updated search profile ${name}.` : `Saved search profile ${name}.`
    );
  };

  const loadSearchProfile = (profileId: string) => {
    const profile = state.searchWorkbench.savedProfiles.find((entry) => entry.id === profileId);
    if (!profile) {
      return;
    }

    state.searchTab = 'run';
    updateSearchDraft(
      {
        name: profile.name,
        targetsText: profile.targetsText,
        queryText: profile.queryText,
        selectedEngineIds: profile.selectedEngineIds,
        launchMode: profile.launchMode,
        openInBackground: profile.openInBackground
      },
      {
        notice: `Loaded search profile ${profile.name}.`
      }
    );
  };

  const deleteSearchProfile = async (profileId: string) => {
    const profile = state.searchWorkbench.savedProfiles.find((entry) => entry.id === profileId);
    if (!profile) {
      return;
    }

    if (profile.id.startsWith('builtin-')) {
      state.notice = `${profile.name} is a built-in OSINT profile and stays available.`;
      render();
      return;
    }

    const nextState: SearchWorkbenchState = {
      ...state.searchWorkbench,
      savedProfiles: state.searchWorkbench.savedProfiles.filter((entry) => entry.id !== profileId)
    };

    await persistSearchWorkbench(nextState, `Deleted search profile ${profile.name}.`);
  };

  const deleteCustomOperator = async (operatorId: string) => {
    const operator = state.searchWorkbench.customOperators.find((entry) => entry.id === operatorId);
    if (!operator) {
      return;
    }

    const nextState: SearchWorkbenchState = {
      ...state.searchWorkbench,
      customOperators: state.searchWorkbench.customOperators.filter((entry) => entry.id !== operatorId)
    };

    await persistSearchWorkbench(nextState, `Deleted custom operator ${operator.label}.`);
  };

  const addCustomOperator = async () => {
    const labelInput = options.container.querySelector<HTMLInputElement>('[data-custom-field="label"]');
    const templateInput = options.container.querySelector<HTMLInputElement>(
      '[data-custom-field="template"]'
    );
    const descriptionInput = options.container.querySelector<HTMLInputElement>(
      '[data-custom-field="description"]'
    );
    const categorySelect = options.container.querySelector<HTMLSelectElement>(
      '[data-custom-field="category"]'
    );

    const selectedEngineIds = Array.from(
      options.container.querySelectorAll<HTMLInputElement>('[data-custom-engine-id]:checked')
    ).map((input) => input.dataset.customEngineId as SearchEngineId);

    const label = labelInput?.value.trim() ?? '';
    const template = templateInput?.value.trim() ?? '';
    if (!label || !template) {
      state.notice = 'Add both a label and a template before saving a custom operator.';
      render();
      return;
    }

    if (selectedEngineIds.length === 0) {
      state.notice = 'Select at least one engine for the custom operator.';
      render();
      return;
    }

    const operator = createCustomSearchOperator({
      label,
      template,
      description: descriptionInput?.value.trim(),
      category:
        (categorySelect?.value as SearchOperatorDefinition['category'] | undefined) ?? 'content',
      engineIds: selectedEngineIds
    });

    const nextState: SearchWorkbenchState = {
      ...state.searchWorkbench,
      customOperators: sortCustomOperators([...state.searchWorkbench.customOperators, operator])
    };

    await persistSearchWorkbench(nextState, `Saved custom operator ${operator.label}.`);
  };

  const launchDorkSuite = async () => {
    const plan = buildDorkSuitePlan(
      state.searchWorkbench.draft,
      state.searchWorkbench.dorkSuiteDraft
    );
    const validationError = validateDorkSuitePlan(plan);
    if (validationError) {
      state.notice = validationError;
      render();
      return;
    }

    state.busy = true;
    render();
    try {
      state.snapshot = await sendRuntimeMessage('core/updateSearchWorkbench', {
        searchWorkbench: state.searchWorkbench
      });
      state.searchWorkbench = state.snapshot.searchWorkbench;
      state.searchWorkbenchDirty = false;
      state.snapshot = await sendRuntimeMessage('core/startDorkSuite', {
        tabId: state.targetTab?.tabId
      });
      state.notice = `Started ${plan.entries.length} engine-aware dork task${
        plan.entries.length === 1 ? '' : 's'
      }.`;
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const discoverNerdSurfaces = async () => {
    if (typeof state.targetTab?.tabId !== 'number') {
      state.notice = 'Open an http(s) page with a search box before scanning for Site Search controls.';
      render();
      return;
    }
    state.busy = true;
    render();
    try {
      const response = await sendRuntimeMessage('core/discoverNerdSearchSurfaces', {
        tabId: state.targetTab.tabId
      });
      state.nerdCandidates = response.surfaces;
      state.notice = response.surfaces.length
        ? `Found ${response.surfaces.length} selectable search surface${
            response.surfaces.length === 1 ? '' : 's'
          } on the active page.`
        : 'No likely search controls were found. Add a reviewed URL template instead.';
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const pickNerdSurface = async () => {
    if (typeof state.targetTab?.tabId !== 'number') {
      state.notice = 'Open an http(s) page before picking a Site Search control.';
      render();
      return;
    }
    state.busy = true;
    state.notice = "Picker active in the target page's top frame. Click its search field, or press Escape to cancel.";
    render();
    try {
      const response = await sendRuntimeMessage('core/pickNerdSearchSurface', {
        tabId: state.targetTab.tabId
      });
      if (response.surface) {
        state.nerdCandidates = [
          response.surface,
          ...state.nerdCandidates.filter(
            (candidate) => candidate.inputSelector !== response.surface?.inputSelector
          )
        ];
        state.notice = `Selected ${response.surface.name} from the target page's top frame for review.`;
      } else {
        state.notice = response.reason ?? 'The top-frame Site Search picker was cancelled.';
      }
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const highlightNerdCandidate = async (candidateId: string) => {
    const candidate = state.nerdCandidates.find((entry) => entry.id === candidateId);
    if (!candidate || typeof state.targetTab?.tabId !== 'number') return;
    try {
      const response = await sendRuntimeMessage('core/highlightNerdSearchSurface', {
        tabId: state.targetTab.tabId,
        inputSelector: candidate.inputSelector
      });
      state.notice = response.highlighted
        ? `Highlighted ${candidate.name} in the target page's top frame.`
        : 'The selected search control is no longer present in the top frame.';
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    }
    render();
  };

  const saveNerdCandidate = async (candidateId: string) => {
    const candidate = state.nerdCandidates.find((entry) => entry.id === candidateId);
    if (!candidate) return;
    try {
      const surface = createNerdSearchSurface(candidate);
      const duplicatesRemoved = state.searchWorkbench.nerdSurfaces.filter(
        (entry) =>
          entry.pageUrl !== surface.pageUrl ||
          entry.inputSelector !== surface.inputSelector ||
          entry.mode !== surface.mode
      );
      await persistSearchWorkbench(
        {
          ...state.searchWorkbench,
          nerdSurfaces: [...duplicatesRemoved, surface],
          selectedNerdSurfaceId: surface.id
        },
        `Saved ${surface.name} as a Site Search surface.`
      );
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
      render();
    }
  };

  const saveManualNerdSurface = async () => {
    const name =
      options.container.querySelector<HTMLInputElement>('[data-nerd-field="template-name"]')?.value ?? '';
    const urlTemplate =
      options.container.querySelector<HTMLInputElement>('[data-nerd-field="url-template"]')?.value ?? '';
    try {
      const surface = createNerdSearchSurfaceFromTemplate({ name, urlTemplate });
      await persistSearchWorkbench(
        {
          ...state.searchWorkbench,
          nerdSurfaces: [...state.searchWorkbench.nerdSurfaces, surface],
          selectedNerdSurfaceId: surface.id
        },
        `Saved ${surface.name} as a Site Search endpoint template.`
      );
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
      render();
    }
  };

  const selectNerdSurface = async (surfaceId: string) => {
    const surface = state.searchWorkbench.nerdSurfaces.find((entry) => entry.id === surfaceId);
    if (!surface) return;
    await persistSearchWorkbench(
      {
        ...state.searchWorkbench,
        selectedNerdSurfaceId: surface.id
      },
      `Selected ${surface.name} for Site Search.`
    );
  };

  const deleteNerdSurface = async (surfaceId: string) => {
    const surface = state.searchWorkbench.nerdSurfaces.find((entry) => entry.id === surfaceId);
    if (!surface) return;
    const nerdSurfaces = state.searchWorkbench.nerdSurfaces.filter((entry) => entry.id !== surfaceId);
    await persistSearchWorkbench(
      {
        ...state.searchWorkbench,
        nerdSurfaces,
        selectedNerdSurfaceId:
          state.searchWorkbench.selectedNerdSurfaceId === surfaceId
            ? nerdSurfaces[0]?.id
            : state.searchWorkbench.selectedNerdSurfaceId
      },
      `Deleted Site Search surface ${surface.name}.`
    );
  };

  const launchNerdSuite = async () => {
    const surface = state.searchWorkbench.nerdSurfaces.find(
      (entry) => entry.id === state.searchWorkbench.selectedNerdSurfaceId
    );
    if (!surface) {
      state.notice = 'Select or save a Site Search surface before launching.';
      render();
      return;
    }
    const plan = buildPortableDorkSuitePlan(
      state.searchWorkbench.draft,
      state.searchWorkbench.dorkSuiteDraft,
      getNerdSearchSurfaceTarget(surface)
    );
    const validationError = validateDorkSuitePlan(plan);
    if (validationError) {
      state.notice = validationError;
      render();
      return;
    }
    state.busy = true;
    render();
    try {
      state.snapshot = await sendRuntimeMessage('core/updateSearchWorkbench', {
        searchWorkbench: state.searchWorkbench
      });
      state.searchWorkbench = state.snapshot.searchWorkbench;
      state.searchWorkbenchDirty = false;
      state.snapshot = await sendRuntimeMessage('core/startNerdSuite', {
        surfaceId: surface.id,
        tabId: state.targetTab?.tabId
      });
      state.notice = `Site Search started ${plan.entries.length} tracked task${
        plan.entries.length === 1 ? '' : 's'
      } against ${surface.name}.`;
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const resetSearchDraft = () => {
    setSearchWorkbench(
      {
        ...state.searchWorkbench,
        draft: createDefaultSearchDraft()
      },
      {
        dirty: true,
        notice: 'Reset the search draft.'
      }
    );
  };

  const useTargetTabHost = () => {
    const host = tryGetHostname(state.targetTab?.url);
    if (!host) {
      state.notice = 'No active tab hostname is available for the search draft.';
      render();
      return;
    }

    const currentTargets = parseTargets(state.searchWorkbench.draft.targetsText);
    if (currentTargets.includes(host)) {
      state.notice = `${host} is already present in the target list.`;
      render();
      return;
    }

    const nextTargetsText = [state.searchWorkbench.draft.targetsText.trim(), host]
      .filter(Boolean)
      .join('\n');

    updateSearchDraft(
      {
        targetsText: nextTargetsText
      },
      {
        notice: `Added ${host} to the target list.`
      }
    );
  };

  const launchSearches = async () => {
    const validationError = validateSearchDraft(state.searchWorkbench.draft);
    if (validationError) {
      state.notice = validationError;
      render();
      return;
    }

    const launchPlans = buildSearchLaunchPlans(state.searchWorkbench.draft);
    if (!launchPlans.length) {
      state.notice = 'No search launches were generated from the current draft.';
      render();
      return;
    }

    state.busy = true;
    render();

    try {
      state.snapshot = await sendRuntimeMessage('core/updateSearchWorkbench', {
        searchWorkbench: state.searchWorkbench
      });
      state.searchWorkbench = state.snapshot.searchWorkbench;
      state.searchWorkbenchDirty = false;

      state.snapshot = await sendRuntimeMessage('core/startSearchSession', {
        useDefaultRecipe: false,
        tabId: state.targetTab?.tabId
      });
      state.notice = `Started ${launchPlans.length} tracked search task${launchPlans.length === 1 ? '' : 's'}.`;
    } catch (error) {
      state.notice = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const updateDraftValue = (moduleId: string, key: string, value: JsonValue) => {
    const current = state.drafts.get(moduleId) ?? {};
    state.drafts.set(moduleId, {
      ...current,
      [key]: value
    });
  };

  const render = () => {
    captureDisclosureState(state, options.container);
    const snapshot = state.snapshot;
    const latentFeatureScan = snapshot?.latentFeatureWorkbench.lastScan;
    state.flashingLatentFeatureScanId =
      state.primaryView === 'labs' &&
      latentFeatureScan &&
      latentFeatureScan.newCandidateIds.some((candidateId) =>
        latentFeatureScan.candidates.some((candidate) => candidate.id === candidateId)
      ) &&
      state.acknowledgedLatentFeatureScanId !== latentFeatureScan.scanId
        ? latentFeatureScan.scanId
        : undefined;
    const targetUrl = state.targetTab?.url;
    const targetIsHttp = isHttpUrl(targetUrl);
    const targetHasParameters = hasUrlParameters(targetUrl);
    const targetOutputValue = targetUrl
      ? formatTargetOutputPreview(targetUrl, state.targetOutputKind)
      : 'No target URL is available.';
    options.container.innerHTML = `
      <section class="ops-header stack target-output-stage" aria-labelledby="target-output-title">
        <div class="ops-header-row">
          <div class="stage-heading">
            <span class="stage-index" aria-hidden="true">[01]</span>
            <div>
              <div class="inline">
                <h1 id="target-output-title">BLANCHE · TARGET / OUTPUT</h1>
                <span class="badge">${escapeHtml(options.surfaceLabel)}</span>
              </div>
              <p class="muted">Choose a URL tool, inspect its exact output, then copy only what you need.</p>
            </div>
          </div>
          <div class="inline">
            <button class="ghost" data-action="refresh"${state.busy ? ' disabled' : ''}>Refresh</button>
          </div>
        </div>
        <div class="target-strip">
          <strong>Target tab</strong>
          <span class="muted">${
            state.targetTab
              ? `${escapeHtml(state.targetTab.title ?? '(untitled)')} [tab ${state.targetTab.tabId}]`
              : 'No inspectable tab context found.'
          }</span>
          ${
            targetUrl
              ? `<div class="target-url-tools">
                  <details class="target-url-disclosure" data-disclosure-key="target-url:${
                    state.targetTab?.tabId ?? 'unknown'
                  }">
                    <summary
                      title="Full target URL"
                      aria-label="Full target URL"
                    >Full URL</summary>
                    <code class="target-url">${escapeHtml(targetUrl)}</code>
                  </details>
                  <div class="target-copy-row" role="group" aria-label="Copy target URL data">
                    <button
                      type="button"
                      class="ghost tiny-button"
                      data-target-copy="url"
                      title="Copy the full target URL"
                      aria-label="Copy the full target URL"
                    >URL</button>
                    <button
                      type="button"
                      class="ghost tiny-button"
                      data-target-copy="params"
                      title="Copy only the target URL parameters"
                      aria-label="Copy only the target URL parameters"
                      ${targetHasParameters ? '' : 'disabled'}
                    >Params</button>
                    <button
                      type="button"
                      class="ghost tiny-button"
                      data-target-copy="get"
                      title="Copy a Burp-compatible GET request template"
                      aria-label="Copy a Burp-compatible GET request template"
                      ${targetIsHttp ? '' : 'disabled'}
                    >GET</button>
                    <button
                      type="button"
                      class="ghost tiny-button"
                      data-target-copy="post"
                      title="Copy a constructed form POST request template"
                      aria-label="Copy a constructed form POST request template"
                      ${targetIsHttp ? '' : 'disabled'}
                    >POST</button>
                  </div>
                </div>`
              : '<span class="muted target-url-unavailable">URL unavailable.</span>'
          }
        </div>
        <div class="target-output-console">
          <div class="target-output-selector">
            <label class="stack">
              <span>Output tool</span>
              <select data-target-output-select aria-controls="target-output-preview"${targetUrl ? '' : ' disabled'}>
                ${(['url', 'params', 'get', 'post'] as TargetOutputKind[])
                  .map(
                    (kind) =>
                      `<option value="${kind}"${state.targetOutputKind === kind ? ' selected' : ''}>${escapeHtml(
                        targetOutputLabel(kind)
                      )}</option>`
                  )
                  .join('')}
              </select>
            </label>
            <div class="stack">
              <span class="muted">Selected output</span>
              <strong data-target-output-label>${escapeHtml(targetOutputLabel(state.targetOutputKind))}</strong>
            </div>
          </div>
          <pre id="target-output-preview" class="search-code target-output-preview" tabindex="0"><code data-target-output-value>${escapeHtml(
            targetOutputValue
          )}</code></pre>
        </div>
        <div class="notice-line" role="status" aria-live="polite" aria-atomic="true">${escapeHtml(
          state.notice ?? ''
        )}</div>
      </section>
      ${renderPrimaryNavigation(state)}
      ${renderPrimaryView(state)}
    `;

    options.container.querySelector('[data-action="refresh"]')?.addEventListener('click', () => {
      void refresh();
    });
    const syncTargetOutputPreview = (kind: TargetOutputKind) => {
      state.targetOutputKind = kind;
      const currentTargetUrl = state.targetTab?.url;
      const outputValue = currentTargetUrl
        ? formatTargetOutputPreview(currentTargetUrl, kind)
        : 'No target URL is available.';
      const outputSelect = options.container.querySelector<HTMLSelectElement>(
        '[data-target-output-select]'
      );
      const outputLabel = options.container.querySelector<HTMLElement>(
        '[data-target-output-label]'
      );
      const outputElement = options.container.querySelector<HTMLElement>(
        '[data-target-output-value]'
      );
      if (outputSelect) outputSelect.value = kind;
      if (outputLabel) outputLabel.textContent = targetOutputLabel(kind);
      if (outputElement) outputElement.textContent = outputValue;
    };
    options.container
      .querySelector<HTMLSelectElement>('[data-target-output-select]')
      ?.addEventListener('change', (event) => {
        const kind = (event.currentTarget as HTMLSelectElement).value;
        if (isTargetOutputKind(kind)) syncTargetOutputPreview(kind);
      });
    for (const button of Array.from(options.container.querySelectorAll<HTMLButtonElement>('[data-target-copy]'))) {
      button.addEventListener('click', async () => {
        const currentTargetUrl = state.targetTab?.url;
        const copyKind = button.dataset.targetCopy;
        if (!currentTargetUrl) {
          state.notice = 'The target URL is unavailable.';
          render();
          return;
        }

        try {
          if (!isTargetOutputKind(copyKind)) {
            throw new Error('Unsupported target copy action.');
          }
          let successNotice: string;
          switch (copyKind) {
            case 'url':
              successNotice = 'Copied the full target URL.';
              break;
            case 'params':
              successNotice = 'Copied the target URL parameters.';
              break;
            case 'get':
              successNotice = 'Copied a Burp-compatible GET request template.';
              break;
            case 'post':
              successNotice = 'Copied a constructed form POST request template from the target URL parameters.';
              break;
          }

          const clipboardText = buildTargetOutput(currentTargetUrl, copyKind);
          await navigator.clipboard.writeText(clipboardText);
          syncTargetOutputPreview(copyKind);
          state.notice = successNotice;
        } catch {
          state.notice = 'Unable to copy the selected target data. Check the URL and clipboard access.';
        }
        const noticeLine = options.container.querySelector<HTMLElement>('.notice-line');
        if (noticeLine) {
          noticeLine.textContent = state.notice;
        }
      });
    }
    options.container
      .querySelector('[data-action="copy-json"]')
      ?.addEventListener('click', () => void copyLastExport());
    options.container
      .querySelector('[data-report-copy]')
      ?.addEventListener('click', () => void copyTearSheetJson());
    for (const button of Array.from(options.container.querySelectorAll<HTMLButtonElement>('[data-report-action]'))) {
      button.addEventListener('click', () => {
        const action = button.dataset.reportAction;
        if (action === 'instrumented') {
          void runAction('burp-bridge', 'collectInstrumented');
        } else if (action === 'passive') {
          void runAction('burp-bridge', 'collectPassive');
        }
      });
    }

    for (const button of Array.from(options.container.querySelectorAll<HTMLButtonElement>('[data-report-mode]'))) {
      button.addEventListener('click', () => {
        const mode = button.dataset.reportMode as ReportViewMode | undefined;
        if (mode === 'stakeholder' || mode === 'json') {
          state.reportMode = mode;
          render();
        }
      });
    }
    for (const button of Array.from(options.container.querySelectorAll<HTMLButtonElement>('[data-report-download]'))) {
      button.addEventListener('click', () => {
        const format = button.dataset.reportDownload;
        if (format === 'html' || format === 'json') {
          downloadTearSheet(format);
        }
      });
    }

    for (const button of Array.from(options.container.querySelectorAll<HTMLButtonElement>('[data-primary-view]'))) {
      button.addEventListener('click', () => {
        const view = button.dataset.primaryView as PrimaryView | undefined;
        if (view) {
          state.primaryView = view;
          if (view === 'traffic') {
            void refreshTrafficLedger();
          } else {
            render();
          }
        }
      });
    }
    options.container.querySelector('[data-home-action="run-search"]')?.addEventListener('click', () => void runAdvancedSearch());
    options.container.querySelector('[data-home-action="view-documents"]')?.addEventListener('click', () => {
      state.primaryView = 'documents';
      render();
    });
    for (const button of Array.from(options.container.querySelectorAll<HTMLButtonElement>('[data-question-id]'))) {
      button.addEventListener('click', async () => {
        const questionId = button.dataset.questionId;
        const actionId = button.dataset.questionAction;
        if (!questionId || !actionId) return;
        state.busy = true;
        render();
        try {
          state.snapshot = await sendRuntimeMessage('core/answerTesterQuestion', {
            questionId,
            actionId,
            tabId: state.targetTab?.tabId
          });
          state.notice = 'Question response saved.';
          if (actionId === 'inspect' || actionId === 'apply-probe') state.primaryView = 'labs';
        } catch (error) {
          state.notice = error instanceof Error ? error.message : String(error);
        } finally {
          state.busy = false;
          render();
        }
      });
    }
    for (const button of Array.from(options.container.querySelectorAll<HTMLButtonElement>('[data-manual-copy]'))) {
      button.addEventListener('click', async () => {
        await navigator.clipboard.writeText(button.dataset.manualCopy ?? '');
        state.notice = 'Copied the exact search string.';
        render();
      });
    }
    for (const button of Array.from(options.container.querySelectorAll<HTMLButtonElement>('[data-manual-open]'))) {
      button.addEventListener('click', () => void chrome.tabs.create({ url: button.dataset.manualOpen, active: true }));
    }
    options.container.querySelector('[data-search-settings-save]')?.addEventListener('click', async () => {
      const readNumber = (key: string) => Number(options.container.querySelector<HTMLInputElement>(`[data-search-setting="${key}"]`)?.value);
      state.busy = true;
      render();
      try {
        state.snapshot = await sendRuntimeMessage('core/updateSearchExecutionSettings', {
          settings: {
            sameEngineLaunchDelayMs: readNumber('sameEngineLaunchDelayMs'),
            sameQueryRepeatCooldownMs: readNumber('sameQueryRepeatCooldownMs'),
            maxConcurrentTasks: readNumber('maxConcurrentTasks'),
            libraryProbeConcurrency: readNumber('libraryProbeConcurrency'),
            libraryProbeDelayMs: readNumber('libraryProbeDelayMs')
          }
        });
        state.notice = 'Saved search and library throttle settings.';
      } catch (error) {
        state.notice = error instanceof Error ? error.message : String(error);
      } finally {
        state.busy = false;
        render();
      }
    });

    wireFeed();
    wireEngagementProfiles();
    wireTrafficLedger();
    wireSearchWorkbench();
    wireDocumentWorkbench();
    wireLatentFeatureWorkbench();
    wireInterestWorkbench();

    for (const button of Array.from(options.container.querySelectorAll<HTMLButtonElement>('[data-document-download]'))) {
      button.addEventListener('click', () => void runAction('document-acquisition', 'downloadDocument', {
        documentId: button.dataset.documentDownload ?? ''
      }));
    }

    const moduleList = options.container.querySelector('#module-list');
    if (moduleList && snapshot) {
      for (const module of snapshot.modules) {
        const card = renderModuleCard(
          module,
          state.drafts.get(module.descriptor.id) ?? module.settings,
          Boolean(state.targetTab?.tabId)
        );
        moduleList.appendChild(card);

        const toggle = card.querySelector<HTMLInputElement>('[data-role="toggle"]');
        toggle?.addEventListener('change', () => {
          void toggleModule(module.descriptor.id, Boolean(toggle.checked));
        });

        const save = card.querySelector<HTMLButtonElement>('[data-role="save-settings"]');
        save?.addEventListener('click', () => {
          void saveSettings(module.descriptor.id);
        });

        for (const field of module.descriptor.settingsSchema) {
          const input = card.querySelector<HTMLElement>(`[data-setting-key="${field.key}"]`);
          if (!input) {
            continue;
          }

          if (field.type === 'boolean' && input instanceof HTMLInputElement) {
            input.addEventListener('change', () => {
              updateDraftValue(module.descriptor.id, field.key, input.checked);
            });
            continue;
          }

          if (field.type === 'number' && input instanceof HTMLInputElement) {
            input.addEventListener('input', () => {
              updateDraftValue(module.descriptor.id, field.key, Number(input.value));
            });
            continue;
          }

          if ((field.type === 'select' || field.type === 'string') && input instanceof HTMLSelectElement) {
            input.addEventListener('change', () => {
              updateDraftValue(module.descriptor.id, field.key, input.value);
            });
            continue;
          }

          if (field.type === 'string' && input instanceof HTMLInputElement) {
            input.addEventListener('input', () => {
              updateDraftValue(module.descriptor.id, field.key, input.value);
            });
          }
        }

        for (const button of Array.from(card.querySelectorAll<HTMLButtonElement>('[data-command-id]'))) {
          button.addEventListener('click', () => {
            void runAction(module.descriptor.id, button.dataset.commandId ?? '');
          });
        }
      }
    }
    restoreDisclosureState(state, options.container);
    if (state.flashingLatentFeatureScanId) {
      state.acknowledgedLatentFeatureScanId = state.flashingLatentFeatureScanId;
      state.flashingLatentFeatureScanId = undefined;
    }
  };

  const wireFeed = () => {
    const filterField = options.container.querySelector<HTMLSelectElement>('[data-feed-filter="kind"]');
    filterField?.addEventListener('change', () => {
      state.feedKindFilter = (filterField.value || 'all') as ConsoleState['feedKindFilter'];
      render();
    });
  };

  const wireEngagementProfiles = () => {
    const nameField = options.container.querySelector<HTMLInputElement>('[data-profile-field="name"]');
    nameField?.addEventListener('input', () => {
      updateEngagementProfileDraft({ name: nameField.value });
    });

    const scopeNotesField = options.container.querySelector<HTMLTextAreaElement>(
      '[data-profile-field="scopeNotes"]'
    );
    scopeNotesField?.addEventListener('input', () => {
      updateEngagementProfileDraft({ scopeNotes: scopeNotesField.value });
    });

    const includeField = options.container.querySelector<HTMLTextAreaElement>(
      '[data-profile-field="includeText"]'
    );
    includeField?.addEventListener('input', () => {
      updateEngagementProfileDraft({ includeText: includeField.value });
    });

    const excludeField = options.container.querySelector<HTMLTextAreaElement>(
      '[data-profile-field="excludeText"]'
    );
    excludeField?.addEventListener('input', () => {
      updateEngagementProfileDraft({ excludeText: excludeField.value });
    });

    const reviewField = options.container.querySelector<HTMLTextAreaElement>(
      '[data-profile-field="reviewText"]'
    );
    reviewField?.addEventListener('input', () => {
      updateEngagementProfileDraft({ reviewText: reviewField.value });
    });

    const defaultDispositionField = options.container.querySelector<HTMLSelectElement>(
      '[data-profile-field="defaultDisposition"]'
    );
    defaultDispositionField?.addEventListener('change', () => {
      const disposition = defaultDispositionField.value;
      if (disposition === 'review' || disposition === 'out-of-scope' || disposition === 'unknown') {
        updateEngagementProfileDraft({
          defaultDisposition: disposition,
          scopePolicy: {
            ...state.engagementProfileDraft.scopePolicy,
            defaultDisposition: disposition
          }
        });
      }
    });

    for (const field of Array.from(
      options.container.querySelectorAll<HTMLInputElement | HTMLSelectElement>(
        '[data-scope-rule-field]'
      )
    )) {
      const eventName = field instanceof HTMLSelectElement ? 'change' : 'input';
      field.addEventListener(eventName, () => {
        const ruleIndex = Number(field.dataset.scopeRuleIndex);
        const fieldName = field.dataset.scopeRuleField;
        if (!Number.isInteger(ruleIndex) || !isScopeRuleDraftField(fieldName)) {
          return;
        }
        updateEngagementScopeRule(
          ruleIndex,
          fieldName,
          field.value,
          fieldName === 'matcherKind'
        );
      });
    }

    for (const button of Array.from(
      options.container.querySelectorAll<HTMLButtonElement>('[data-scope-rule-remove]')
    )) {
      button.addEventListener('click', () => {
        const ruleIndex = Number(button.dataset.scopeRuleRemove);
        if (Number.isInteger(ruleIndex)) {
          removeEngagementScopeRule(ruleIndex);
        }
      });
    }

    options.container
      .querySelector('[data-profile-action="save"]')
      ?.addEventListener('click', () => void saveEngagementProfile());
    options.container
      .querySelector('[data-profile-action="add-rule"]')
      ?.addEventListener('click', addEngagementScopeRule);
    options.container
      .querySelector('[data-profile-action="new"]')
      ?.addEventListener('click', resetEngagementProfileDraft);

    for (const button of Array.from(
      options.container.querySelectorAll<HTMLButtonElement>('[data-engagement-activate]')
    )) {
      button.addEventListener('click', () => {
        const profileId = button.dataset.engagementActivate;
        if (profileId) {
          void activateEngagementProfile(profileId);
        }
      });
    }

    for (const button of Array.from(
      options.container.querySelectorAll<HTMLButtonElement>('[data-engagement-delete]')
    )) {
      button.addEventListener('click', () => {
        const profileId = button.dataset.engagementDelete;
        if (profileId) {
          void deleteEngagementProfile(profileId);
        }
      });
    }

    for (const button of Array.from(
      options.container.querySelectorAll<HTMLButtonElement>('[data-engagement-edit]')
    )) {
      button.addEventListener('click', () => {
        const profileId = button.dataset.engagementEdit;
        if (profileId) {
          editEngagementProfile(profileId);
        }
      });
    }
  };

  const wireTrafficLedger = () => {
    const scopeField = options.container.querySelector<HTMLSelectElement>('[data-traffic-scope]');
    scopeField?.addEventListener('change', () => {
      const value = scopeField.value;
      if (
        value === 'all' ||
        value === 'in-scope' ||
        value === 'out-of-scope' ||
        value === 'review' ||
        value === 'unknown'
      ) {
        state.trafficScopeFilter = value;
        void refreshTrafficLedger();
      }
    });

    const scoreField = options.container.querySelector<HTMLInputElement>('[data-traffic-score]');
    scoreField?.addEventListener('change', () => {
      state.trafficMinimumScore = Math.max(0, Math.min(100, Number(scoreField.value) || 0));
      void refreshTrafficLedger();
    });

    options.container
      .querySelector('[data-traffic-action="refresh"]')
      ?.addEventListener('click', () => void refreshTrafficLedger());
    options.container
      .querySelector('[data-traffic-action="clear"]')
      ?.addEventListener('click', () => void clearTrafficLedger());
    for (const button of Array.from(
      options.container.querySelectorAll<HTMLButtonElement>('[data-traffic-download]')
    )) {
      button.addEventListener('click', () => {
        const format = button.dataset.trafficDownload;
        if (format === 'json' || format === 'jsonl') {
          void downloadTrafficLedger(format);
        }
      });
    }
  };

  const wireDocumentWorkbench = () => {
    options.container.querySelectorAll<HTMLButtonElement>('[data-doc-tab]').forEach((button) => {
      button.addEventListener('click', () => {
        const tabId = button.dataset.docTab as DocumentWorkbenchTab | undefined;
        if (tabId) {
          state.documentTab = tabId;
          render();
        }
      });
    });

    options.container.querySelectorAll<HTMLButtonElement>('[data-doc-action]').forEach((button) => {
      button.addEventListener('click', () => {
        void runDocumentAction(button.dataset.docAction ?? '');
      });
    });

    options.container
      .querySelector('[data-document-settings-action="save"]')
      ?.addEventListener('click', () => void saveSettings('document-acquisition'));

    const documentModule = state.snapshot?.modules.find(
      (module) => module.descriptor.id === 'document-acquisition'
    );
    if (documentModule) {
      for (const field of documentModule.descriptor.settingsSchema) {
        const input = options.container.querySelector<HTMLElement>(
          `[data-document-setting-key="${field.key}"]`
        );
        if (!input) {
          continue;
        }

        if (field.type === 'boolean' && input instanceof HTMLInputElement) {
          input.addEventListener('change', () => {
            updateDraftValue(documentModule.descriptor.id, field.key, input.checked);
          });
          continue;
        }

        if (field.type === 'number' && input instanceof HTMLInputElement) {
          input.addEventListener('input', () => {
            updateDraftValue(documentModule.descriptor.id, field.key, Number(input.value));
          });
          continue;
        }

        if ((field.type === 'select' || field.type === 'string') && input instanceof HTMLSelectElement) {
          input.addEventListener('change', () => {
            updateDraftValue(documentModule.descriptor.id, field.key, input.value);
          });
          continue;
        }

        if (
          field.type === 'string' &&
          (input instanceof HTMLInputElement || input instanceof HTMLTextAreaElement)
        ) {
          input.addEventListener('input', () => {
            updateDraftValue(documentModule.descriptor.id, field.key, input.value);
          });
        }
      }
    }
  };

  const wireSearchWorkbench = () => {
    options.container.querySelectorAll<HTMLButtonElement>('[data-search-tab]').forEach((button) => {
      button.addEventListener('click', () => {
        const tabId = button.dataset.searchTab as SearchWorkbenchTab | undefined;
        if (tabId) {
          state.searchTab = tabId;
          render();
        }
      });
    });

    const targetsField = options.container.querySelector<HTMLTextAreaElement>(
      '[data-search-field="targetsText"]'
    );
    targetsField?.addEventListener('input', () => {
      updateSearchDraft(
        {
          targetsText: targetsField.value
        },
        {
          rerender: false
        }
      );
      syncSearchLaunchControls();
    });
    targetsField?.addEventListener('change', () => {
      if (state.searchTab === 'suite' || state.searchTab === 'nerd') {
        render();
      }
    });

    const queryField = options.container.querySelector<HTMLTextAreaElement>(
      '[data-search-field="queryText"]'
    );
    queryField?.addEventListener('input', () => {
      updateSearchDraft(
        {
          queryText: queryField.value
        },
        {
          rerender: false
        }
      );
      syncSearchLaunchControls();
    });

    const nameField = options.container.querySelector<HTMLInputElement>('[data-search-field="name"]');
    nameField?.addEventListener('input', () => {
      updateSearchDraft(
        {
          name: nameField.value
        },
        {
          rerender: false
        }
      );
    });

    const launchModeField = options.container.querySelector<HTMLSelectElement>(
      '[data-search-field="launchMode"]'
    );
    launchModeField?.addEventListener('change', () => {
      updateSearchDraft({
        launchMode: launchModeField.value === 'per-target' ? 'per-target' : 'combined'
      });
    });

    const openInBackgroundField = options.container.querySelector<HTMLInputElement>(
      '[data-search-field="openInBackground"]'
    );
    openInBackgroundField?.addEventListener('change', () => {
      updateSearchDraft({
        openInBackground: openInBackgroundField.checked
      });
    });

    for (const button of Array.from(
      options.container.querySelectorAll<HTMLButtonElement>('[data-engine-id]')
    )) {
      button.addEventListener('click', () => {
        const engineId = button.dataset.engineId as SearchEngineId | undefined;
        if (engineId) {
          toggleSearchEngine(engineId);
        }
      });
    }

    for (const button of Array.from(
      options.container.querySelectorAll<HTMLButtonElement>('[data-operator-id]')
    )) {
      button.addEventListener('click', () => {
        const operatorId = button.dataset.operatorId;
        if (operatorId) {
          insertOperatorTemplate(operatorId);
        }
      });
    }

    options.container
      .querySelector('[data-search-action="use-tab-host"]')
      ?.addEventListener('click', () => useTargetTabHost());
    options.container
      .querySelector('[data-search-action="save-draft"]')
      ?.addEventListener('click', () => void saveSearchDraft());
    options.container
      .querySelector('[data-search-action="save-profile"]')
      ?.addEventListener('click', () => void saveSearchProfile());
    options.container
      .querySelector('[data-search-action="reset-draft"]')
      ?.addEventListener('click', () => resetSearchDraft());
    options.container
      .querySelector('[data-search-action="launch"]')
      ?.addEventListener('click', () => void launchSearches());
    options.container
      .querySelector('[data-search-action="add-custom-operator"]')
      ?.addEventListener('click', () => void addCustomOperator());
    options.container
      .querySelector('[data-search-action="launch-suite"]')
      ?.addEventListener('click', () => void launchDorkSuite());
    options.container
      .querySelector('[data-search-action="discover-nerd"]')
      ?.addEventListener('click', () => void discoverNerdSurfaces());
    options.container
      .querySelector('[data-search-action="pick-nerd"]')
      ?.addEventListener('click', () => void pickNerdSurface());
    options.container
      .querySelector('[data-search-action="save-nerd-template"]')
      ?.addEventListener('click', () => void saveManualNerdSurface());
    options.container
      .querySelector('[data-search-action="launch-nerd"]')
      ?.addEventListener('click', () => void launchNerdSuite());

    const keywordField = options.container.querySelector<HTMLTextAreaElement>(
      '[data-suite-field="keywordsText"]'
    );
    keywordField?.addEventListener('input', () => {
      updateDorkSuiteDraft(
        { keywordsText: keywordField.value },
        { rerender: false }
      );
    });
    keywordField?.addEventListener('change', () => render());

    const maxQueriesField = options.container.querySelector<HTMLInputElement>(
      '[data-suite-field="maxQueries"]'
    );
    maxQueriesField?.addEventListener('change', () => {
      updateDorkSuiteDraft({ maxQueries: Number(maxQueriesField.value) });
    });

    for (const field of Array.from(
      options.container.querySelectorAll<HTMLInputElement>('[data-suite-category]')
    )) {
      field.addEventListener('change', () => {
        const allowedCategories = new Set(DORK_SUITE_CATEGORIES.map((category) => category.id));
        const categoryIds = Array.from(
          options.container.querySelectorAll<HTMLInputElement>('[data-suite-category]:checked')
        )
          .map((entry) => entry.dataset.suiteCategory)
          .filter(
            (categoryId): categoryId is SearchWorkbenchState['dorkSuiteDraft']['categoryIds'][number] =>
              Boolean(
                categoryId &&
                  allowedCategories.has(
                    categoryId as SearchWorkbenchState['dorkSuiteDraft']['categoryIds'][number]
                  )
              )
          );
        updateDorkSuiteDraft({ categoryIds });
      });
    }

    for (const button of Array.from(
      options.container.querySelectorAll<HTMLButtonElement>('[data-nerd-highlight]')
    )) {
      button.addEventListener('click', () => {
        const candidateId = button.dataset.nerdHighlight;
        if (candidateId) void highlightNerdCandidate(candidateId);
      });
    }

    for (const button of Array.from(
      options.container.querySelectorAll<HTMLButtonElement>('[data-nerd-candidate]')
    )) {
      button.addEventListener('click', () => {
        const candidateId = button.dataset.nerdCandidate;
        if (candidateId) void saveNerdCandidate(candidateId);
      });
    }

    for (const button of Array.from(
      options.container.querySelectorAll<HTMLButtonElement>('[data-nerd-select]')
    )) {
      button.addEventListener('click', () => {
        const surfaceId = button.dataset.nerdSelect;
        if (surfaceId) void selectNerdSurface(surfaceId);
      });
    }

    for (const button of Array.from(
      options.container.querySelectorAll<HTMLButtonElement>('[data-nerd-delete]')
    )) {
      button.addEventListener('click', () => {
        const surfaceId = button.dataset.nerdDelete;
        if (surfaceId) void deleteNerdSurface(surfaceId);
      });
    }

    for (const button of Array.from(
      options.container.querySelectorAll<HTMLButtonElement>('[data-profile-load]')
    )) {
      button.addEventListener('click', () => {
        const profileId = button.dataset.profileLoad;
        if (profileId) {
          loadSearchProfile(profileId);
        }
      });
    }

    for (const button of Array.from(
      options.container.querySelectorAll<HTMLButtonElement>('[data-profile-delete]')
    )) {
      button.addEventListener('click', () => {
        const profileId = button.dataset.profileDelete;
        if (profileId) {
          void deleteSearchProfile(profileId);
        }
      });
    }

    for (const button of Array.from(
      options.container.querySelectorAll<HTMLButtonElement>('[data-custom-delete]')
    )) {
      button.addEventListener('click', () => {
        const operatorId = button.dataset.customDelete;
        if (operatorId) {
          void deleteCustomOperator(operatorId);
        }
      });
    }
  };

  const wireLatentFeatureWorkbench = () => {
    options.container
      .querySelector('[data-latent-action="discover"]')
      ?.addEventListener('click', () => void runAction('latent-features', 'discover'));
    options.container
      .querySelector('[data-latent-action="test-javascript"]')
      ?.addEventListener('click', () => void runAction('latent-features', 'testJavascript'));
    options.container
      .querySelector('[data-latent-action="restore"]')
      ?.addEventListener('click', () => void runAction('latent-features', 'restoreProbe'));

    for (const button of Array.from(
      options.container.querySelectorAll<HTMLButtonElement>(
        '[data-latent-state-candidate-id][data-latent-candidate-state]'
      )
    )) {
      button.addEventListener('click', () => {
        const candidateId = button.dataset.latentStateCandidateId;
        const requestedState = button.dataset.latentCandidateState;
        if (
          candidateId &&
          (requestedState === 'enabled' || requestedState === 'disabled')
        ) {
          void runAction('latent-features', 'setCandidateState', {
            candidateId,
            state: requestedState
          });
        }
      });
    }

    // Retain the original one-way probe control for snapshots produced by an older worker.
    for (const button of Array.from(
      options.container.querySelectorAll<HTMLButtonElement>('[data-latent-candidate-id]')
    )) {
      button.addEventListener('click', () => {
        void runAction('latent-features', 'probeCandidate', {
          candidateId: button.dataset.latentCandidateId ?? ''
        });
      });
    }
  };

  const wireInterestWorkbench = () => {
    const folderNameField = options.container.querySelector<HTMLInputElement>(
      '[data-interest-field="folderName"]'
    );
    folderNameField?.addEventListener('input', () => {
      updateInterestSettings(
        {
          folderName: folderNameField.value
        },
        {
          rerender: false
        }
      );
    });
    folderNameField?.addEventListener('change', () => {
      render();
    });

    const walkDepthField = options.container.querySelector<HTMLInputElement>(
      '[data-interest-field="walkDepth"]'
    );
    walkDepthField?.addEventListener('input', () => {
      updateInterestSettings(
        {
          walkDepth: Number(walkDepthField.value)
        },
        {
          rerender: false
        }
      );
    });
    walkDepthField?.addEventListener('change', () => {
      render();
    });

    const walkCountField = options.container.querySelector<HTMLInputElement>(
      '[data-interest-field="walkCount"]'
    );
    walkCountField?.addEventListener('input', () => {
      updateInterestSettings(
        {
          walkCount: Number(walkCountField.value)
        },
        {
          rerender: false
        }
      );
    });
    walkCountField?.addEventListener('change', () => {
      render();
    });

    const maxPredictionsField = options.container.querySelector<HTMLInputElement>(
      '[data-interest-field="maxPredictions"]'
    );
    maxPredictionsField?.addEventListener('input', () => {
      updateInterestSettings(
        {
          maxPredictions: Number(maxPredictionsField.value)
        },
        {
          rerender: false
        }
      );
    });
    maxPredictionsField?.addEventListener('change', () => {
      render();
    });

    options.container
      .querySelector('[data-interest-action="save-settings"]')
      ?.addEventListener('click', () => void saveInterestSettings());
    options.container
      .querySelector('[data-interest-action="create-folder"]')
      ?.addEventListener('click', () =>
        void runInterestAction('create-folder', 'Bound the interest bookmark folder.')
      );
    options.container
      .querySelector('[data-interest-action="bookmark-tab"]')
      ?.addEventListener('click', () =>
        void runInterestAction('bookmark-tab', 'Bookmarked the current tab as an interest sample.')
      );
    options.container
      .querySelector('[data-interest-action="analyze"]')
      ?.addEventListener('click', () =>
        void runInterestAction('analyze', 'Refreshed the interest score and Markov forecast.')
      );
  };

  const pollState = async () => {
    try {
      const [snapshot, trafficLedger] = await Promise.all([
        sendRuntimeMessage('core/getState', { includeLogs: state.primaryView === 'labs' }),
        state.primaryView === 'traffic'
          ? sendRuntimeMessage('traffic/query', {
              tabId: state.targetTab?.tabId,
              targetOrigin: tryParseOrigin(state.targetTab?.url),
              scope:
                state.trafficScopeFilter === 'all'
                  ? undefined
                  : state.trafficScopeFilter,
              minScore: state.trafficMinimumScore,
              limit: 250
            })
          : Promise.resolve(undefined)
      ]);
      state.snapshot = snapshot;
      if (trafficLedger) state.trafficLedger = trafficLedger;
      if (!state.searchWorkbenchDirty) state.searchWorkbench = snapshot.searchWorkbench;
      if (!state.interestWorkbenchDirty) state.interestWorkbench = snapshot.interestWorkbench;
      state.engagementProfiles = snapshot.engagementProfiles;
      const activeElement = document.activeElement;
      const editing =
        options.container.contains(activeElement) &&
        (activeElement instanceof HTMLInputElement ||
          activeElement instanceof HTMLTextAreaElement ||
          activeElement instanceof HTMLSelectElement);
      if (!editing) render();
    } catch {
      // A suspended/restarting MV3 service worker is retried on the next interval.
    }
  };
  window.setInterval(() => void pollState(), 1500);
  void refresh();
}

function captureDisclosureState(state: ConsoleState, container: HTMLElement): void {
  const activeElement = document.activeElement;
  const activeDisclosure =
    activeElement instanceof HTMLElement &&
    container.contains(activeElement) &&
    activeElement.matches('summary')
      ? activeElement.closest<HTMLDetailsElement>('details[data-disclosure-key]')
      : undefined;
  state.focusedDisclosureKey = activeDisclosure?.dataset.disclosureKey;

  for (const disclosure of Array.from(
    container.querySelectorAll<HTMLDetailsElement>('details[data-disclosure-key]')
  )) {
    const key = disclosure.dataset.disclosureKey;
    if (!key) continue;
    if (disclosure.open) {
      state.openDisclosureKeys.add(key);
    } else {
      state.openDisclosureKeys.delete(key);
    }
  }
}

function restoreDisclosureState(state: ConsoleState, container: HTMLElement): void {
  let focusTarget: HTMLElement | undefined;
  for (const disclosure of Array.from(
    container.querySelectorAll<HTMLDetailsElement>('details[data-disclosure-key]')
  )) {
    const key = disclosure.dataset.disclosureKey;
    if (!key) continue;
    disclosure.open = state.openDisclosureKeys.has(key);
    if (key === state.focusedDisclosureKey) {
      focusTarget = disclosure.querySelector<HTMLElement>('summary') ?? undefined;
    }
    disclosure.addEventListener('toggle', () => {
      if (disclosure.open) {
        state.openDisclosureKeys.add(key);
      } else {
        state.openDisclosureKeys.delete(key);
      }
    });
  }
  focusTarget?.focus({ preventScroll: true });
}

function getOrBuildTearSheet(state: ConsoleState): BlancheTearSheetV1 | undefined {
  if (!state.snapshot) {
    state.tearSheet = undefined;
    return undefined;
  }

  const candidate = buildTearSheetReport(state.snapshot);
  if (!candidate) {
    state.tearSheet = undefined;
    return undefined;
  }
  if (state.tearSheet?.metadata.reportId === candidate.metadata.reportId) {
    return state.tearSheet;
  }

  state.tearSheet = candidate;
  return candidate;
}

function renderPrimaryNavigation(state: ConsoleState): string {
  const openQuestions = state.snapshot?.findingsWorkbench?.questions?.filter((entry) => entry.status === 'open').length ?? 0;
  const trafficCount = state.snapshot?.trafficLedgerSummary?.entryCount ?? 0;
  return `
    <nav class="primary-nav" aria-label="BLANCHE sections">
      ${(['home', 'search', 'findings', 'traffic', 'documents', 'report', 'labs'] as PrimaryView[]).map((view) => `
        <button type="button" class="tab-button${state.primaryView === view ? ' is-active' : ''}" data-primary-view="${view}">
          ${view === 'home' ? 'Home' : view[0]?.toUpperCase() + view.slice(1)}${view === 'findings' && openQuestions > 0 ? ` (${openQuestions})` : ''}${view === 'traffic' && trafficCount > 0 ? ` (${trafficCount})` : ''}
        </button>
      `).join('')}
    </nav>
  `;
}

function renderPrimaryView(state: ConsoleState): string {
  switch (state.primaryView) {
    case 'traffic':
      return `${renderTrafficLedger(state)}${renderEngagementProfiles(state)}`;
    case 'search':
      return `${renderSearchWorkbench(state)}${renderSearchExecution(state)}`;
    case 'documents':
      return renderDocumentWorkbench(state);
    case 'findings':
      return `${renderTesterQuestions(state)}${renderFindingsWorkbench(state)}`;
    case 'report':
      return renderTearSheetReportView(state);
    case 'labs':
      return `
        <section class="panel stack labs-intro">
          <div><h2>Labs</h2><p class="muted">Technical controls, raw evidence, module settings, exports, and logs.</p></div>
        </section>
        ${renderFeed(state)}
        ${renderLatentFeatureWorkbench(state)}
        ${renderInterestWorkbench(state)}
        <section class="layout">
          <section class="panel stack"><h2>Modules</h2><div class="grid" id="module-list"></div></section>
          <section class="panel stack"><div class="inline profile-card-header"><h2>Latest Export</h2><button class="ghost" data-action="copy-json"${!state.snapshot?.lastExport ? ' disabled' : ''}>Copy JSON</button></div>${renderExportSummary(state.snapshot)}</section>
          <section class="panel stack"><h2>Recent Logs</h2>${renderLogs(state.snapshot)}</section>
        </section>
      `;
    default:
      return `
        <section class="panel stack home-hero stage-panel" aria-labelledby="run-search-stage-title">
          <div class="stage-heading">
            <span class="stage-index" aria-hidden="true">[02]</span>
            <div>
              <h2 id="run-search-stage-title">RUN SEARCH</h2>
              <p class="muted">Run the bounded advanced recipe for the active target, or review documents BLANCHE already inspected in memory.</p>
            </div>
          </div>
          <div class="home-actions">
            <button class="primary home-action" type="button" data-home-action="run-search"${state.busy ? ' disabled' : ''}>Run Search</button>
            <button class="home-action" type="button" data-home-action="view-documents">View Documents</button>
          </div>
        </section>
        ${renderTaskStatus(state)}
        ${renderTesterQuestions(state)}
        ${renderFindingsWorkbench(state, 5)}
      `;
  }
}

function renderTearSheetReportView(state: ConsoleState): string {
  const report = getOrBuildTearSheet(state);
  if (!report) {
    return `
      <section class="panel stack report-empty" data-tear-sheet-report>
        <div>
          <h2>Site Tear Sheet</h2>
          <p class="muted">Capture the active site to create a stakeholder-readable report and a full JSON evidence bundle.</p>
        </div>
        <div class="inline">
          <button class="primary" type="button" data-report-action="instrumented"${state.busy || !state.targetTab ? ' disabled' : ''}>Capture Full Site (reloads)</button>
          <button type="button" data-report-action="passive"${state.busy || !state.targetTab ? ' disabled' : ''}>Passive Snapshot</button>
        </div>
        <p class="muted">The capture is browser evidence, not a complete HTTP archive. BLANCHE records that boundary in every report.</p>
      </section>`;
  }

  const reportPageUrl = normalizePageUrl(report.target.url);
  const activePageUrl = normalizePageUrl(state.targetTab?.url);
  const targetMismatch = Boolean(reportPageUrl && activePageUrl && reportPageUrl !== activePageUrl);
  const json = JSON.stringify(report, null, 2);

  return `
    <section class="panel stack report-toolbar">
      <div class="report-toolbar-heading">
        <div>
          <div class="inline">
            <h2>Site Tear Sheet</h2>
            <span class="badge report-assessment-${escapeHtml(report.executiveSummary.assessment)}">${escapeHtml(report.executiveSummary.assessment)}</span>
          </div>
          <p class="muted">One canonical report, rendered for stakeholders or exported as full-fidelity JSON evidence.</p>
        </div>
        <div class="inline">
          <button class="primary" type="button" data-report-action="instrumented"${state.busy || !state.targetTab ? ' disabled' : ''}>Capture Full Site (reloads)</button>
          <button type="button" data-report-action="passive"${state.busy || !state.targetTab ? ' disabled' : ''}>Passive Snapshot</button>
        </div>
      </div>
      ${
        targetMismatch
          ? `<div class="report-target-warning"><strong>Showing the latest captured page.</strong> The active tab is ${escapeHtml(maskPageUrl(activePageUrl) ?? 'different')} while this report covers ${escapeHtml(maskPageUrl(reportPageUrl) ?? 'another page')}.</div>`
          : ''
      }
      <div class="report-control-row">
        <div class="tab-row" role="tablist" aria-label="Tear sheet mode">
          <button type="button" class="tab-button${state.reportMode === 'stakeholder' ? ' is-active' : ''}" data-report-mode="stakeholder">Stakeholder</button>
          <button type="button" class="tab-button${state.reportMode === 'json' ? ' is-active' : ''}" data-report-mode="json">JSON Evidence</button>
        </div>
        <div class="inline">
          <button type="button" data-report-download="html">Download HTML</button>
          <button type="button" data-report-download="json">Download JSON</button>
          <button type="button" class="ghost" data-report-copy>Copy JSON</button>
        </div>
      </div>
      <div class="report-sensitive-note">
        <strong>Assessment-sensitive</strong>
        <span>${escapeHtml(report.dataHandling.notice)}</span>
      </div>
    </section>
    ${
      state.reportMode === 'stakeholder'
        ? `<section class="report-preview">${renderTearSheetStakeholderBody(report)}</section>`
        : `
          <section class="panel stack report-json-panel" data-tear-sheet-report>
            <div>
              <h2>Full JSON Evidence</h2>
              <p class="muted">Includes the complete source capture plus site-correlated findings, searches, documents, feature evidence, and activity retained by BLANCHE.</p>
            </div>
            <textarea class="raw-json report-json" data-report-json readonly>${escapeHtml(json)}</textarea>
          </section>`
    }
  `;
}

function renderTaskStatus(state: ConsoleState): string {
  const sessions = state.snapshot?.searchExecution?.sessions ?? [];
  const latest = sessions[0];
  if (!latest) {
    return `
      <section class="panel stack task-status-panel stage-panel" aria-labelledby="live-status-stage-title">
        <div class="stage-heading">
          <span class="stage-index" aria-hidden="true">[03]</span>
          <div><h2 id="live-status-stage-title">LIVE STATUS</h2><div class="muted">No search has run yet.</div></div>
          <span class="badge">0 tasks</span>
        </div>
      </section>`;
  }
  const completed = latest.tasks.filter((task) => task.status === 'completed-results' || task.status === 'completed-no-results').length;
  const manual = latest.tasks.filter((task) => task.status === 'manual-required').length;
  const failed = latest.tasks.filter((task) => task.status === 'failed').length;
  const active = latest.tasks.length - completed - manual - failed;
  return `
    <section class="panel stack task-status-panel stage-panel" aria-labelledby="live-status-stage-title">
      <div class="stage-heading profile-card-header">
        <span class="stage-index" aria-hidden="true">[03]</span>
        <div><h2 id="live-status-stage-title">LIVE STATUS</h2><strong>${escapeHtml(latest.label)}</strong></div>
        <span class="badge">${completed}/${latest.tasks.length} complete</span>
      </div>
      <div class="summary-grid">
        <div class="panelish"><strong>Running / queued</strong><div>${active}</div></div>
        <div class="panelish"><strong>Results</strong><div>${latest.tasks.reduce((sum, task) => sum + task.resultCount, 0)}</div></div>
        <div class="panelish"><strong>Manual required</strong><div>${manual}</div></div>
        <div class="panelish"><strong>Failed</strong><div>${failed}</div></div>
      </div>
      ${renderManualSearchTasks(latest.tasks)}
    </section>
  `;
}

function renderSearchExecution(state: ConsoleState): string {
  const execution = state.snapshot?.searchExecution;
  if (!execution) return '';
  const session = execution.sessions.find((entry) => entry.id === execution.activeSessionId) ?? execution.sessions[0];
  const settings = execution.settings;
  return `
    <section class="panel stack">
      <div><h2>Tracked search results</h2><p class="muted">A result page that runs and returns zero results is complete. Anti-automation remains manual-required.</p></div>
      ${session ? `
        <div class="panelish stack">
          <div class="inline profile-card-header">
            <strong>${escapeHtml(session.label)}</strong>
            <span class="badge">${escapeHtml(session.mode ?? 'classic')}</span>
          </div>
          <div class="tag-row">
            ${(session.targets ?? (session.target ? [session.target] : []))
              .map((target) => `<span class="search-tag">target: ${escapeHtml(target)}</span>`)
              .join('')}
            ${
              session.catalogReviewedAt
                ? `<span class="search-tag">catalog: ${escapeHtml(session.catalogReviewedAt)}</span>`
                : ''
            }
          </div>
        </div>
        <div class="search-plan-list">
          ${session.tasks.map((task) => `
            <article class="profile-card stack">
              <div class="inline profile-card-header"><strong>${escapeHtml(task.dorkTitle ?? task.category.replaceAll('-', ' '))}</strong><span class="search-tag">${escapeHtml(task.status)}</span></div>
              <code class="search-code">${escapeHtml(task.query)}</code>
              <div class="tag-row">
                ${task.dialect ? `<span class="search-tag">${escapeHtml(task.dialect)}</span>` : ''}
                ${(task.operatorIds ?? []).map((operatorId) => `<span class="search-tag">${escapeHtml(operatorId)}</span>`).join('')}
                ${task.nerdSurface ? `<span class="search-tag">Site Search: ${escapeHtml(task.nerdSurface.name)}</span>` : ''}
              </div>
              ${(task.warnings ?? []).map((warning) => `<div class="status-warning">${escapeHtml(warning)}</div>`).join('')}
              ${task.error ? `<div class="status-error">${escapeHtml(task.error)}</div>` : ''}
              ${task.manualReason ? `<div class="status-warning">${escapeHtml(task.manualReason)}</div>` : ''}
              ${task.results.slice(0, 10).map((result) => `<a class="result-link" href="${escapeHtml(result.url)}" target="_blank" rel="noreferrer">${escapeHtml(result.title ?? result.url)}</a>`).join('')}
              ${
                task.results.length > 10
                  ? `<details data-disclosure-key="search-task-results:${escapeHtml(task.id)}">
                      <summary>Showing 10 of ${task.results.length} results · Show ${task.results.length - 10} more</summary>
                      <div class="stack">
                        ${task.results
                          .slice(10)
                          .map(
                            (result) =>
                              `<a class="result-link" href="${escapeHtml(result.url)}" target="_blank" rel="noreferrer">${escapeHtml(result.title ?? result.url)}</a>`
                          )
                          .join('')}
                      </div>
                    </details>`
                  : ''
              }
            </article>
          `).join('')}
        </div>
        ${renderManualSearchTasks(session.tasks)}
      ` : '<div class="muted">No tracked session yet.</div>'}
      <details class="search-subpanel" data-disclosure-key="search-throttles">
        <summary>Throttle settings</summary>
        <div class="search-grid search-grid-compact throttle-grid">
          ${renderNumberSetting('Engine spacing (ms)', 'sameEngineLaunchDelayMs', settings.sameEngineLaunchDelayMs, 0, 60000)}
          ${renderNumberSetting('Repeated query cooldown (ms)', 'sameQueryRepeatCooldownMs', settings.sameQueryRepeatCooldownMs, 0, 86400000)}
          ${renderNumberSetting('Search task threads', 'maxConcurrentTasks', settings.maxConcurrentTasks, 1, 8)}
          ${renderNumberSetting('Library probe threads', 'libraryProbeConcurrency', settings.libraryProbeConcurrency, 1, 4)}
          ${renderNumberSetting('Library probe spacing (ms)', 'libraryProbeDelayMs', settings.libraryProbeDelayMs, 100, 60000)}
        </div>
        <button class="primary" type="button" data-search-settings-save>Save throttles</button>
      </details>
    </section>
  `;
}

function renderManualSearchTasks(tasks: NonNullable<HostStateSnapshot['searchExecution']['sessions'][number]>['tasks']): string {
  const manual = tasks.filter((task) => task.status === 'manual-required');
  if (manual.length === 0) return '';
  return `<div class="stack">${manual.map((task) => `
    <article class="manual-search-card stack">
      <strong>${escapeHtml(task.engineName)} needs you</strong>
      <div class="muted">${escapeHtml(task.manualReason ?? 'Human verification interrupted automation.')}</div>
      <code class="search-code">${escapeHtml(task.query)}</code>
      <div class="inline"><button data-manual-copy="${escapeHtml(task.query)}">Copy search string</button><button class="primary" data-manual-open="${escapeHtml(task.searchUrl)}">Open search</button></div>
    </article>
  `).join('')}</div>`;
}

function renderTesterQuestions(state: ConsoleState): string {
  const questions = state.snapshot?.findingsWorkbench?.questions?.filter((entry) => entry.status === 'open') ?? [];
  const initialQuestions = questions.slice(0, 8);
  return `
    <section class="panel stack question-panel stage-panel" aria-labelledby="questions-stage-title">
      <div class="stage-heading profile-card-header">
        <span class="stage-index" aria-hidden="true">[04]</span>
        <div><h2 id="questions-stage-title">TESTER QUESTIONS</h2><p class="muted">Actionable follow-up requested by retained findings.</p></div>
        <span class="badge">${questions.length} open</span>
      </div>
      ${
        questions.length === 0
          ? '<div class="muted">No open tester questions.</div>'
          : initialQuestions.map(renderTesterQuestionCard).join('')
      }
      ${
        questions.length > initialQuestions.length
          ? `<details data-disclosure-key="tester-questions:open">
              <summary>Showing ${initialQuestions.length} of ${questions.length} questions · Show ${questions.length - initialQuestions.length} more</summary>
              <div class="stack">${questions.slice(initialQuestions.length).map(renderTesterQuestionCard).join('')}</div>
            </details>`
          : ''
      }
    </section>
  `;
}

function renderFindingsWorkbench(state: ConsoleState, limit = 100): string {
  const findings = state.snapshot?.findingsWorkbench?.findings ?? [];
  const initialFindings = findings.slice(0, limit);
  const isHomeSummary = limit === 5;
  return `
    <section class="panel stack findings-panel stage-panel stage-results" aria-labelledby="findings-stage-title">
      <div class="stage-heading profile-card-header">
        <span class="stage-index" aria-hidden="true">[05]</span>
        <div><h2 id="findings-stage-title">FINDINGS / RESULTS</h2><p class="muted">Tester-facing output from search, documents, dependency checks, archives, and shipped client features.</p></div>
        <span class="badge">${findings.length} total</span>
      </div>
      ${findings.length === 0 ? '<div class="muted">No scored findings yet.</div>' : initialFindings.map(renderFindingCard).join('')}
      ${
        findings.length > initialFindings.length && isHomeSummary
          ? `<div class="inline profile-card-header">
              <span class="muted">Showing ${initialFindings.length} of ${findings.length} findings.</span>
              <button type="button" data-primary-view="findings">View all (${findings.length})</button>
            </div>`
          : findings.length > initialFindings.length
            ? `<details data-disclosure-key="findings:remaining">
                <summary>Showing ${initialFindings.length} of ${findings.length} findings · Show ${findings.length - initialFindings.length} more</summary>
                <div class="stack">${findings.slice(initialFindings.length).map(renderFindingCard).join('')}</div>
              </details>`
            : ''
      }
    </section>
  `;
}

function renderTesterQuestionCard(
  question: HostStateSnapshot['findingsWorkbench']['questions'][number]
): string {
  return `
    <article class="question-card stack">
      <strong>${escapeHtml(question.prompt)}</strong>
      <div class="muted">${escapeHtml(question.reason)}</div>
      <div class="inline">${question.actions
        .map(
          (action) =>
            `<button type="button" class="${
              action.kind === 'inspect' || action.kind === 'follow-up' ? 'primary' : 'ghost'
            }" data-question-id="${escapeHtml(question.id)}" data-question-action="${escapeHtml(
              action.id
            )}">${escapeHtml(action.label)}</button>`
        )
        .join('')}</div>
    </article>`;
}

function renderFindingCard(
  finding: HostStateSnapshot['findingsWorkbench']['findings'][number]
): string {
  const initialEvidence = finding.evidence.slice(0, 6);
  return `
    <article class="finding-card stack severity-${escapeHtml(finding.severity)}">
      <div class="inline profile-card-header"><strong>${escapeHtml(finding.title)}</strong><span class="search-tag">${escapeHtml(finding.severity)} · ${finding.score}</span></div>
      <div>${escapeHtml(finding.summary)}</div>
      ${initialEvidence.map(renderFindingEvidence).join('')}
      ${
        finding.evidence.length > initialEvidence.length
          ? `<details data-disclosure-key="finding-evidence:${escapeHtml(finding.id)}">
              <summary>Showing ${initialEvidence.length} of ${finding.evidence.length} evidence records · Show ${finding.evidence.length - initialEvidence.length} more</summary>
              <div class="stack">${finding.evidence.slice(initialEvidence.length).map(renderFindingEvidence).join('')}</div>
            </details>`
          : ''
      }
    </article>`;
}

function renderFindingEvidence(
  evidence: HostStateSnapshot['findingsWorkbench']['findings'][number]['evidence'][number]
): string {
  return evidence.url
    ? `<a class="result-link" href="${escapeHtml(evidence.url)}" target="_blank" rel="noreferrer"><strong>${escapeHtml(evidence.label)}</strong> — ${escapeHtml(evidence.detail)}</a>`
    : `<div class="muted"><strong>${escapeHtml(evidence.label)}</strong> — ${escapeHtml(evidence.detail)}</div>`;
}

function renderNumberSetting(label: string, key: string, value: number, min: number, max: number): string {
  return `<label class="stack"><span>${escapeHtml(label)}</span><input type="number" data-search-setting="${escapeHtml(key)}" value="${value}" min="${min}" max="${max}" /></label>`;
}

function renderModuleCard(
  module: HostStateSnapshot['modules'][number],
  draftSettings: Record<string, JsonValue>,
  hasTargetTab: boolean
): HTMLElement {
  const element = document.createElement('article');
  element.className = 'module-card stack';
  element.innerHTML = `
    <header>
      <div>
        <h3>${escapeHtml(module.descriptor.name)}</h3>
        <div class="muted">${escapeHtml(module.descriptor.description)}</div>
      </div>
      <label class="inline muted">
        <input type="checkbox" data-role="toggle"${module.enabled ? ' checked' : ''} />
        Enabled
      </label>
    </header>
    <div class="inline">
      ${module.descriptor.commands
        .map(
          (command) => `
            <button class="primary" data-command-id="${escapeHtml(command.id)}"${
              !module.enabled || (command.requiresTab && !hasTargetTab) ? ' disabled' : ''
            }>
              ${escapeHtml(command.title)}
            </button>
          `
        )
        .join('')}
    </div>
    <details class="module-settings" data-disclosure-key="module-settings:${escapeHtml(
      module.descriptor.id
    )}">
      <summary>Module Settings</summary>
      <div class="grid">
        ${module.descriptor.settingsSchema
          .map((field) => renderSettingField(field, draftSettings[field.key] ?? field.defaultValue))
          .join('')}
      </div>
      <div class="inline">
        <button class="ghost" data-role="save-settings">Save Settings</button>
      </div>
    </details>
  `;

  return element;
}

function renderDocumentWorkbench(state: ConsoleState): string {
  const workbench = state.snapshot?.documentWorkbench;
  if (!workbench) {
    return '';
  }

  const activeSession = getRenderableDocumentSession(workbench);
  const sessionDocuments = workbench.documents.filter(
    (document) => document.sessionId === activeSession?.id
  );

  return `
    <section class="panel stack search-workbench">
      <div class="search-toolbar">
        <div class="stack">
          <h2>Document Center</h2>
          <p class="muted">
            ${activeSession ? escapeHtml(activeSession.label) : 'No active document session.'}
          </p>
        </div>
        <div class="inline">
          <button class="ghost" type="button" data-doc-action="startSession">New Session</button>
          <button class="primary" type="button" data-doc-action="scanCurrentPageLinks"${
            state.targetTab?.tabId ? '' : ' disabled'
          }>Scan Page</button>
          <button class="primary" type="button" data-doc-action="launchDocumentSearches"${
            state.targetTab?.tabId ? '' : ' disabled'
          }>Indexed Searches</button>
        </div>
      </div>
      <div class="tab-row" role="tablist" aria-label="Document Center sections">
        ${renderTabButton('doc', 'overview', 'Overview', state.documentTab === 'overview')}
        ${renderTabButton('doc', 'configure', 'Configure', state.documentTab === 'configure')}
      </div>
      ${
        state.documentTab === 'configure'
          ? renderDocumentConfigureTab(state)
          : renderDocumentOverviewTab(sessionDocuments, activeSession)
      }
    </section>
  `;
}

function renderDocumentOverviewTab(
  sessionDocuments: AcquiredDocument[],
  activeSession: DocumentWorkbenchState['sessions'][number] | undefined
): string {
  const acquiredCount = sessionDocuments.filter((document) => ['acquired', 'reviewed', 'downloaded'].includes(document.status)).length;
  const downloadedCount = sessionDocuments.filter((document) => document.status === 'downloaded').length;
  const interestingCount = sessionDocuments.filter(
    (document) =>
      (document.analysis?.interestingKeywords.length ?? 0) > 0 ||
      (document.analysis?.extractedUrls.length ?? 0) > 0
  ).length;

  return `
    <div class="summary-grid">
      <div class="panelish">
        <strong>Seen</strong>
        <div>${sessionDocuments.length}</div>
      </div>
      <div class="panelish">
        <strong>Inspected</strong>
        <div>${acquiredCount}</div>
      </div>
      <div class="panelish">
        <strong>Downloaded</strong>
        <div>${downloadedCount}</div>
      </div>
      <div class="panelish">
        <strong>Interesting</strong>
        <div>${interestingCount}</div>
      </div>
      <div class="panelish">
        <strong>Folder</strong>
        <div class="muted">${escapeHtml(activeSession?.folderName ?? 'none')}</div>
      </div>
    </div>
    ${renderDocumentList(sessionDocuments)}
  `;
}

function renderDocumentConfigureTab(state: ConsoleState): string {
  const documentModule = state.snapshot?.modules.find(
    (module) => module.descriptor.id === 'document-acquisition'
  );
  if (!documentModule) {
    return '<div class="muted">Document Acquisition module is not available.</div>';
  }

  const draftSettings = state.drafts.get(documentModule.descriptor.id) ?? documentModule.settings;
  return `
    <section class="search-subpanel stack">
      <div class="inline profile-card-header">
        <div>
          <h3>Acquisition Settings</h3>
          <p class="muted">Controls for automatic capture, downloads, size limits, and review keywords.</p>
        </div>
        <button class="primary" type="button" data-document-settings-action="save">Save Settings</button>
      </div>
      <div class="search-grid search-grid-compact">
        ${documentModule.descriptor.settingsSchema
          .map((field) =>
            renderDocumentSettingField(field, draftSettings[field.key] ?? field.defaultValue)
          )
          .join('')}
      </div>
      <div class="inline">
        <button class="ghost" type="button" data-doc-action="openSessionFolder">Open Folder</button>
        <button class="ghost" type="button" data-doc-action="clearDocuments">Clear Inventory</button>
      </div>
    </section>
  `;
}

function renderDocumentList(documents: AcquiredDocument[]): string {
  if (documents.length === 0) {
    return '<div class="muted">No documents captured yet. Browse document links, launch indexed searches, or scan the current page.</div>';
  }

  const initialDocuments = documents.slice(0, 30);
  return `
    <div class="document-list">
      ${initialDocuments.map((document) => renderDocumentCard(document)).join('')}
    </div>
    ${
      documents.length > initialDocuments.length
        ? `<details data-disclosure-key="documents:remaining">
            <summary>Showing ${initialDocuments.length} of ${documents.length} documents · Show ${documents.length - initialDocuments.length} more</summary>
            <div class="document-list">${documents
              .slice(initialDocuments.length)
              .map((document) => renderDocumentCard(document))
              .join('')}</div>
          </details>`
        : ''
    }
  `;
}

function renderDocumentCard(document: AcquiredDocument): string {
  const analysis = document.analysis;
  const allKeywordHits = analysis?.interestingKeywords ?? [];
  const keywordHits = allKeywordHits.slice(0, 8);
  const allExtractedUrls = analysis?.extractedUrls ?? [];
  const extractedUrls = allExtractedUrls.slice(0, 6);
  const compressionTypes = analysis?.compressionTypes ?? [];

  return `
    <article class="profile-card stack">
      <div class="inline profile-card-header">
        <strong>${escapeHtml(document.filename ?? '(unnamed document)')}</strong>
        <span class="search-tag">${escapeHtml(document.status)}</span>
      </div>
      <div class="muted">${escapeHtml(document.url)}</div>
      <div class="tag-row">
        <span class="search-tag">${escapeHtml(document.source)}</span>
        ${document.mimeType ? `<span class="search-tag">${escapeHtml(document.mimeType)}</span>` : ''}
        ${document.byteLength ? `<span class="search-tag">${formatBytes(document.byteLength)}</span>` : ''}
        ${document.sha256 ? `<span class="search-tag">${escapeHtml(document.sha256.slice(0, 12))}</span>` : ''}
        ${typeof document.interestScore === 'number' ? `<span class="search-tag interest-tag">score ${document.interestScore}</span>` : ''}
      </div>
      ${
        document.sha256 && document.sha256.length > 12
          ? `<details data-disclosure-key="document-sha256:${escapeHtml(document.id)}">
              <summary>SHA-256 shown as 12 of ${document.sha256.length} characters · Show full digest</summary>
              <code class="search-code">${escapeHtml(document.sha256)}</code>
            </details>`
          : ''
      }
      ${
        compressionTypes.length > 0
          ? `<div class="tag-row">${compressionTypes
              .map((entry) => `<span class="search-tag interest-tag">${escapeHtml(entry)}</span>`)
              .join('')}</div>`
          : ''
      }
      ${
        keywordHits.length > 0
          ? `<div class="tag-row">${keywordHits
              .map(
                (hit) =>
                  `<span class="search-tag interest-tag">${escapeHtml(hit.keyword)}:${hit.count}</span>`
              )
              .join('')}</div>`
          : ''
      }
      ${
        allKeywordHits.length > keywordHits.length
          ? `<details data-disclosure-key="document-keywords:${escapeHtml(document.id)}">
              <summary>Showing ${keywordHits.length} of ${allKeywordHits.length} keyword hits · Show ${allKeywordHits.length - keywordHits.length} more</summary>
              <div class="tag-row">${allKeywordHits
                .slice(keywordHits.length)
                .map(
                  (hit) =>
                    `<span class="search-tag interest-tag">${escapeHtml(hit.keyword)}:${hit.count}</span>`
                )
                .join('')}</div>
            </details>`
          : ''
      }
      ${
        extractedUrls.length > 0
          ? `<div class="stack">${extractedUrls
              .map((url) => `<code class="search-code">${escapeHtml(url)}</code>`)
              .join('')}</div>`
          : ''
      }
      ${
        allExtractedUrls.length > extractedUrls.length
          ? `<details data-disclosure-key="document-urls:${escapeHtml(document.id)}">
              <summary>Showing ${extractedUrls.length} of ${allExtractedUrls.length} extracted URLs · Show ${allExtractedUrls.length - extractedUrls.length} more</summary>
              <div class="stack">${allExtractedUrls
                .slice(extractedUrls.length)
                .map((url) => `<code class="search-code">${escapeHtml(url)}</code>`)
                .join('')}</div>
            </details>`
          : ''
      }
      ${document.failureReason ? `<div class="status-warning">${escapeHtml(document.failureReason)}</div>` : ''}
      ${document.queueReason ? `<div class="muted">${escapeHtml(document.queueReason)}</div>` : ''}
      ${document.downloadFilename ? `<div class="muted">${escapeHtml(document.downloadFilename)}</div>` : ''}
      ${document.status === 'reviewed' || document.status === 'acquired' ? `<div><button class="primary" type="button" data-document-download="${escapeHtml(document.id)}">Download this file</button></div>` : ''}
    </article>
  `;
}

function renderLatentFeatureWorkbench(state: ConsoleState): string {
  const workbench = state.snapshot?.latentFeatureWorkbench;
  const scan = workbench?.lastScan;
  const activeProbe = workbench?.activeProbe;
  const lastMutation = workbench?.lastMutation;
  const javascriptTest = workbench?.lastJavascriptTest;
  const javascriptTestMatchesCurrentScan = javascriptTestMatchesScan(javascriptTest, scan);
  const module = state.snapshot?.modules.find(
    (entry) => entry.descriptor.id === 'latent-features'
  );
  const currentOrigin = tryParseOrigin(state.targetTab?.url);
  const scanMatchesTarget = Boolean(scan && currentOrigin && scan.origin === currentOrigin);
  const activeProbeMatchesTarget = Boolean(
    activeProbe &&
      currentOrigin &&
      activeProbe.origin === currentOrigin &&
      activeProbe.tabId === state.targetTab?.tabId
  );
  const canDiscover = Boolean(
    module?.enabled && state.targetTab?.tabId && /^https?:/i.test(state.targetTab.url ?? '')
  );
  const candidates = scan?.candidates ?? [];
  const scriptAssessments = scan?.scriptAssessments ?? [];
  const probeableCount = candidates.filter((candidate) => candidate.probeable).length;
  const newCandidateIds = new Set(scan?.newCandidateIds ?? []);
  const orderedCandidates = [
    ...candidates.filter((candidate) => newCandidateIds.has(candidate.id)),
    ...candidates.filter((candidate) => !newCandidateIds.has(candidate.id))
  ];
  const renderedCandidates = orderedCandidates.slice(0, 100);
  const remainingCandidates = orderedCandidates.slice(renderedCandidates.length);
  const initialScriptAssessments = scriptAssessments.slice(0, 50);
  const flashNewCandidates = Boolean(
    scan && state.flashingLatentFeatureScanId === scan.scanId
  );
  const candidateInteractionBlocked =
    state.busy ||
    !module?.enabled ||
    !scanMatchesTarget ||
    Boolean(activeProbe && !activeProbeMatchesTarget);
  const renderCandidate = (candidate: (typeof candidates)[number]) =>
    renderLatentFeatureCandidate(
      candidate,
      candidateInteractionBlocked,
      activeProbe?.changes.find((change) => change.candidateId === candidate.id)?.appliedValue,
      flashNewCandidates && newCandidateIds.has(candidate.id)
    );

  return `
    <section class="panel stack latent-feature-workbench">
      <div class="search-toolbar">
        <div class="stack">
          <div class="inline">
            <h2>Feature Switchboard</h2>
            <span class="badge">JavaScript &amp; latent features</span>
            ${
              activeProbe
                ? `<span class="status-warning">${activeProbe.changes.length} local override${activeProbe.changes.length === 1 ? '' : 's'} active</span>`
                : ''
            }
          </div>
          <p class="muted">
            Discover reversible controls shipped in packed, bundled, minified, obfuscated, or
            readable JavaScript. Switch browser-local values on or off, inspect the exact virtual
            config change, and separately review what the page displayed after the toggle.
          </p>
        </div>
        <div class="inline">
          <button class="primary" data-latent-action="discover"${
            state.busy || !canDiscover ? ' disabled' : ''
          }>Analyze Current Tab</button>
          <button data-latent-action="test-javascript"${
            state.busy || !canDiscover || Boolean(activeProbe) ? ' disabled' : ''
          }>Observe Startup (reloads)</button>
          <button class="ghost" data-latent-action="restore"${
            state.busy || !activeProbeMatchesTarget ? ' disabled' : ''
          }>Restore All</button>
        </div>
      </div>
      ${
        activeProbe
          ? `
            <div class="panelish stack latent-active-overrides">
              <div class="inline profile-card-header">
                <strong>Active browser-local overrides</strong>
                <span class="muted">${escapeHtml(activeProbe.origin)}</span>
              </div>
              <div class="latent-active-change-list">
                ${activeProbe.changes
                  .map(
                    (change) =>
                      `<span><strong>${escapeHtml(change.key)}</strong> <code>${escapeHtml(
                        formatCandidateValue(change.appliedValue)
                      )}</code></span>`
                  )
                  .join('')}
              </div>
              <div class="muted">Restore All returns every listed storage value to its exact captured original.</div>
            </div>
          `
          : ''
      }
      ${
        !scan
          ? '<div class="muted">No JavaScript analysis yet. Analysis uses only the current document and script URLs the page already loaded; it does not guess URLs or enumerate endpoints.</div>'
          : `
            <div class="interest-card-grid">
              <article class="profile-card stack">
                <strong>${candidates.length}</strong>
                <span class="muted">correlated candidates</span>
              </article>
              <article class="profile-card stack">
                <strong>${probeableCount}</strong>
                <span class="muted">reversible local controls</span>
              </article>
              <article class="profile-card stack">
                <strong>${scan.stats.libraryReadCount}/${scan.stats.loadedLibraryCount}</strong>
                <span class="muted">already-loaded libraries read</span>
              </article>
              <article class="profile-card stack">
                <strong>${scan.stats.libraryThreadCount} × ${scan.stats.libraryDelayMs} ms</strong>
                <span class="muted">workers and global spacing</span>
              </article>
            </div>
            <div class="muted">
              Last scan: ${escapeHtml(scan.origin)} · ${escapeHtml(
                formatRelativeTimestamp(scan.scannedAt)
              )}${scanMatchesTarget ? '' : ' · scan does not match the current tab origin'}
            </div>
            ${
              scan.warnings.length
                ? `<details data-disclosure-key="javascript-scan-warnings:${escapeHtml(
                    scan.scanId
                  )}"><summary>${scan.warnings.length} bounded-read warning${
                    scan.warnings.length === 1 ? '' : 's'
                  }</summary><div class="stack">${scan.warnings
                    .map((warning) => `<div class="muted">${escapeHtml(warning)}</div>`)
                    .join('')}</div></details>`
                : ''
            }
            ${lastMutation ? renderLatentMutationEvidence(lastMutation, currentOrigin) : ''}
            <section class="panelish stack latent-switchboard" aria-label="Reversible feature switches">
              <div class="inline profile-card-header">
                <div>
                  <h3>Feature switches</h3>
                  <div class="muted">ON and OFF write only the candidate's reversible browser-storage value. Controls never patch a delivered bundle.</div>
                </div>
                <span class="badge">${probeableCount} reversible</span>
              </div>
              <div class="profile-list latent-candidate-list">
                ${
                  renderedCandidates.length
                    ? renderedCandidates
                        .map(renderCandidate)
                        .join('')
                    : '<div class="muted">No flag-shaped values were correlated from the current page.</div>'
                }
              </div>
              ${
                remainingCandidates.length > 0
                  ? `<details data-disclosure-key="latent-candidates:${escapeHtml(scan.scanId)}">
                      <summary>Showing ${renderedCandidates.length} of ${orderedCandidates.length} candidates · Show ${remainingCandidates.length} more</summary>
                      <div class="profile-list latent-candidate-list">${remainingCandidates
                        .map(renderCandidate)
                        .join('')}</div>
                    </details>`
                  : ''
              }
            </section>
            <section class="panelish stack javascript-analysis-results">
              <div class="inline profile-card-header">
                <div>
                  <h3>Delivered JavaScript</h3>
                  <div class="muted">Transform, likely purpose, behavior maturity, evidence, and review priority.</div>
                </div>
                <span class="badge">rubric v1</span>
              </div>
              ${
                scriptAssessments.length > 0
                  ? `
                    <div class="interest-card-grid">
                      <article class="profile-card stack"><strong>${scriptAssessments.length}</strong><span class="muted">sources assessed</span></article>
                      <article class="profile-card stack"><strong>${scriptAssessments.filter((entry) => entry.transform.detected.includes('packed') || entry.transform.detected.includes('obfuscated')).length}</strong><span class="muted">packed or obfuscated</span></article>
                      <article class="profile-card stack"><strong>${scriptAssessments.filter((entry) => entry.coverage.status !== 'complete').length}</strong><span class="muted">limited or partial</span></article>
                      <article class="profile-card stack"><strong>${scriptAssessments.filter((entry) => entry.reviewPriority.band === 'high' || entry.reviewPriority.band === 'urgent').length}</strong><span class="muted">high-priority review</span></article>
                    </div>
                    ${initialScriptAssessments.map(renderScriptPurposeAssessment).join('')}
                    ${
                      scriptAssessments.length > initialScriptAssessments.length
                        ? `<details data-disclosure-key="javascript-assessments:${escapeHtml(scan.scanId)}">
                            <summary>Showing ${initialScriptAssessments.length} of ${scriptAssessments.length} assessments · Show ${scriptAssessments.length - initialScriptAssessments.length} more</summary>
                            <div class="stack">${scriptAssessments
                              .slice(initialScriptAssessments.length)
                              .map(renderScriptPurposeAssessment)
                              .join('')}</div>
                          </details>`
                        : ''
                    }
                  `
                  : '<div class="muted">No JavaScript body was available within the current scope and collection caps.</div>'
              }
            </section>
            ${renderJavascriptFullTest(
              javascriptTest && javascriptTestMatchesCurrentScan
                ? javascriptTest
                : undefined,
              Boolean(
                javascriptTest &&
                  javascriptTest.overallStatus !== 'failed' &&
                  !javascriptTestMatchesCurrentScan
              ),
              javascriptTest?.overallStatus === 'failed' && !javascriptTestMatchesCurrentScan
                ? javascriptTest
                : undefined
            )}
          `
      }
    </section>
  `;
}

function renderScriptPurposeAssessment(
  assessment: NonNullable<
    HostStateSnapshot['latentFeatureWorkbench']['lastScan']
  >['scriptAssessments'][number]
): string {
  const allPurposes = assessment.purposeClaims.filter(
    (claim) => claim.role === 'primary' || claim.role === 'secondary'
  );
  const purposes = allPurposes.slice(0, 5);
  const allCandidates = assessment.purposeClaims.filter((claim) => claim.role === 'candidate');
  const candidates = allCandidates.slice(0, 5);
  const allBehaviors = assessment.behaviorClaims.filter((entry) => entry.maturity > 0);
  const behaviors = allBehaviors.slice(0, 6);
  const indicators = assessment.indicators.slice(0, 6);
  const evidence = assessment.evidence.slice(0, 10);
  const materialGaps = assessment.coverage.gaps.filter((entry) => entry.material);
  const transforms = assessment.transform.detected.length
    ? assessment.transform.detected
    : [assessment.transform.primary];
  const renderPurposeClaim = (claim: (typeof assessment.purposeClaims)[number]) =>
    `<div class="muted"><span class="search-tag">${escapeHtml(claim.category)} · ${escapeHtml(
      claim.role
    )} · ${escapeHtml(claim.confidence)} confidence · ${claim.score}</span> ${escapeHtml(
      claim.reason
    )}</div>`;
  const renderCandidateClaim = (claim: (typeof assessment.purposeClaims)[number]) =>
    `<div class="muted"><span class="search-tag">${escapeHtml(claim.category)} · ${escapeHtml(
      claim.confidence
    )} confidence · ${claim.score}</span> ${escapeHtml(claim.reason)}</div>`;
  const renderBehaviorClaim = (claim: (typeof assessment.behaviorClaims)[number]) =>
    `<span class="search-tag">${escapeHtml(claim.axis)} L${claim.maturity}</span>`;
  const renderIndicator = (entry: (typeof assessment.indicators)[number]) =>
    `<code class="search-code">${escapeHtml(entry.kind)}: ${escapeHtml(entry.value)}</code>`;
  const renderEvidence = (entry: (typeof assessment.evidence)[number]) =>
    `<div class="muted"><strong>${escapeHtml(entry.label)}</strong>: ${escapeHtml(
      entry.detail
    )}</div>`;
  return `
    <article class="profile-card stack javascript-assessment-card">
      <div class="inline profile-card-header">
        <div class="stack">
          <strong>${escapeHtml(assessment.artifact.label)}</strong>
          ${assessment.artifact.finalUrl || assessment.artifact.sourceUrl
            ? `<code class="search-code">${escapeHtml(maskPageUrl(assessment.artifact.finalUrl ?? assessment.artifact.sourceUrl) ?? '')}</code>`
            : ''}
        </div>
        <span class="search-tag">priority ${assessment.reviewPriority.score} · ${escapeHtml(assessment.reviewPriority.band)}</span>
      </div>
      <div class="tag-row">
        ${transforms.map((entry) => `<span class="search-tag">${escapeHtml(entry)}</span>`).join('')}
        <span class="search-tag">${escapeHtml(assessment.transform.confidence)} transform confidence</span>
        <span class="search-tag">${escapeHtml(assessment.coverage.status)} source coverage</span>
      </div>
      <div class="stack">
        <strong>Primary and secondary purpose</strong>
        <div class="stack">
          ${purposes.length
            ? purposes.map(renderPurposeClaim).join('')
            : '<span class="muted">Unknown from retained evidence.</span>'}
        </div>
        ${
          allPurposes.length > purposes.length
            ? `<details data-disclosure-key="javascript-script:${escapeHtml(
                assessment.artifact.artifactId
              )}:purpose-remaining"><summary>Showing ${purposes.length} of ${allPurposes.length} primary and secondary purpose signals · Show ${allPurposes.length - purposes.length} more</summary><div class="stack">${allPurposes
                .slice(purposes.length)
                .map(renderPurposeClaim)
                .join('')}</div></details>`
            : ''
        }
      </div>
      ${allCandidates.length
        ? `<details data-disclosure-key="javascript-script:${escapeHtml(
            assessment.artifact.artifactId
          )}:weak-purpose"><summary>${allCandidates.length} weak purpose signal${allCandidates.length === 1 ? '' : 's'}</summary><div class="stack">${candidates
            .map(renderCandidateClaim)
            .join('')}${
            allCandidates.length > candidates.length
              ? `<details data-disclosure-key="javascript-script:${escapeHtml(
                  assessment.artifact.artifactId
                )}:weak-purpose-remaining"><summary>Showing ${candidates.length} of ${allCandidates.length} weak purpose signals · Show ${allCandidates.length - candidates.length} more</summary><div class="stack">${allCandidates
                  .slice(candidates.length)
                  .map(renderCandidateClaim)
                  .join('')}</div></details>`
              : ''
          }</div></details>`
        : ''}
      ${behaviors.length
        ? `<div class="tag-row">${behaviors.map(renderBehaviorClaim).join('')}</div>${
            allBehaviors.length > behaviors.length
              ? `<details data-disclosure-key="javascript-script:${escapeHtml(
                  assessment.artifact.artifactId
                )}:behaviors-remaining"><summary>Showing ${behaviors.length} of ${allBehaviors.length} behavior claims · Show ${allBehaviors.length - behaviors.length} more</summary><div class="tag-row">${allBehaviors
                  .slice(behaviors.length)
                  .map(renderBehaviorClaim)
                  .join('')}</div></details>`
              : ''
          }`
        : ''}
      ${indicators.length
        ? `<details data-disclosure-key="javascript-script:${escapeHtml(
            assessment.artifact.artifactId
          )}:indicators"><summary>${assessment.indicators.length} sanitized indicator${assessment.indicators.length === 1 ? '' : 's'}</summary><div class="stack">${indicators
            .map(renderIndicator)
            .join('')}${
            assessment.indicators.length > indicators.length
              ? `<details data-disclosure-key="javascript-script:${escapeHtml(
                  assessment.artifact.artifactId
                )}:indicators-remaining"><summary>Showing ${indicators.length} of ${assessment.indicators.length} sanitized indicators · Show ${assessment.indicators.length - indicators.length} more</summary><div class="stack">${assessment.indicators
                  .slice(indicators.length)
                  .map(renderIndicator)
                  .join('')}</div></details>`
              : ''
          }</div></details>`
        : ''}
      <details data-disclosure-key="javascript-script:${escapeHtml(
        assessment.artifact.artifactId
      )}:evidence">
        <summary>${assessment.evidence.length} evidence record${assessment.evidence.length === 1 ? '' : 's'} · ${assessment.reviewPriority.factors.length} priority factor${assessment.reviewPriority.factors.length === 1 ? '' : 's'}</summary>
        <div class="stack">
          ${evidence.map(renderEvidence).join('')}
          ${
            assessment.evidence.length > evidence.length
              ? `<details data-disclosure-key="javascript-script:${escapeHtml(
                  assessment.artifact.artifactId
                )}:evidence-remaining"><summary>Showing ${evidence.length} of ${assessment.evidence.length} evidence records · Show ${assessment.evidence.length - evidence.length} more</summary><div class="stack">${assessment.evidence
                  .slice(evidence.length)
                  .map(renderEvidence)
                  .join('')}</div></details>`
              : ''
          }
          ${assessment.reviewPriority.factors.map((factor) => `<div class="muted">${factor.appliedWeight >= 0 ? '+' : ''}${factor.appliedWeight} ${escapeHtml(factor.reason)}</div>`).join('')}
          ${materialGaps.map((gap) => `<div class="status-warning">${escapeHtml(gap.code)}: ${escapeHtml(gap.detail)}</div>`).join('')}
          <div class="muted">Review priority ranks follow-up and is not vulnerability severity.</div>
        </div>
      </details>
      <details data-disclosure-key="javascript-script:${escapeHtml(
        assessment.artifact.artifactId
      )}:test-plan">
        <summary>${assessment.testPlan.stages.length}-stage test plan</summary>
        <div class="stack">
          ${assessment.testPlan.stages
            .map((stage) => {
              const actions = stage.actions.slice(0, 5);
              return `
                <article class="panelish stack">
                  <div class="inline profile-card-header"><strong>Stage ${stage.stage} · ${escapeHtml(stage.mode)}</strong><span class="search-tag">${escapeHtml(stage.status)}</span></div>
                  <div class="muted">${escapeHtml(stage.objective)}</div>
                  ${actions.map((action) => `<div class="muted">• ${escapeHtml(action)}</div>`).join('')}
                  ${
                    stage.actions.length > actions.length
                      ? `<details data-disclosure-key="javascript-script:${escapeHtml(
                          assessment.artifact.artifactId
                        )}:stage-${stage.stage}-actions"><summary>Showing ${actions.length} of ${stage.actions.length} stage actions · Show ${stage.actions.length - actions.length} more</summary><div class="stack">${stage.actions
                          .slice(actions.length)
                          .map((action) => `<div class="muted">• ${escapeHtml(action)}</div>`)
                          .join('')}</div></details>`
                      : ''
                  }
                  ${stage.terminationReason !== 'NONE' ? `<div class="status-warning">Stop state: ${escapeHtml(stage.terminationReason)}</div>` : ''}
                </article>`;
            })
            .join('')}
        </div>
      </details>
    </article>
  `;
}

function renderLatentMutationEvidence(
  mutation: NonNullable<HostStateSnapshot['latentFeatureWorkbench']['lastMutation']>,
  currentOrigin: string | undefined
): string {
  const mutationMatchesTarget = !currentOrigin || mutation.origin === currentOrigin;
  const pageDiff = mutation.pageDiff;
  const observedCount = pageDiff.added.length + pageDiff.changed.length + pageDiff.removed.length;

  return `
    <section class="panelish stack latent-mutation-evidence">
      <div class="inline profile-card-header">
        <div>
          <h3>Latest switch result</h3>
          <div class="muted">${escapeHtml(formatRelativeTimestamp(mutation.observedAt))} · ${escapeHtml(mutation.key)}</div>
        </div>
        <div class="tag-row">
          <span class="latent-state-pill is-${escapeHtml(mutation.requestedState)}">${escapeHtml(mutation.requestedState.toUpperCase())}</span>
          <span class="search-tag">${escapeHtml(mutation.outcome)}</span>
        </div>
      </div>
      ${
        mutationMatchesTarget
          ? ''
          : '<div class="status-warning">This result belongs to a different origin than the current target tab.</div>'
      }
      <div class="latent-diff-heading">
        <strong>Virtual code/config diff</strong>
        <span class="muted">A safe representation of the browser-storage value written. Delivered bundle bytes are not patched or rewritten.</span>
      </div>
      <div class="latent-code-diff-grid" aria-label="Virtual configuration before and after">
        <div class="latent-code-diff is-before">
          <span>Before</span>
          <pre><code><del>${escapeHtml(mutation.codeDiff.before)}</del></code></pre>
        </div>
        <div class="latent-code-diff is-after">
          <span>After</span>
          <pre><code><ins>${escapeHtml(mutation.codeDiff.after)}</ins></code></pre>
        </div>
      </div>
      <div class="muted">Captured value: ${escapeHtml(formatCandidateValue(mutation.previousValue))} → ${escapeHtml(formatCandidateValue(mutation.appliedValue))}</div>
      <div class="latent-page-diff-heading">
        <div>
          <strong>Observed after toggle</strong>
          <div class="muted">These are bounded DOM observations after the storage change and reload. Timing does not prove the toggle caused them.</div>
        </div>
        <span class="badge">${observedCount} DOM record${observedCount === 1 ? '' : 's'}</span>
      </div>
      <div class="latent-page-diff-counts">
        <span class="latent-diff-count is-added"><strong>${pageDiff.added.length}</strong> added</span>
        <span class="latent-diff-count is-changed"><strong>${pageDiff.changed.length}</strong> changed</span>
        <span class="latent-diff-count is-removed"><strong>${pageDiff.removed.length}</strong> removed</span>
        <span class="latent-diff-count"><strong>${pageDiff.highlightedCount}</strong> highlighted on page</span>
      </div>
      ${
        observedCount > 0
          ? `<div class="latent-page-diff-records">
              ${renderLatentPageDiffGroup('Added', 'added', pageDiff.added)}
              ${renderLatentPageDiffGroup('Changed', 'changed', pageDiff.changed)}
              ${renderLatentPageDiffGroup('Removed', 'removed', pageDiff.removed)}
            </div>`
          : '<div class="muted">No retained DOM selector changed inside the observation window.</div>'
      }
      ${pageDiff.truncated ? '<div class="status-warning">The DOM diff reached its retention cap; additional records were omitted.</div>' : ''}
      ${
        pageDiff.limitations.length
          ? `<details data-disclosure-key="latent-mutation-limitations:${escapeHtml(
              mutation.mutationId
            )}"><summary>${pageDiff.limitations.length} observation limitation${pageDiff.limitations.length === 1 ? '' : 's'}</summary><div class="stack">${pageDiff.limitations
              .map((limitation) => `<div class="muted">${escapeHtml(limitation)}</div>`)
              .join('')}</div></details>`
          : ''
      }
    </section>
  `;
}

function renderLatentPageDiffGroup(
  label: string,
  kind: 'added' | 'changed' | 'removed',
  entries: NonNullable<
    HostStateSnapshot['latentFeatureWorkbench']['lastMutation']
  >['pageDiff']['added']
): string {
  if (entries.length === 0) return '';

  return `
    <div class="latent-page-diff-group is-${kind}">
      <strong>${label}</strong>
      ${entries
        .map(
          (entry) => `
            <div class="latent-page-diff-record">
              <code>${escapeHtml(entry.selector)}</code>
              <span>${escapeHtml(entry.tagName)}${
                entry.parentSelector
                  ? ` · parent ${escapeHtml(entry.parentSelector)}`
                  : ''
              }</span>
            </div>
          `
        )
        .join('')}
    </div>
  `;
}

function renderJavascriptFullTest(
  test: HostStateSnapshot['latentFeatureWorkbench']['lastJavascriptTest'],
  stale = false,
  unboundFailure?: HostStateSnapshot['latentFeatureWorkbench']['lastJavascriptTest']
): string {
  if (!test) {
    return `
      <section class="panelish stack javascript-test-results">
        <div class="inline profile-card-header"><h3>Bounded startup observation</h3><span class="badge">not run</span></div>
        <div class="muted">Run one explicitly in-scope, instrumented reload to compare static claims with observed startup behavior. No controls are clicked or submitted.</div>
        ${stale ? '<div class="status-warning">The prior run belongs to a different source scan and was withheld.</div>' : ''}
        ${unboundFailure ? `<div class="status-warning"><strong>Latest startup attempt failed before a source scan was retained.</strong> ${escapeHtml(unboundFailure.cells[0]?.detail ?? unboundFailure.gaps[0] ?? 'No failure detail was retained.')} Scope: ${escapeHtml(unboundFailure.scopeDisposition)} · policy ${escapeHtml(unboundFailure.scopePolicyId ?? 'unknown')} ${escapeHtml(unboundFailure.scopePolicyVersion ?? '')}</div>` : ''}
      </section>
    `;
  }
  const observed = test.cells.filter((cell) => cell.status === 'observed').length;
  const unverifiedObserved = test.cells.filter(
    (cell) => cell.status === 'observed-unverified'
  ).length;
  const staticOnly = test.cells.filter((cell) => cell.status === 'static-only').length;
  const completedControls = test.cells.filter((cell) => cell.status === 'passed').length;
  const unresolved = test.cells.filter((cell) => cell.status === 'blocked' || cell.status === 'manual-required' || cell.status === 'failed').length;
  return `
    <section class="panelish stack javascript-test-results">
      <div class="inline profile-card-header">
        <div><h3>Bounded startup observation</h3><div class="muted">${escapeHtml(formatRelativeTimestamp(test.completedAt))} · ${escapeHtml(test.origin)}</div></div>
        <span class="badge">${escapeHtml(test.overallStatus)}</span>
      </div>
      <div class="interest-card-grid">
        <article class="profile-card stack"><strong>${observed}</strong><span class="muted">extension verified</span></article>
        <article class="profile-card stack"><strong>${unverifiedObserved}</strong><span class="muted">page-world unverified</span></article>
        <article class="profile-card stack"><strong>${staticOnly}</strong><span class="muted">static only</span></article>
        <article class="profile-card stack"><strong>${completedControls}</strong><span class="muted">controls completed</span></article>
        <article class="profile-card stack"><strong>${unresolved}</strong><span class="muted">blocked or manual</span></article>
        <article class="profile-card stack"><strong>${test.runtimeStats.trafficEntryCount}</strong><span class="muted">traffic shapes in window</span></article>
      </div>
      <div class="muted">Scope: ${escapeHtml(test.scopeDisposition)} · policy ${escapeHtml(test.scopePolicyId ?? 'unknown')} ${escapeHtml(test.scopePolicyVersion ?? '')} · instrumentation integrity: ${escapeHtml(test.instrumentationIntegrity)}</div>
      ${test.instrumentationIntegrity === 'page-world-unverified' ? '<div class="status-warning">Same-window page instrumentation can be fabricated or suppressed by the inspected page. These events remain page-world unverified and do not raise per-script behavior maturity to runtime level 3.</div>' : ''}
      <div class="profile-list">
        ${test.cells.map((cell) => `
          <article class="profile-card stack">
            <div class="inline profile-card-header"><strong>${escapeHtml(cell.title)}</strong><span class="search-tag">${escapeHtml(cell.status)}</span></div>
            <div class="muted">${escapeHtml(cell.detail)}</div>
            <div class="muted">${cell.evidenceRefs.length} retained evidence reference${cell.evidenceRefs.length === 1 ? '' : 's'} · ${cell.artifactIds.length} correlated artifact${cell.artifactIds.length === 1 ? '' : 's'}</div>
          </article>
        `).join('')}
      </div>
      <div class="muted">${test.evidence.length} sanitized runtime evidence record${test.evidence.length === 1 ? '' : 's'} persisted with this run.</div>
      ${test.gaps.length
        ? `<details data-disclosure-key="javascript-test-gaps:${escapeHtml(
            test.scanId
          )}"><summary>${test.gaps.length} coverage gap${test.gaps.length === 1 ? '' : 's'}</summary><div class="stack">${test.gaps.map((gap) => `<div class="status-warning">${escapeHtml(gap)}</div>`).join('')}</div></details>`
        : ''}
      <div class="muted">This run covers one startup path. Not observed is not evidence of absence. The matrix keeps isolated and interactive stages explicit when they require a separate environment or operator action.</div>
    </section>
  `;
}

function renderLatentFeatureCandidate(
  candidate: NonNullable<
    HostStateSnapshot['latentFeatureWorkbench']['lastScan']
  >['candidates'][number],
  interactionBlocked: boolean,
  activeValue: JsonValue | undefined,
  newlyDiscovered: boolean
): string {
  const sourceLabels = Array.from(
    new Set(candidate.evidence.map((evidence) => evidence.sourceKind))
  );
  const currentValue = activeValue !== undefined ? activeValue : candidate.currentValue;
  const enabled = latentFeatureValuesEqual(currentValue, candidate.enabledValue);
  const disabled = latentFeatureValuesEqual(currentValue, candidate.disabledValue);
  const visibleState = enabled ? 'enabled' : disabled ? 'disabled' : 'observed';
  const canSetEnabled = Boolean(
    candidate.probeable && candidate.storageLocation && candidate.enabledValue !== undefined
  );
  const canSetDisabled = Boolean(
    candidate.probeable && candidate.storageLocation && candidate.disabledValue !== undefined
  );
  const location = candidate.storageLocation
    ? `${candidate.storageLocation.area}.${candidate.storageLocation.storageKey}${
        candidate.storageLocation.jsonPath.length
          ? ` → ${candidate.storageLocation.jsonPath.join('.')}`
          : ''
      }`
    : candidate.controlSurface;
  return `
    <article class="profile-card stack latent-switch-card is-${visibleState}${
      newlyDiscovered ? ' is-newly-discovered' : ''
    }">
      <div class="inline profile-card-header">
        <div class="stack latent-switch-title">
          <strong>${escapeHtml(candidate.key)}</strong>
          <span class="muted">${escapeHtml(location)}</span>
        </div>
        <div class="tag-row">
          ${newlyDiscovered ? '<span class="latent-new-badge">New</span>' : ''}
          <span class="latent-state-pill is-${visibleState}">${
            visibleState === 'enabled' ? 'ON' : visibleState === 'disabled' ? 'OFF' : 'Observed'
          }</span>
          <span class="search-tag">${escapeHtml(candidate.confidence)}</span>
        </div>
      </div>
      <div class="tag-row">
        ${sourceLabels
          .map((label) => `<span class="search-tag">${escapeHtml(label)}</span>`)
          .join('')}
        ${
          candidate.status !== 'discovered'
            ? `<span class="search-tag">${escapeHtml(candidate.status)}</span>`
            : ''
        }
      </div>
      <div class="latent-current-config">
        <span class="muted">Current browser-local value</span>
        <code>${escapeHtml(formatCandidateValue(currentValue))}</code>
      </div>
      ${
        candidate.evidence[0]
          ? `<div class="muted">${escapeHtml(candidate.evidence[0].detail)}</div>`
          : ''
      }
      ${
        canSetEnabled || canSetDisabled
          ? `
            <div class="latent-switch-control" role="group" aria-label="Change ${escapeHtml(candidate.key)} state">
              <button
                type="button"
                class="latent-state-button is-on${enabled ? ' is-active' : ''}"
                data-latent-state-candidate-id="${escapeHtml(candidate.id)}"
                data-latent-candidate-state="enabled"
                aria-pressed="${enabled ? 'true' : 'false'}"
                ${interactionBlocked || !canSetEnabled ? 'disabled' : ''}
              >ON</button>
              <button
                type="button"
                class="latent-state-button is-off${disabled ? ' is-active' : ''}"
                data-latent-state-candidate-id="${escapeHtml(candidate.id)}"
                data-latent-candidate-state="disabled"
                aria-pressed="${disabled ? 'true' : 'false'}"
                ${interactionBlocked || !canSetDisabled ? 'disabled' : ''}
              >OFF</button>
            </div>
            <div class="latent-switch-values">
              <span>ON <code>${escapeHtml(formatCandidateValue(candidate.enabledValue))}</code></span>
              <span>OFF <code>${escapeHtml(formatCandidateValue(candidate.disabledValue))}</code></span>
            </div>
          `
          : candidate.probeable
            ? `<div class="inline">
                <button class="ghost" data-latent-candidate-id="${escapeHtml(candidate.id)}"${
                  interactionBlocked ? ' disabled' : ''
                }>Apply Suggested (legacy)</button>
                <span class="muted">This older candidate does not expose separate ON and OFF values.</span>
              </div>`
            : '<div class="muted">Observe only — no reversible browser-storage control was verified.</div>'
      }
    </article>
  `;
}

function latentFeatureValuesEqual(
  left: JsonValue | undefined,
  right: JsonValue | undefined
): boolean {
  if (left === undefined || right === undefined) return false;
  return JSON.stringify(left) === JSON.stringify(right);
}

function getRenderableDocumentSession(
  workbench: DocumentWorkbenchState
): DocumentWorkbenchState['sessions'][number] | undefined {
  return (
    workbench.sessions.find((session) => session.id === workbench.activeSessionId) ??
    workbench.sessions[0]
  );
}

function renderTabButton(
  scope: 'search' | 'doc',
  tabId: string,
  label: string,
  selected: boolean
): string {
  const dataAttribute = scope === 'search' ? 'data-search-tab' : 'data-doc-tab';
  return `
    <button
      type="button"
      class="tab-button${selected ? ' is-active' : ''}"
      ${dataAttribute}="${escapeHtml(tabId)}"
      role="tab"
      aria-selected="${selected ? 'true' : 'false'}"
    >
      ${escapeHtml(label)}
    </button>
  `;
}

const FEED_KIND_LABELS: Record<FeedEntryKind, string> = {
  'burp-capture': 'Burp Capture',
  'osint-seed': 'OSINT Seed',
  'osint-report': 'OSINT Report',
  'document-hit': 'Document Hit',
  'interest-score': 'Interest Score',
  'javascript-analysis': 'JavaScript Analysis',
  'latent-feature': 'Latent Feature'
};

const FEED_KIND_ORDER: FeedEntryKind[] = [
  'osint-seed',
  'osint-report',
  'document-hit',
  'javascript-analysis',
  'latent-feature',
  'interest-score',
  'burp-capture'
];

interface FeedHostGroup {
  host: string;
  entries: FeedEntry[];
  latestAt: string;
}

function renderFeed(state: ConsoleState): string {
  const allEntries = state.snapshot?.feed ?? [];
  const filtered =
    state.feedKindFilter === 'all'
      ? allEntries
      : allEntries.filter((entry) => entry.kind === state.feedKindFilter);
  const groups = groupFeedByHost(filtered);

  return `
    <section class="panel stack feed-panel">
      <div class="inline profile-card-header">
        <div>
          <h2>Feed</h2>
          <p class="muted">
            Chromium-only captures, auto-seeded OSINT, document keyword hits, and interest scores —
            merged and grouped by host, instead of hunting across separate tabs.
          </p>
        </div>
        <span class="muted">${filtered.length} of ${allEntries.length} shown</span>
      </div>
      <label class="stack search-field-wide">
        <span>Filter by kind</span>
        <select data-feed-filter="kind">
          <option value="all"${state.feedKindFilter === 'all' ? ' selected' : ''}>All kinds</option>
          ${FEED_KIND_ORDER.map(
            (kind) =>
              `<option value="${kind}"${state.feedKindFilter === kind ? ' selected' : ''}>${escapeHtml(
                FEED_KIND_LABELS[kind]
              )}</option>`
          ).join('')}
        </select>
      </label>
      ${
        groups.length === 0
          ? '<div class="muted">No feed entries yet. Auto-capture, OSINT seeding, document review, and interest scoring all report here as they run.</div>'
          : `<div class="profile-list">${groups.map((group) => renderFeedHostGroup(group)).join('')}</div>`
      }
    </section>
  `;
}

function groupFeedByHost(entries: FeedEntry[]): FeedHostGroup[] {
  const groups = new Map<string, FeedEntry[]>();
  for (const entry of entries) {
    const key = entry.host ?? '(no host)';
    const group = groups.get(key);
    if (group) {
      group.push(entry);
    } else {
      groups.set(key, [entry]);
    }
  }

  return [...groups.entries()]
    .map(([host, groupEntries]) => ({
      host,
      // Feed entries are stored most-recent-first already (PersistentFeedManager unshifts).
      entries: groupEntries,
      latestAt: groupEntries[0]?.createdAt ?? ''
    }))
    .sort((left, right) => right.latestAt.localeCompare(left.latestAt));
}

function renderFeedHostGroup(group: FeedHostGroup): string {
  return `
    <article class="profile-card stack">
      <div class="inline profile-card-header">
        <strong>${escapeHtml(group.host)}</strong>
        <span class="muted">${group.entries.length} entr${group.entries.length === 1 ? 'y' : 'ies'}</span>
      </div>
      ${group.entries.map((entry) => renderFeedEntry(entry)).join('')}
    </article>
  `;
}

function renderFeedEntry(entry: FeedEntry): string {
  return `
    <div class="stack">
      <div class="tag-row">
        <span class="search-tag">${escapeHtml(FEED_KIND_LABELS[entry.kind] ?? entry.kind)}</span>
        ${entry.severity ? `<span class="search-tag">${escapeHtml(entry.severity)}</span>` : ''}
        <span class="muted">${escapeHtml(formatRelativeTimestamp(entry.createdAt))}</span>
      </div>
      <div>${escapeHtml(entry.title)}</div>
      ${entry.detail ? `<div class="muted">${escapeHtml(entry.detail)}</div>` : ''}
    </div>
  `;
}

function renderTrafficLedger(state: ConsoleState): string {
  const { entries, summary } = state.trafficLedger;
  const totalMatchedEntries = state.trafficLedger.totalMatchedEntries ?? entries.length;
  const queryTruncated = state.trafficLedger.truncated === true;
  const highPriorityCount = summary.byPriority.high + summary.byPriority.urgent;
  return `
    <section class="panel stack traffic-ledger">
      <div class="traffic-toolbar">
        <div>
          <div class="inline">
            <h2>Traffic Ledger</h2>
            <span class="badge">Priority model v1</span>
          </div>
          <p class="muted">Scope-qualified endpoint inventory for downstream triage.</p>
        </div>
        <div class="inline">
          <button class="ghost" type="button" data-traffic-action="refresh"${state.busy ? ' disabled' : ''}>Refresh</button>
          <button type="button" data-traffic-download="json"${state.busy ? ' disabled' : ''}>JSON</button>
          <button type="button" data-traffic-download="jsonl"${state.busy ? ' disabled' : ''}>JSONL</button>
          <button class="ghost" type="button" data-traffic-action="clear"${state.busy || summary.entryCount === 0 ? ' disabled' : ''}>Clear</button>
        </div>
      </div>
      <div class="summary-grid traffic-summary-grid">
        <div class="panelish"><strong>Endpoints</strong><div>${summary.entryCount}</div></div>
        <div class="panelish"><strong>In scope</strong><div>${summary.byScope['in-scope']}</div></div>
        <div class="panelish"><strong>High / urgent</strong><div>${highPriorityCount}</div></div>
        <div class="panelish"><strong>Highest priority</strong><div>${summary.highestScore}</div></div>
      </div>
      <div class="traffic-filters">
        <label class="stack">
          <span>Scope</span>
          <select data-traffic-scope>
            ${(['all', 'in-scope', 'review', 'unknown', 'out-of-scope'] as const)
              .map(
                (scope) =>
                  `<option value="${scope}"${state.trafficScopeFilter === scope ? ' selected' : ''}>${
                    scope === 'all'
                      ? 'All dispositions'
                      : scope
                          .split('-')
                          .map((part) => part[0]?.toUpperCase() + part.slice(1))
                          .join(' ')
                  }</option>`
              )
              .join('')}
          </select>
        </label>
        <label class="stack">
          <span>Minimum score</span>
          <input data-traffic-score type="number" min="0" max="100" step="5" value="${state.trafficMinimumScore}" />
        </label>
        <div class="muted traffic-filter-result">Showing ${entries.length}${queryTruncated ? ` of ${totalMatchedEntries}` : ''} method-aware endpoint${totalMatchedEntries === 1 ? '' : 's'}.</div>
      </div>
      ${
        queryTruncated
          ? '<div class="status-warning">The current query reached its display limit. JSON/JSONL exports report retained and omitted coverage explicitly.</div>'
          : ''
      }
      ${
        entries.length === 0
          ? '<div class="muted">No traffic matches the current target and filters.</div>'
          : `
            <div class="traffic-table-wrap">
              <table class="traffic-table">
                <thead>
                  <tr>
                    <th>Priority</th>
                    <th>Scope</th>
                    <th>Method</th>
                    <th>Endpoint</th>
                    <th>Roles</th>
                    <th>Status</th>
                    <th>Seen</th>
                  </tr>
                </thead>
                <tbody>${entries.map(renderTrafficLedgerRow).join('')}</tbody>
              </table>
            </div>
          `
      }
    </section>
  `;
}

function renderTrafficLedgerRow(entry: TrafficLedgerEntryV1): string {
  const statusCodes = entry.observation.statusCodes.length
    ? entry.observation.statusCodes.join(', ')
    : 'unknown';
  const roles = entry.classification.roles.length
    ? entry.classification.roles.join(', ')
    : 'other';
  return `
    <tr>
      <td>
        <strong class="traffic-priority traffic-priority-${escapeHtml(entry.priority.band)}">${entry.priority.score}</strong>
        <small>${escapeHtml(entry.priority.band)}</small>
      </td>
      <td><span class="traffic-scope traffic-scope-${escapeHtml(entry.scope.disposition)}">${escapeHtml(entry.scope.disposition)}</span></td>
      <td><code>${escapeHtml(entry.endpoint.method)}</code></td>
      <td class="traffic-endpoint-cell">
        <code>${escapeHtml(formatTrafficEndpoint(entry))}</code>
        ${renderTrafficEntryDetail(entry)}
      </td>
      <td>${escapeHtml(roles)}</td>
      <td>${escapeHtml(statusCodes)}</td>
      <td>${entry.observation.count}</td>
    </tr>
  `;
}

function renderTrafficEntryDetail(entry: TrafficLedgerEntryV1): string {
  const factors = entry.priority.factors.length
    ? entry.priority.factors
        .map(
          (factor) =>
            `<li><code>${factor.delta >= 0 ? '+' : ''}${factor.delta}</code> ${escapeHtml(factor.reason)}</li>`
        )
        .join('')
    : '<li>No priority factors matched.</li>';
  const requestFields = entry.observation.requestBodyFieldNames?.join(', ') || 'none';
  const requestHeaders = entry.observation.requestHeaderNames?.join(', ') || 'none';
  const responseHeaders = entry.observation.responseHeaderNames?.join(', ') || 'none';
  return `
    <details class="traffic-detail" data-disclosure-key="traffic:${escapeHtml(entry.entryId)}">
      <summary>Evidence and score factors</summary>
      <dl>
        <div><dt>Policy</dt><dd>${escapeHtml(entry.scope.policyId)} v${escapeHtml(entry.scope.policyVersion)}</dd></div>
        <div><dt>Boundary</dt><dd>${escapeHtml(entry.classification.boundary)}</dd></div>
        <div><dt>Environment</dt><dd>${escapeHtml(entry.classification.environment)}</dd></div>
        <div><dt>Request fields</dt><dd>${escapeHtml(requestFields)}</dd></div>
        <div><dt>Request headers</dt><dd>${escapeHtml(requestHeaders)}</dd></div>
        <div><dt>Response headers</dt><dd>${escapeHtml(responseHeaders)}</dd></div>
      </dl>
      <ul>${factors}</ul>
    </details>
  `;
}

function formatTrafficEndpoint(entry: TrafficLedgerEntryV1): string {
  const defaultPort =
    (entry.endpoint.scheme === 'https' || entry.endpoint.scheme === 'wss') ? 443 : 80;
  const port = entry.endpoint.port === defaultPort ? '' : `:${entry.endpoint.port}`;
  const query = entry.endpoint.queryParameterNames.length
    ? `?${entry.endpoint.queryParameterNames.join('&')}`
    : '';
  return `${entry.endpoint.scheme}://${entry.endpoint.host}${port}${entry.endpoint.pathTemplate}${query}`;
}

function renderEngagementProfiles(state: ConsoleState): string {
  const profileCount = state.engagementProfiles.savedProfiles.length;
  return `
    <section class="panel stack engagement-profiles">
      <div class="inline profile-card-header">
        <div>
          <div class="inline">
            <h2>Scope Policies</h2>
            ${
              state.engagementProfiles.activeProfileId
                ? '<span class="badge">Active policy</span>'
                : '<span class="status-warning">No active policy</span>'
            }
          </div>
          <p class="muted">
            Scope rules and module settings are activated together as one engagement profile.
          </p>
        </div>
        <span class="muted">${profileCount} stored</span>
      </div>
      <div class="search-grid search-grid-wide">
        <label class="stack search-field-wide">
          <span>Profile Name</span>
          <input
            type="text"
            data-profile-field="name"
            placeholder="Web App ProdPT - External Recon"
            value="${escapeHtml(state.engagementProfileDraft.name)}"
          />
        </label>
        <label class="stack search-field-wide">
          <span>Scope Notes</span>
          <textarea
            class="search-textarea"
            data-profile-field="scopeNotes"
            placeholder="Authorization, ownership, dates, ticket, and operator notes"
          >${escapeHtml(state.engagementProfileDraft.scopeNotes)}</textarea>
        </label>
      </div>
      ${renderStructuredScopePolicyEditor(state.engagementProfileDraft.scopePolicy)}
      <div class="search-grid search-grid-wide">
        <label class="stack search-field-wide">
          <span>Bulk Add In-Scope Patterns</span>
          <textarea
            class="search-textarea"
            data-profile-field="includeText"
            placeholder="example.com&#10;*.example.com&#10;POST https://api.example.com/v1/"
          >${escapeHtml(state.engagementProfileDraft.includeText)}</textarea>
        </label>
        <label class="stack search-field-wide">
          <span>Bulk Add Out-of-Scope Patterns</span>
          <textarea
            class="search-textarea"
            data-profile-field="excludeText"
            placeholder="payments.example.com&#10;10.0.0.0/8"
          >${escapeHtml(state.engagementProfileDraft.excludeText)}</textarea>
        </label>
        <label class="stack search-field-wide">
          <span>Bulk Add Review Patterns</span>
          <textarea
            class="search-textarea"
            data-profile-field="reviewText"
            placeholder="review.example.com schemes=https ports=443"
          >${escapeHtml(state.engagementProfileDraft.reviewText)}</textarea>
        </label>
        <label class="stack">
          <span>Unmatched Traffic</span>
          <select data-profile-field="defaultDisposition">
            <option value="review"${state.engagementProfileDraft.defaultDisposition === 'review' ? ' selected' : ''}>Review</option>
            <option value="out-of-scope"${state.engagementProfileDraft.defaultDisposition === 'out-of-scope' ? ' selected' : ''}>Out of scope</option>
            <option value="unknown"${state.engagementProfileDraft.defaultDisposition === 'unknown' ? ' selected' : ''}>Unknown</option>
          </select>
        </label>
      </div>
      <div class="inline">
        <button type="button" data-profile-action="add-rule">Add Rule</button>
        <button class="primary" type="button" data-profile-action="save"${
          state.busy ? ' disabled' : ''
        }>Save Scope and Module Profile</button>
        <button class="ghost" type="button" data-profile-action="new">New Profile</button>
      </div>
      ${renderEngagementProfileList(state.engagementProfiles)}
    </section>
  `;
}

function renderStructuredScopePolicyEditor(policy: ScopePolicy): string {
  return `
    <div class="stack">
      <div class="inline profile-card-header">
        <h3>Structured Scope Rules</h3>
        <span class="muted">${policy.rules.length} rule${policy.rules.length === 1 ? '' : 's'}</span>
      </div>
      ${
        policy.rules.length
          ? policy.rules.map((rule, ruleIndex) => renderStructuredScopeRule(rule, ruleIndex)).join('')
          : '<div class="muted">No structured scope rules.</div>'
      }
    </div>
  `;
}

function renderStructuredScopeRule(rule: TrafficScopeRuleV1, ruleIndex: number): string {
  const matcherValue = getScopeMatcherValue(rule.matcher);
  const supportsConstraints = rule.matcher.kind !== 'url-prefix';
  return `
    <fieldset class="search-subpanel stack scope-rule-card">
      <legend>Rule ${ruleIndex + 1}</legend>
      <div class="inline">
        <code>${escapeHtml(rule.ruleId)}</code>
        <span class="search-tag">source: ${escapeHtml(rule.source)}</span>
      </div>
      <div class="search-grid search-grid-compact">
        <label class="stack">
          <span>Disposition</span>
          <select data-scope-rule-index="${ruleIndex}" data-scope-rule-field="disposition">
            <option value="in-scope"${rule.disposition === 'in-scope' ? ' selected' : ''}>In scope</option>
            <option value="out-of-scope"${rule.disposition === 'out-of-scope' ? ' selected' : ''}>Out of scope</option>
            <option value="review"${rule.disposition === 'review' ? ' selected' : ''}>Review</option>
          </select>
        </label>
        <label class="stack">
          <span>Priority</span>
          <input
            type="number"
            step="1"
            data-scope-rule-index="${ruleIndex}"
            data-scope-rule-field="priority"
            value="${escapeHtml(String(rule.priority))}"
          />
        </label>
        <label class="stack">
          <span>Matcher</span>
          <select data-scope-rule-index="${ruleIndex}" data-scope-rule-field="matcherKind">
            <option value="exact-host"${rule.matcher.kind === 'exact-host' ? ' selected' : ''}>Exact host</option>
            <option value="wildcard-subdomain"${rule.matcher.kind === 'wildcard-subdomain' ? ' selected' : ''}>Wildcard subdomain</option>
            <option value="url-prefix"${rule.matcher.kind === 'url-prefix' ? ' selected' : ''}>URL prefix</option>
            <option value="ipv4-cidr"${rule.matcher.kind === 'ipv4-cidr' ? ' selected' : ''}>IPv4 CIDR</option>
          </select>
        </label>
        <label class="stack">
          <span>Matcher Value</span>
          <input
            type="text"
            data-scope-rule-index="${ruleIndex}"
            data-scope-rule-field="matcherValue"
            value="${escapeHtml(matcherValue)}"
          />
        </label>
        <label class="stack">
          <span>Methods</span>
          <input
            type="text"
            data-scope-rule-index="${ruleIndex}"
            data-scope-rule-field="methods"
            placeholder="GET, POST"
            value="${escapeHtml(rule.methods?.join(', ') ?? '')}"
          />
        </label>
        ${
          supportsConstraints
            ? `
                <label class="stack">
                  <span>Schemes</span>
                  <input
                    type="text"
                    data-scope-rule-index="${ruleIndex}"
                    data-scope-rule-field="schemes"
                    placeholder="https, wss"
                    value="${escapeHtml(getScopeMatcherSchemes(rule.matcher).join(', '))}"
                  />
                </label>
                <label class="stack">
                  <span>Ports</span>
                  <input
                    type="text"
                    data-scope-rule-index="${ruleIndex}"
                    data-scope-rule-field="ports"
                    placeholder="443, 8443"
                    value="${escapeHtml(getScopeMatcherPorts(rule.matcher).join(', '))}"
                  />
                </label>
              `
            : ''
        }
        <label class="stack search-field-wide">
          <span>Note</span>
          <input
            type="text"
            data-scope-rule-index="${ruleIndex}"
            data-scope-rule-field="note"
            value="${escapeHtml(rule.note ?? '')}"
          />
        </label>
      </div>
      <div class="inline">
        <button
          class="ghost"
          type="button"
          data-scope-rule-remove="${ruleIndex}"
        >Remove Rule</button>
      </div>
    </fieldset>
  `;
}

function isScopeRuleDraftField(value: string | undefined): value is ScopeRuleDraftField {
  return (
    value === 'priority' ||
    value === 'disposition' ||
    value === 'matcherKind' ||
    value === 'matcherValue' ||
    value === 'schemes' ||
    value === 'ports' ||
    value === 'methods' ||
    value === 'note'
  );
}

function updateScopeRuleDraftField(
  rule: TrafficScopeRuleV1,
  field: ScopeRuleDraftField,
  value: string
): TrafficScopeRuleV1 {
  switch (field) {
    case 'priority':
      return { ...rule, priority: value.trim() ? Number(value) : Number.NaN };
    case 'disposition':
      return value === 'in-scope' || value === 'out-of-scope' || value === 'review'
        ? { ...rule, disposition: value }
        : rule;
    case 'matcherKind':
      return isScopeMatcherKind(value)
        ? { ...rule, matcher: changeScopeMatcherKind(rule.matcher, value) }
        : rule;
    case 'matcherValue':
      return { ...rule, matcher: updateScopeMatcherValue(rule.matcher, value) };
    case 'schemes':
      return rule.matcher.kind === 'url-prefix'
        ? rule
        : {
            ...rule,
            matcher: {
              ...rule.matcher,
              schemes: parseTokenList(value) as TrafficScheme[]
            }
          };
    case 'ports':
      return rule.matcher.kind === 'url-prefix'
        ? rule
        : {
            ...rule,
            matcher: {
              ...rule.matcher,
              ports: parseTokenList(value).map(Number)
            }
          };
    case 'methods':
      return { ...rule, methods: parseTokenList(value) };
    case 'note':
      return { ...rule, note: value };
  }
}

function isScopeMatcherKind(value: string): value is TrafficScopeRuleMatcherV1['kind'] {
  return (
    value === 'exact-host' ||
    value === 'wildcard-subdomain' ||
    value === 'url-prefix' ||
    value === 'ipv4-cidr'
  );
}

function changeScopeMatcherKind(
  matcher: TrafficScopeRuleMatcherV1,
  kind: TrafficScopeRuleMatcherV1['kind']
): TrafficScopeRuleMatcherV1 {
  const value = getScopeMatcherValue(matcher);
  const constraints =
    matcher.kind === 'url-prefix'
      ? {}
      : {
          schemes: matcher.schemes ? [...matcher.schemes] : undefined,
          ports: matcher.ports ? [...matcher.ports] : undefined
        };
  switch (kind) {
    case 'exact-host':
      return { kind, hostname: value, ...constraints };
    case 'wildcard-subdomain':
      return { kind, baseHostname: value.replace(/^\*\./, ''), ...constraints };
    case 'url-prefix':
      return { kind, prefix: value };
    case 'ipv4-cidr':
      return { kind, cidr: value, ...constraints };
  }
}

function updateScopeMatcherValue(
  matcher: TrafficScopeRuleMatcherV1,
  value: string
): TrafficScopeRuleMatcherV1 {
  switch (matcher.kind) {
    case 'exact-host':
      return { ...matcher, hostname: value };
    case 'wildcard-subdomain':
      return { ...matcher, baseHostname: value.replace(/^\*\./, '') };
    case 'url-prefix':
      return { ...matcher, prefix: value };
    case 'ipv4-cidr':
      return { ...matcher, cidr: value };
  }
}

function getScopeMatcherValue(matcher: TrafficScopeRuleMatcherV1): string {
  switch (matcher.kind) {
    case 'exact-host':
      return matcher.hostname;
    case 'wildcard-subdomain':
      return matcher.baseHostname;
    case 'url-prefix':
      return matcher.prefix;
    case 'ipv4-cidr':
      return matcher.cidr;
  }
}

function getScopeMatcherSchemes(matcher: TrafficScopeRuleMatcherV1): TrafficScheme[] {
  return matcher.kind === 'url-prefix' ? [] : (matcher.schemes ?? []);
}

function getScopeMatcherPorts(matcher: TrafficScopeRuleMatcherV1): number[] {
  return matcher.kind === 'url-prefix' ? [] : (matcher.ports ?? []);
}

function parseTokenList(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function renderEngagementProfileList(engagementProfiles: EngagementProfilesState): string {
  if (engagementProfiles.savedProfiles.length === 0) {
    return '<div class="muted">No engagement profiles saved yet. Configure modules below, then save the current configuration as a profile.</div>';
  }

  return `
    <div class="profile-list">
      ${sortProfiles(engagementProfiles.savedProfiles)
        .map((profile) => {
          const moduleCount = profile.enabledModuleIds.length;
          const includeRuleCount = profile.scopePolicy.rules.filter(
            (rule) => rule.disposition === 'in-scope'
          ).length;
          const excludeRuleCount = profile.scopePolicy.rules.filter(
            (rule) => rule.disposition === 'out-of-scope'
          ).length;
          const reviewRuleCount = profile.scopePolicy.rules.filter(
            (rule) => rule.disposition === 'review'
          ).length;
          const active = engagementProfiles.activeProfileId === profile.id;
          return `
            <article class="profile-card stack">
              <div class="inline profile-card-header">
                <strong>${escapeHtml(profile.name)}</strong>
                <span class="inline">
                  ${active ? '<span class="badge">Active</span>' : ''}
                  <span class="muted">Updated ${escapeHtml(formatRelativeTimestamp(profile.updatedAt))}</span>
                </span>
              </div>
              <div class="tag-row">
                <span class="search-tag">${moduleCount} module${moduleCount === 1 ? '' : 's'} enabled</span>
                <span class="search-tag">${includeRuleCount} include</span>
                <span class="search-tag">${excludeRuleCount} exclude</span>
                <span class="search-tag">${reviewRuleCount} review</span>
                <span class="search-tag">default: ${escapeHtml(profile.scopePolicy.defaultDisposition)}</span>
              </div>
              ${profile.scopeNotes ? `<div class="muted">${escapeHtml(profile.scopeNotes)}</div>` : ''}
              <div class="inline">
                <button class="primary" type="button" data-engagement-activate="${escapeHtml(profile.id)}"${active ? ' disabled' : ''}>Activate</button>
                <button type="button" data-engagement-edit="${escapeHtml(profile.id)}">Edit</button>
                <button class="ghost" type="button" data-engagement-delete="${escapeHtml(profile.id)}">Delete</button>
              </div>
            </article>
          `;
        })
        .join('')}
    </div>
  `;
}

function renderSearchWorkbench(state: ConsoleState): string {
  const draft = state.searchWorkbench.draft;
  const targetTabHost = tryGetHostname(state.targetTab?.url);
  const targetCount = parseTargets(draft.targetsText).length;
  const launchPlans = buildSearchLaunchPlans(draft);
  const validationError = validateSearchDraft(draft);
  const selectedEngineCount = draft.selectedEngineIds.length;

  return `
    <section class="panel stack search-workbench">
      <div class="search-toolbar">
        <div class="stack">
          <div class="inline">
            <h2>Search Workbench</h2>
            <span class="badge">Multi-engine</span>
            ${state.searchWorkbenchDirty ? '<span class="status-warning">Unsaved local changes</span>' : ''}
          </div>
          <p class="muted">
            Build bounded, target-scoped OSINT searches; translate reviewed operators per engine;
            or route the same suite through a search surface you select on the target site.
          </p>
        </div>
        <div class="inline">
          <button class="ghost" data-search-action="use-tab-host"${
            targetTabHost ? '' : ' disabled'
          }>Use Tab Host</button>
          <button class="ghost" data-search-action="reset-draft"${
            state.busy ? ' disabled' : ''
          }>Reset Draft</button>
          ${
            state.searchTab === 'run'
              ? `<button class="primary" data-search-action="launch"${
                  state.busy || validationError || launchPlans.length === 0 ? ' disabled' : ''
                }>
                  Launch ${launchPlans.length || ''} Search${launchPlans.length === 1 ? '' : 'es'}
                </button>`
              : ''
          }
        </div>
      </div>
      <div class="tab-row" role="tablist" aria-label="Search Workbench sections">
        ${renderTabButton('search', 'run', 'Run', state.searchTab === 'run')}
        ${renderTabButton('search', 'suite', 'Dork Suite', state.searchTab === 'suite')}
        ${renderTabButton('search', 'nerd', 'Site Search', state.searchTab === 'nerd')}
        ${renderTabButton('search', 'catalog', 'Operators', state.searchTab === 'catalog')}
        ${renderTabButton('search', 'profiles', 'Profiles', state.searchTab === 'profiles')}
        ${renderTabButton('search', 'configure', 'Configure', state.searchTab === 'configure')}
      </div>
      ${
        state.searchTab === 'suite'
          ? renderDorkSuiteTab(state, targetTabHost)
          : state.searchTab === 'nerd'
            ? renderNerdModeTab(state, targetTabHost)
            : state.searchTab === 'catalog'
              ? renderOperatorCatalogTab()
              : state.searchTab === 'profiles'
                ? renderSearchProfilesTab(state)
                : state.searchTab === 'configure'
                  ? renderSearchConfigureTab(state, selectedEngineCount)
                  : renderSearchRunTab(
                      state,
                      targetTabHost,
                      targetCount,
                      selectedEngineCount,
                      launchPlans,
                      validationError
                    )
      }
    </section>
  `;
}

function renderSearchRunTab(
  state: ConsoleState,
  targetTabHost: string | undefined,
  targetCount: number,
  selectedEngineCount: number,
  launchPlans: ReturnType<typeof buildSearchLaunchPlans>,
  validationError: string | undefined
): string {
  const draft = state.searchWorkbench.draft;
  return `
    <div class="search-grid search-grid-wide">
      <label class="stack search-field-wide">
        <span>Target Sites</span>
        <textarea
          class="search-textarea"
          data-search-field="targetsText"
          placeholder="example.com&#10;app.example.org"
        >${escapeHtml(draft.targetsText)}</textarea>
        <div class="muted">
          Comma- or newline-separated domains, subdomains, or URLs. Current tab host:
          ${escapeHtml(targetTabHost ?? 'unavailable')}.
        </div>
      </label>
      <label class="stack search-field-wide">
        <span>Query Builder</span>
        <textarea
          class="search-textarea"
          data-search-field="queryText"
          placeholder='login "admin" filetype:pdf'
        >${escapeHtml(draft.queryText)}</textarea>
        <div class="muted">
          Load a profile or use operator chips in Configure. Replace <code>{value}</code> and
          <code>{target}</code> placeholders before launching when required.
        </div>
      </label>
    </div>
    <section class="search-subpanel stack">
      <div class="inline">
        <h3>Launch Preview</h3>
        <span class="muted" data-search-preview="summary">
          ${launchPlans.length} tab${launchPlans.length === 1 ? '' : 's'} across
          ${selectedEngineCount} engine${selectedEngineCount === 1 ? '' : 's'} and
          ${targetCount} target${targetCount === 1 ? '' : 's'}
        </span>
      </div>
      <div data-search-preview="status">
      ${
        validationError
          ? `<div class="status-error">${escapeHtml(validationError)}</div>`
          : '<div class="muted">Preview shows the exact query string that will be sent to each engine.</div>'
      }
      </div>
      <div data-search-preview="list">${renderLaunchPreview(launchPlans)}</div>
    </section>
  `;
}

function renderDorkSuiteTab(state: ConsoleState, targetTabHost: string | undefined): string {
  const plan = buildDorkSuitePlan(
    state.searchWorkbench.draft,
    state.searchWorkbench.dorkSuiteDraft
  );
  const validationError = validateDorkSuitePlan(plan);
  const selectedCoreEngines = state.searchWorkbench.draft.selectedEngineIds.filter(
    (engineId): engineId is CoreWebSearchEngineId =>
      CORE_WEB_SEARCH_ENGINE_IDS.includes(engineId as CoreWebSearchEngineId)
  );

  return `
    <section class="search-subpanel stack" data-dork-suite>
      <div class="inline profile-card-header">
        <div>
          <div class="inline">
            <h3>Engine-aware Dork Suite</h3>
            <span class="badge">Catalog reviewed ${escapeHtml(plan.catalogReviewedAt)}</span>
          </div>
          <p class="muted">
            Generate bounded, authorized target queries using each destination's verified dialect.
            Deprecated and unsupported operators are excluded from generation.
          </p>
        </div>
        <button class="primary" type="button" data-search-action="launch-suite"${
          state.busy || Boolean(validationError) ? ' disabled' : ''
        }>Run ${plan.entries.length || ''} Dork${plan.entries.length === 1 ? '' : 's'}</button>
      </div>
      ${renderSuiteDraftControls(state, targetTabHost)}
      <div class="inline suite-destination-summary">
        <strong>Destinations</strong>
        <span class="muted">${
          selectedCoreEngines.length
            ? selectedCoreEngines.map((engineId) => escapeHtml(searchEngineLabel(engineId))).join(', ')
            : 'Select Google, Bing, or DuckDuckGo in Configure.'
        }</span>
      </div>
      ${renderDorkSuitePreview(plan, validationError)}
    </section>
  `;
}

function renderNerdModeTab(state: ConsoleState, targetTabHost: string | undefined): string {
  const surfaces = state.searchWorkbench.nerdSurfaces;
  const selectedSurface = surfaces.find(
    (surface) => surface.id === state.searchWorkbench.selectedNerdSurfaceId
  );
  const siteSearchTarget = selectedSurface
    ? getNerdSearchSurfaceTarget(selectedSurface)
    : undefined;
  const plan = buildPortableDorkSuitePlan(
    state.searchWorkbench.draft,
    state.searchWorkbench.dorkSuiteDraft,
    siteSearchTarget
  );
  const validationError = validateDorkSuitePlan(plan);
  const latestNerdSession = (state.snapshot?.searchExecution.sessions ?? []).find(
    (session) =>
      session.mode === 'nerd' &&
      (!selectedSurface ||
        session.tasks.some((task) => task.nerdSurface?.id === selectedSurface.id))
  );
  const fingerprint = buildSiteSearchFingerprint(latestNerdSession);

  return `
    <section class="search-subpanel stack nerd-mode-panel" data-nerd-mode>
      <div class="inline profile-card-header">
        <div>
          <div class="inline">
            <h3>Site Search Audit</h3>
            <span class="badge">Select · Locate · Probe · Review</span>
          </div>
          <p class="muted">
            Select a search function on an authorized site, review the captured route, and run the
            portable dork suite through it. GET, POST, and JavaScript-driven forms are supported.
          </p>
        </div>
        <button class="primary" type="button" data-search-action="launch-nerd"${
          state.busy || !selectedSurface || Boolean(validationError) ? ' disabled' : ''
        }>Run ${plan.entries.length || ''} Site Search Probe${plan.entries.length === 1 ? '' : 's'}</button>
      </div>

      <section class="nerd-step stack">
        <div class="inline profile-card-header">
          <div>
            <h4>1. Select a site search</h4>
            <p class="muted">Pick a top-frame search field directly, or scan the active page and review likely controls.</p>
          </div>
          <div class="inline">
            <button class="primary" type="button" data-search-action="pick-nerd"${
              state.busy || !state.targetTab?.tabId ? ' disabled' : ''
            }>Pick Search on Page</button>
            <button type="button" data-search-action="discover-nerd"${
              state.busy || !state.targetTab?.tabId ? ' disabled' : ''
            }>Scan Page</button>
          </div>
        </div>
        ${renderNerdCandidates(state.nerdCandidates)}
        <details class="search-subpanel nerd-template-composer" data-disclosure-key="nerd-template-composer">
          <summary>Supply a reviewed GET endpoint</summary>
          <div class="search-grid search-grid-compact">
            <label class="stack">
              <span>Surface name</span>
              <input type="text" data-nerd-field="template-name" placeholder="Internal docs search" />
            </label>
            <label class="stack search-field-wide">
              <span>GET URL with exactly one <code>{query}</code></span>
              <input type="url" data-nerd-field="url-template" placeholder="https://docs.example/search?q={query}" />
            </label>
          </div>
          <div class="muted">For POST or JavaScript-driven searches, select the real page control so BLANCHE can replay its native submission.</div>
          <button type="button" data-search-action="save-nerd-template">Save GET Endpoint</button>
        </details>
        ${renderNerdSurfaces(state)}
      </section>

      <section class="nerd-step stack">
        <h4>2. Choose templates and keywords</h4>
        ${renderSuiteDraftControls(state, targetTabHost, siteSearchTarget)}
      </section>

      <section class="nerd-step stack">
        <div class="inline profile-card-header">
          <div>
            <h4>3. Review exact probes</h4>
            <p class="muted">Portable syntax is submitted unchanged so the selected site decides how to interpret it.</p>
          </div>
          <span class="badge">${escapeHtml(selectedSurface?.name ?? 'No surface selected')}</span>
        </div>
        ${renderDorkSuitePreview(
          plan,
          selectedSurface ? validationError : 'Select or save a Site Search surface before launching.'
        )}
      </section>
      ${renderSiteSearchFingerprint(fingerprint)}
    </section>
  `;
}

function renderSiteSearchFingerprint(fingerprint: SiteSearchFingerprint | undefined): string {
  if (!fingerprint) {
    return `
      <section class="nerd-step stack site-search-fingerprint" data-site-search-fingerprint>
        <div class="inline profile-card-header">
          <div>
            <h4>Observed behavior fingerprint</h4>
            <p class="muted">Run the reviewed probes to compare result, zero-result, manual, and failed outcomes by category and operator.</p>
          </div>
          <span class="badge">Not run</span>
        </div>
        <div class="muted">Result behavior can characterize the selected search surface. It does not identify a vendor without direct implementation evidence.</div>
      </section>
    `;
  }
  const assessmentLabel = siteSearchAssessmentLabel(fingerprint.assessment);
  const provider = fingerprint.surface?.providerFingerprint;
  return `
    <section class="nerd-step stack site-search-fingerprint" data-site-search-fingerprint>
      <div class="inline profile-card-header">
        <div>
          <h4>Observed behavior fingerprint</h4>
          <p class="muted">${escapeHtml(fingerprint.surface?.name ?? 'Selected site search')} · ${fingerprint.coverage.observedTasks}/${fingerprint.totals.tasks} probes produced observable result states.</p>
        </div>
        <span class="badge">${escapeHtml(assessmentLabel)}</span>
      </div>
      ${
        provider
          ? `<div class="muted"><strong>Possible page implementation marker:</strong> ${escapeHtml(provider.label)} · ${escapeHtml(provider.confidence)} confidence${
              provider.evidence.length
                ? ` · ${provider.evidence.map((entry) => escapeHtml(entry)).join('; ')}`
                : ''
            }</div>`
          : '<div class="muted">No direct implementation marker was retained for this run.</div>'
      }
      <div class="interest-card-grid">
        <article class="profile-card stack"><strong>${fingerprint.totals.tasks}</strong><span class="muted">bounded probes</span></article>
        <article class="profile-card stack"><strong>${fingerprint.totals.results}</strong><span class="muted">parsed results</span></article>
        <article class="profile-card stack"><strong>${fingerprint.totals.resultTasks}</strong><span class="muted">result responses</span></article>
        <article class="profile-card stack"><strong>${fingerprint.totals.noResultTasks}</strong><span class="muted">zero-result responses</span></article>
        <article class="profile-card stack"><strong>${fingerprint.totals.manualRequiredTasks + fingerprint.totals.failedTasks}</strong><span class="muted">manual or failed</span></article>
        <article class="profile-card stack"><strong>${Math.round(fingerprint.coverage.coverageRate * 100)}%</strong><span class="muted">observable coverage</span></article>
      </div>
      <div class="stack">
        <strong>Category signals</strong>
        <div class="tag-row">${fingerprint.categories
          .map(
            (signal) => `<span class="search-tag">${escapeHtml(signal.id)} · ${escapeHtml(
              siteSearchAssessmentLabel(signal.assessment)
            )} · ${signal.counts.results} result${signal.counts.results === 1 ? '' : 's'}</span>`
          )
          .join('')}</div>
      </div>
      <details data-disclosure-key="site-search-fingerprint:${escapeHtml(fingerprint.sessionId)}">
        <summary>${fingerprint.operators.length} operator behavior signal${fingerprint.operators.length === 1 ? '' : 's'}</summary>
        <div class="tag-row">${fingerprint.operators
          .map(
            (signal) => `<span class="search-tag">${escapeHtml(signal.id)} · ${escapeHtml(
              siteSearchAssessmentLabel(signal.assessment)
            )}</span>`
          )
          .join('')}</div>
      </details>
      ${fingerprint.truncated ? '<div class="status-warning">The fingerprint reached a retention cap; review the underlying tracked session for complete task detail.</div>' : ''}
      <div class="muted">These are observed response patterns. BLANCHE does not infer a named backend from result counts.</div>
    </section>
  `;
}

function siteSearchAssessmentLabel(assessment: SiteSearchSignalAssessment): string {
  switch (assessment) {
    case 'results-observed':
      return 'results observed';
    case 'no-results-observed':
      return 'zero results observed';
    case 'mixed':
      return 'mixed outcomes';
    default:
      return 'inconclusive';
  }
}

function renderSuiteDraftControls(
  state: ConsoleState,
  targetTabHost: string | undefined,
  siteSearchTarget?: string
): string {
  const draft = state.searchWorkbench.draft;
  const suiteDraft = state.searchWorkbench.dorkSuiteDraft;
  return `
    <div class="search-grid search-grid-wide suite-controls">
      ${
        siteSearchTarget
          ? `<div class="stack search-field-wide">
              <span>Site Search target</span>
              <code class="search-code">${escapeHtml(siteSearchTarget)}</code>
              <div class="muted">Derived from the selected search page. Every portable probe runs once against this surface.</div>
            </div>`
          : `<label class="stack search-field-wide">
              <span>Authorized Target Sites</span>
              <textarea
                class="search-textarea"
                data-search-field="targetsText"
                placeholder="example.com&#10;app.example.org"
              >${escapeHtml(draft.targetsText)}</textarea>
              <div class="muted">Required. Comma- or newline-separated domains, subdomains, or URLs. Active tab: ${escapeHtml(
                targetTabHost ?? 'unavailable'
              )}.</div>
            </label>`
      }
      <label class="stack search-field-wide">
        <span>Keyword or phrase list (optional)</span>
        <textarea
          class="search-textarea"
          data-suite-field="keywordsText"
          placeholder="acquisition project&#10;legacy portal&#10;internal API"
        >${escapeHtml(suiteDraft.keywordsText)}</textarea>
        <div class="muted">One per line, comma, or semicolon. BLANCHE repeats the selected template suite for each bounded entry.</div>
      </label>
      <label class="stack">
        <span>Maximum submissions</span>
        <input
          type="number"
          min="1"
          max="60"
          data-suite-field="maxQueries"
          value="${suiteDraft.maxQueries}"
        />
        <div class="muted">Hard cap prevents accidental tab storms.</div>
      </label>
    </div>
    <fieldset class="suite-category-fieldset">
      <legend>Suite categories</legend>
      <div class="suite-category-grid">
        ${DORK_SUITE_CATEGORIES.map(
          (category) => `
            <label class="suite-category-card${
              suiteDraft.categoryIds.includes(category.id) ? ' is-selected' : ''
            }">
              <input type="checkbox" data-suite-category="${escapeHtml(category.id)}"${
                suiteDraft.categoryIds.includes(category.id) ? ' checked' : ''
              } />
              <span><strong>${escapeHtml(category.label)}</strong><small>${escapeHtml(
                category.description
              )}</small></span>
            </label>
          `
        ).join('')}
      </div>
    </fieldset>
  `;
}

function renderDorkSuitePreview(
  plan: DorkSuitePlan,
  validationError?: string
): string {
  const planWarnings = Array.from(new Set(plan.warnings));
  return `
    <section class="search-subpanel stack dork-preview" data-dork-preview>
      <div class="inline profile-card-header">
        <div>
          <h4>Exact query preview</h4>
          <p class="muted">${plan.entries.length} bounded submission${
            plan.entries.length === 1 ? '' : 's'
          } across ${plan.targets.length} target${plan.targets.length === 1 ? '' : 's'}.</p>
        </div>
        <span class="badge">${escapeHtml(plan.kind)} · ${escapeHtml(plan.schemaVersion)}</span>
      </div>
      ${
        validationError
          ? `<div class="status-error">${escapeHtml(validationError)}</div>`
          : ''
      }
      ${planWarnings.map((warning) => `<div class="status-warning">${escapeHtml(warning)}</div>`).join('')}
      ${
        plan.entries.length
          ? `<div class="search-plan-list">${plan.entries
              .map(
                (entry) => `
                  <article class="profile-card stack" data-dork-entry="${escapeHtml(entry.id)}">
                    <div class="inline profile-card-header">
                      <strong>${escapeHtml(entry.title)}</strong>
                      <span class="search-tag">${escapeHtml(entry.dialect)}</span>
                    </div>
                    <code class="search-code">${escapeHtml(entry.query)}</code>
                    <div class="tag-row">
                      ${entry.operatorIds
                        .map((operatorId) => `<span class="search-tag">${escapeHtml(operatorId)}</span>`)
                        .join('')}
                    </div>
                    ${Array.from(new Set(entry.warnings))
                      .map((warning) => `<div class="muted dork-entry-warning">${escapeHtml(warning)}</div>`)
                      .join('')}
                  </article>
                `
              )
              .join('')}</div>`
          : '<div class="muted">No exact submissions are available with the current target, categories, and destinations.</div>'
      }
    </section>
  `;
}

function renderNerdCandidates(candidates: NerdSearchCandidate[]): string {
  if (!candidates.length) {
    return '<div class="muted nerd-empty">No page scan results yet.</div>';
  }
  return `
    <div class="nerd-candidate-grid">
      ${candidates
        .map(
          (candidate) => `
            <article class="profile-card stack" data-nerd-candidate-card="${escapeHtml(candidate.id)}">
              <div class="inline profile-card-header">
                <strong>${escapeHtml(candidate.name)}</strong>
                <span class="search-tag">${escapeHtml(candidate.method.toUpperCase())}</span>
              </div>
              <div class="muted target-url">${escapeHtml(candidate.actionUrl)}</div>
              <code class="search-code">${escapeHtml(candidate.inputSelector)}</code>
              ${renderNerdProviderFingerprint(candidate.providerFingerprint)}
              <div class="inline">
                <button class="ghost" type="button" data-nerd-highlight="${escapeHtml(candidate.id)}">Highlight</button>
                <button type="button" data-nerd-candidate="${escapeHtml(candidate.id)}">Use This Search</button>
              </div>
            </article>
          `
        )
        .join('')}
    </div>
  `;
}

function renderNerdSurfaces(state: ConsoleState): string {
  const surfaces = state.searchWorkbench.nerdSurfaces;
  if (!surfaces.length) {
    return '<div class="muted nerd-empty">No saved Site Search surfaces. Scan an authorized page or add a reviewed template.</div>';
  }
  return `
    <div class="nerd-surface-grid">
      ${surfaces
        .map((surface) => {
          const selected = surface.id === state.searchWorkbench.selectedNerdSurfaceId;
          return `
            <article class="profile-card stack nerd-surface-card${selected ? ' is-selected' : ''}" data-nerd-surface="${escapeHtml(surface.id)}">
              <div class="inline profile-card-header">
                <strong>${escapeHtml(surface.name)}</strong>
                <span class="search-tag">${escapeHtml(surface.mode)} · ${escapeHtml(surface.method.toUpperCase())}</span>
              </div>
              <div class="muted target-url">${escapeHtml(surface.urlTemplate ?? surface.actionUrl)}</div>
              ${renderNerdProviderFingerprint(surface.providerFingerprint)}
              <div class="inline">
                <button type="button" data-nerd-select="${escapeHtml(surface.id)}"${selected ? ' disabled' : ''}>${selected ? 'Selected' : 'Select'}</button>
                <button class="ghost" type="button" data-nerd-delete="${escapeHtml(surface.id)}">Delete</button>
              </div>
            </article>
          `;
        })
        .join('')}
    </div>
  `;
}

function renderNerdProviderFingerprint(
  fingerprint: NerdSearchCandidate['providerFingerprint']
): string {
  if (!fingerprint) return '';
  const evidence = fingerprint.evidence.length
    ? ` · ${fingerprint.evidence.map((entry) => escapeHtml(entry)).join('; ')}`
    : '';
  return `<div class="muted"><strong>Possible page source hint:</strong> ${escapeHtml(fingerprint.label)} · ${escapeHtml(
    fingerprint.confidence
  )} confidence${evidence}</div>`;
}

function renderOperatorCatalogTab(): string {
  const operators = SEARCH_OPERATOR_CATALOG.operators;
  return `
    <section class="search-subpanel stack operator-catalog" data-search-operator-catalog>
      <div class="inline profile-card-header">
        <div>
          <div class="inline">
            <h3>Cross-engine Operator Catalog</h3>
            <span class="badge">${operators.length} operators</span>
          </div>
          <p class="muted">
            Current Google, Bing, and DuckDuckGo behavior is classified separately. Open any cell
            for semantics, caveats, replacements, and the source used for assessment.
          </p>
        </div>
        <span class="badge">Reviewed ${escapeHtml(SEARCH_OPERATOR_CATALOG.lastReviewed)}</span>
      </div>
      <div class="operator-status-legend">
        ${(['documented', 'observed', 'fragile', 'deprecated', 'unsupported'] as SearchOperatorSupportStatus[])
          .map(
            (status) => `<span class="operator-status operator-status-${status}">${escapeHtml(
              operatorStatusLabel(status)
            )}</span>`
          )
          .join('')}
      </div>
      <div class="operator-table-wrap">
        <table class="operator-matrix">
          <thead>
            <tr>
              <th scope="col">Operator</th>
              ${CORE_WEB_SEARCH_ENGINE_IDS.map(
                (engineId) => `<th scope="col">${escapeHtml(searchEngineLabel(engineId))}</th>`
              ).join('')}
            </tr>
          </thead>
          <tbody>
            ${operators.map((operator) => renderOperatorCatalogRow(operator)).join('')}
          </tbody>
        </table>
      </div>
      <p class="muted">
        A documented operator can still be constrained by indexing and ranking. “Observed” and
        “fragile” entries are never presented as vendor contracts; deprecated and unsupported
        entries are excluded from generated dorks.
      </p>
    </section>
  `;
}

function renderOperatorCatalogRow(operator: SearchOperatorCatalogEntry): string {
  return `
    <tr data-catalog-operator="${escapeHtml(operator.id)}">
      <th scope="row">
        <strong>${escapeHtml(operator.label)}</strong>
        <code>${escapeHtml(operator.id)}</code>
        <span class="search-tag">${escapeHtml(operator.category)}</span>
        <small>${escapeHtml(operator.description)}</small>
      </th>
      ${CORE_WEB_SEARCH_ENGINE_IDS.map((engineId) =>
        renderOperatorSupportCell(operator, engineId)
      ).join('')}
    </tr>
  `;
}

function renderOperatorSupportCell(
  operator: SearchOperatorCatalogEntry,
  engineId: CoreWebSearchEngineId
): string {
  const support = operator.engines[engineId];
  return `
    <td data-catalog-engine="${escapeHtml(engineId)}" data-catalog-status="${escapeHtml(
      support.status
    )}">
      <details data-disclosure-key="operator-catalog:${escapeHtml(operator.id)}:${escapeHtml(
        engineId
      )}">
        <summary>
          <span class="operator-status operator-status-${escapeHtml(support.status)}">${escapeHtml(
            operatorStatusLabel(support.status)
          )}</span>
          <code>${escapeHtml(support.syntax.join(' · ') || '—')}</code>
        </summary>
        <div class="stack operator-support-detail">
          <p>${escapeHtml(support.semantics)}</p>
          ${support.notes.map((note) => `<small>${escapeHtml(note)}</small>`).join('')}
          ${
            support.replacement
              ? `<small><strong>Use instead:</strong> ${escapeHtml(support.replacement)}</small>`
              : ''
          }
          <div class="tag-row">
            ${support.surfaces
              .map((surface) => `<span class="search-tag">${escapeHtml(surface)}</span>`)
              .join('')}
            <span class="search-tag">${support.safeForGeneration ? 'generator-safe' : 'review-only'}</span>
          </div>
          <div class="operator-source-list">
            ${Array.from(new Set(support.sourceUrls))
              .map(
                (sourceUrl, index) =>
                  `<a href="${escapeHtml(sourceUrl)}" target="_blank" rel="noreferrer">Source ${
                    index + 1
                  }</a>`
              )
              .join('')}
          </div>
        </div>
      </details>
    </td>
  `;
}

function operatorStatusLabel(status: SearchOperatorSupportStatus): string {
  switch (status) {
    case 'documented':
      return 'Documented';
    case 'observed':
      return 'Observed';
    case 'fragile':
      return 'Fragile';
    case 'deprecated':
      return 'Deprecated';
    case 'unsupported':
      return 'Unsupported';
  }
}

function searchEngineLabel(engineId: CoreWebSearchEngineId): string {
  return SEARCH_ENGINES.find((engine) => engine.id === engineId)?.name ?? engineId;
}

function renderSearchProfilesTab(state: ConsoleState): string {
  return `
    <section class="search-subpanel stack">
      <div class="inline profile-card-header">
        <div>
          <h3>OSINT Search Profiles</h3>
          <p class="muted">
            Built-in sweeps are ready to load; add a target from the Run tab or the active tab host before launch.
          </p>
        </div>
        <span class="muted">${state.searchWorkbench.savedProfiles.length} stored</span>
      </div>
      ${renderSavedProfiles(state.searchWorkbench)}
    </section>
  `;
}

function renderSearchConfigureTab(state: ConsoleState, selectedEngineCount: number): string {
  const draft = state.searchWorkbench.draft;
  return `
    <section class="search-subpanel stack">
      <div class="inline profile-card-header">
        <div>
          <h3>Search Behavior</h3>
          <p class="muted">Profile naming, engine selection, launch behavior, and operator libraries.</p>
        </div>
        <div class="inline">
          <button class="ghost" data-search-action="save-draft"${
            state.busy ? ' disabled' : ''
          }>Save Draft</button>
          <button class="primary" data-search-action="save-profile"${
            state.busy ? ' disabled' : ''
          }>Save Profile</button>
        </div>
      </div>
      <div class="search-grid search-grid-compact">
        <label class="stack">
          <span>Profile Name</span>
          <input
            type="text"
            data-search-field="name"
            value="${escapeHtml(draft.name)}"
            placeholder="Acme recon sweep"
          />
          <div class="muted">Used when saving a reusable search profile.</div>
        </label>
        <label class="stack">
          <span>Launch Mode</span>
          <select data-search-field="launchMode">
            <option value="combined"${draft.launchMode === 'combined' ? ' selected' : ''}>
              One tab per engine
            </option>
            <option value="per-target"${draft.launchMode === 'per-target' ? ' selected' : ''}>
              One tab per engine and target
            </option>
          </select>
          <div class="muted">Choose whether multiple targets are grouped or split into separate searches.</div>
        </label>
        <div class="stack">
          <span>Open In Background</span>
          <label class="inline muted">
            <input type="checkbox" data-search-field="openInBackground"${
              draft.openInBackground ? ' checked' : ''
            } />
            Leave the panel focused while opening tabs
          </label>
          <div class="muted">If disabled, the final launched tab becomes the active tab.</div>
        </div>
      </div>
    </section>
    <section class="search-subpanel stack">
      <div class="inline">
        <h3>Engines</h3>
        <span class="muted">${selectedEngineCount} selected</span>
      </div>
      <div class="engine-grid">
        ${SEARCH_ENGINES.map((engine) => renderEngineSelector(engine, draft.selectedEngineIds)).join('')}
      </div>
    </section>
    <section class="search-subpanel stack">
      <div class="inline">
        <h3>Operator Chips</h3>
        <span class="muted">Click a chip to append its template to the query builder.</span>
      </div>
      ${renderOperatorGroups(state.searchWorkbench)}
    </section>
    <section class="search-subpanel stack">
      <div class="inline">
        <h3>Custom Operators</h3>
        <span class="muted">Use {target} and {value} placeholders in templates when needed.</span>
      </div>
      ${renderCustomOperatorComposer()}
      ${renderCustomOperatorList(state.searchWorkbench)}
    </section>
  `;
}

function renderInterestWorkbench(state: ConsoleState): string {
  const workbench = state.interestWorkbench;
  const settings = workbench.settings;
  const analysis = workbench.lastAnalysis;
  const currentTabAnalysis = analysis?.currentTab;
  const canUseTargetTab = Boolean(state.targetTab?.tabId);
  const predictionCount = currentTabAnalysis?.predictions.length ?? 0;
  const currentScore = currentTabAnalysis
    ? formatPercent(currentTabAnalysis.rating.overall)
    : 'Awaiting analysis';

  return `
    <section class="panel stack interest-workbench">
      <div class="search-toolbar">
        <div class="stack">
          <div class="inline">
            <h2>Interest Model</h2>
            <span class="badge">Bookmarks + Markov</span>
            ${state.interestWorkbenchDirty ? '<span class="status-warning">Unsaved local changes</span>' : ''}
          </div>
          <p class="muted">
            Train a lightweight interest model from a bookmark folder, score the active page against
            those examples, and walk bookmark-sequence transitions to estimate likely next topics.
          </p>
        </div>
        <div class="inline">
          <button class="ghost" data-interest-action="save-settings"${
            state.busy ? ' disabled' : ''
          }>Save Settings</button>
          <button class="ghost" data-interest-action="create-folder"${
            state.busy ? ' disabled' : ''
          }>Create or Bind Folder</button>
          <button class="ghost" data-interest-action="bookmark-tab"${
            state.busy || !canUseTargetTab ? ' disabled' : ''
          }>Bookmark Current Tab</button>
          <button class="primary" data-interest-action="analyze"${
            state.busy || !canUseTargetTab ? ' disabled' : ''
          }>Analyze Current Tab</button>
        </div>
      </div>
      <div class="search-grid search-grid-compact">
        <label class="stack">
          <span>Folder Name</span>
          <input
            type="text"
            data-interest-field="folderName"
            value="${escapeHtml(settings.folderName)}"
            placeholder="BLANCHE Interest Signals"
          />
          <div class="muted">
            The folder acts as positive training data for what content is worth following.
          </div>
        </label>
        <label class="stack">
          <span>Walk Depth</span>
          <input
            type="number"
            min="1"
            max="6"
            data-interest-field="walkDepth"
            value="${settings.walkDepth}"
          />
          <div class="muted">How many transition steps each Markov walk should take.</div>
        </label>
        <label class="stack">
          <span>Walk Count</span>
          <input
            type="number"
            min="8"
            max="256"
            data-interest-field="walkCount"
            value="${settings.walkCount}"
          />
          <div class="muted">More walks smooth the prediction distribution.</div>
        </label>
        <label class="stack">
          <span>Max Predictions</span>
          <input
            type="number"
            min="3"
            max="12"
            data-interest-field="maxPredictions"
            value="${settings.maxPredictions}"
          />
          <div class="muted">How many likely next signals to surface from the walk results.</div>
        </label>
      </div>
      <div class="summary-grid">
        <div class="panelish">
          <strong>Folder</strong>
          <div>${escapeHtml(renderFolderStatusLabel(analysis?.folderStatus))}</div>
          <div class="muted">${escapeHtml(analysis?.folderName ?? settings.folderName)}</div>
        </div>
        <div class="panelish">
          <strong>Training Examples</strong>
          <div>${analysis?.bookmarkCount ?? 0}</div>
          <div class="muted">Bookmarks learned from the folder.</div>
        </div>
        <div class="panelish">
          <strong>Current Score</strong>
          <div>${escapeHtml(currentScore)}</div>
          <div class="muted">Heuristic fit against bookmarked interests.</div>
        </div>
        <div class="panelish">
          <strong>Forecast Signals</strong>
          <div>${predictionCount}</div>
          <div class="muted">Top next-step outputs from the Markov walks.</div>
        </div>
      </div>
      ${
        analysis?.warnings.length
          ? `
            <section class="search-subpanel stack">
              <div class="inline">
                <h3>Model Notes</h3>
                <span class="muted">${escapeHtml(
                  analysis.generatedAt ? `Updated ${formatRelativeTimestamp(analysis.generatedAt)}` : ''
                )}</span>
              </div>
              <ul class="warning-list">
                ${analysis.warnings
                  .map((warning) => `<li>${escapeHtml(warning)}</li>`)
                  .join('')}
              </ul>
            </section>
          `
          : ''
      }
      <section class="search-subpanel stack">
        <div class="inline">
          <h3>Top Interest Signals</h3>
          <span class="muted">
            ${analysis?.topSignals.length ?? 0} weighted host and token signals.
          </span>
        </div>
        ${renderInterestSignalList(analysis?.topSignals)}
      </section>
      <section class="search-subpanel stack">
        <div class="inline">
          <h3>Current Tab Rating</h3>
          <span class="muted">
            ${
              currentTabAnalysis
                ? escapeHtml(currentTabAnalysis.hostname ?? currentTabAnalysis.url)
                : 'Run an analysis against the active tab.'
            }
          </span>
        </div>
        ${renderCurrentTabAnalysis(currentTabAnalysis)}
      </section>
      <section class="search-subpanel stack">
        <div class="inline">
          <h3>Predicted Next Signals</h3>
          <span class="muted">
            This is a deterministic walk over bookmark-order transitions, not literal future knowledge.
          </span>
        </div>
        ${renderInterestPredictionList(currentTabAnalysis?.predictions)}
      </section>
      <section class="search-subpanel stack">
        <div class="inline">
          <h3>Likely Paths</h3>
          <span class="muted">Representative Markov paths seeded from the current page.</span>
        </div>
        ${renderInterestPathList(currentTabAnalysis?.futurePaths)}
      </section>
      <section class="search-subpanel stack">
        <div class="inline">
          <h3>Recent Training Samples</h3>
          <span class="muted">${analysis?.recentBookmarks.length ?? 0} recent bookmarks shown.</span>
        </div>
        ${renderInterestBookmarkList(analysis?.recentBookmarks)}
      </section>
    </section>
  `;
}

function renderEngineSelector(
  engine: SearchEngineDefinition,
  selectedEngineIds: SearchEngineId[]
): string {
  const selected = selectedEngineIds.includes(engine.id);
  return `
    <button
      type="button"
      class="engine-button${selected ? ' is-selected' : ''}"
      data-engine-id="${escapeHtml(engine.id)}"
      style="--engine-accent: ${escapeHtml(engine.accentColor)}"
    >
      <span class="engine-icon">${escapeHtml(engine.iconLabel)}</span>
      <span class="stack">
        <strong>${escapeHtml(engine.name)}</strong>
        <span class="muted">${escapeHtml(engine.description)}</span>
      </span>
    </button>
  `;
}

function renderOperatorGroups(searchWorkbench: SearchWorkbenchState): string {
  const operators = getSearchOperators(searchWorkbench.customOperators);
  return `
    <div class="operator-groups">
      ${SEARCH_OPERATOR_CATEGORY_ORDER.map((category) => {
        const categoryOperators = operators.filter((operator) => operator.category === category);
        if (categoryOperators.length === 0) {
          return '';
        }

        return `
          <section class="operator-group stack">
            <div class="inline">
              <strong>${escapeHtml(SEARCH_OPERATOR_CATEGORY_LABELS[category])}</strong>
              <span class="muted">${categoryOperators.length} chip${categoryOperators.length === 1 ? '' : 's'}</span>
            </div>
            <div class="chip-grid">
              ${categoryOperators.map((operator) => renderOperatorChip(operator)).join('')}
            </div>
          </section>
        `;
      }).join('')}
    </div>
  `;
}

function renderOperatorChip(operator: SearchOperatorDefinition): string {
  return `
    <button type="button" class="operator-chip stack" data-operator-id="${escapeHtml(operator.id)}">
      <span class="inline">
        <strong>${escapeHtml(operator.label)}</strong>
        ${operator.isCustom ? '<span class="badge">Custom</span>' : ''}
      </span>
      <span class="muted">${escapeHtml(operator.description)}</span>
      <span class="engine-mini-row">
        ${operator.engineIds.map((engineId) => renderEngineMini(engineId)).join('')}
      </span>
    </button>
  `;
}

function renderEngineMini(engineId: SearchEngineId): string {
  const engine = SEARCH_ENGINES.find((candidate) => candidate.id === engineId);
  if (!engine) {
    return '';
  }

  return `
    <span
      class="engine-mini"
      title="${escapeHtml(engine.name)}"
      style="--engine-accent: ${escapeHtml(engine.accentColor)}"
    >
      ${escapeHtml(engine.iconLabel)}
    </span>
  `;
}

function renderInterestSignalList(signals?: InterestSignalSummary[]): string {
  if (!signals?.length) {
    return '<div class="muted">No weighted signals yet. Add bookmarks and analyze the model.</div>';
  }

  return `
    <div class="interest-card-grid">
      ${signals
        .map(
          (signal) => `
            <article class="profile-card stack">
              <div class="inline profile-card-header">
                <strong>${escapeHtml(signal.label)}</strong>
                <span class="search-tag">${escapeHtml(signal.type)}</span>
              </div>
              <div class="muted">Seen ${signal.count} time${signal.count === 1 ? '' : 's'}</div>
              <div class="interest-meter">
                <span style="width: ${Math.min(100, Math.max(10, Math.round(signal.weight * 12)))}%"></span>
              </div>
            </article>
          `
        )
        .join('')}
    </div>
  `;
}

function renderCurrentTabAnalysis(analysis?: InterestAnalysis['currentTab']): string {
  if (!analysis) {
    return '<div class="muted">No current-tab analysis has been generated yet.</div>';
  }

  return `
    <div class="stack">
      <div class="summary-grid">
        <div class="panelish">
          <strong>Overall</strong>
          <div>${formatPercent(analysis.rating.overall)}</div>
          <div class="muted">Combined relevance estimate.</div>
        </div>
        <div class="panelish">
          <strong>Host</strong>
          <div>${formatPercent(analysis.rating.hostAffinity)}</div>
          <div class="muted">Similarity to bookmarked hosts.</div>
        </div>
        <div class="panelish">
          <strong>Tokens</strong>
          <div>${formatPercent(analysis.rating.tokenAffinity)}</div>
          <div class="muted">Overlap with learned content tokens.</div>
        </div>
        <div class="panelish">
          <strong>Coverage</strong>
          <div>${formatPercent(analysis.rating.coverage)}</div>
          <div class="muted">Share of current signals seen before.</div>
        </div>
      </div>
      <div class="muted">${escapeHtml(analysis.url)}</div>
      <div class="tag-row">
        ${analysis.tokens.length > 0 ? analysis.tokens.map((token) => renderInterestTag(token)).join('') : '<span class="muted">No extracted tokens.</span>'}
      </div>
      <div class="tag-row">
        ${
          analysis.rating.matchedSignals.length > 0
            ? analysis.rating.matchedSignals.map((signal) => renderInterestTag(signal)).join('')
            : '<span class="muted">No matched interest signals.</span>'
        }
      </div>
    </div>
  `;
}

function renderInterestPredictionList(predictions?: InterestPrediction[]): string {
  if (!predictions?.length) {
    return '<div class="muted">No transition forecast is available yet.</div>';
  }

  return `
    <div class="interest-card-grid">
      ${predictions
        .map(
          (prediction) => `
            <article class="profile-card stack">
              <div class="inline profile-card-header">
                <strong>${escapeHtml(prediction.label)}</strong>
                <span class="search-tag">${escapeHtml(prediction.type)}</span>
              </div>
              <div class="muted">
                ${formatPercent(prediction.probability)} of sampled next-step visits across
                ${prediction.support} supporting transition${prediction.support === 1 ? '' : 's'}.
              </div>
            </article>
          `
        )
        .join('')}
    </div>
  `;
}

function renderInterestPathList(paths?: InterestWalkPath[]): string {
  if (!paths?.length) {
    return '<div class="muted">No Markov paths were generated from the current state.</div>';
  }

  return `
    <ol class="search-plan-list">
      ${paths
        .map(
          (path) => `
            <li class="plan-card stack">
              <div class="inline">
                <strong>${formatPercent(path.probability)}</strong>
                <span class="muted">share of simulated walks</span>
              </div>
              <div class="tag-row">
                ${path.path.map((step) => renderInterestTag(step)).join('')}
              </div>
            </li>
          `
        )
        .join('')}
    </ol>
  `;
}

function renderInterestBookmarkList(bookmarks?: InterestBookmarkSummary[]): string {
  if (!bookmarks?.length) {
    return '<div class="muted">No bookmarked samples are available yet.</div>';
  }

  return `
    <div class="interest-card-grid">
      ${bookmarks
        .map(
          (bookmark) => `
            <article class="profile-card stack">
              <div class="inline profile-card-header">
                <strong>${escapeHtml(bookmark.title)}</strong>
                <span class="muted">${escapeHtml(formatRelativeTimestamp(bookmark.addedAt))}</span>
              </div>
              <div class="muted">${escapeHtml(bookmark.hostname ?? bookmark.url)}</div>
              <div class="tag-row">
                ${bookmark.tokens.map((token) => renderInterestTag(token)).join('')}
              </div>
            </article>
          `
        )
        .join('')}
    </div>
  `;
}

function renderInterestTag(label: string): string {
  return `<span class="search-tag interest-tag">${escapeHtml(label)}</span>`;
}

function renderFolderStatusLabel(status?: InterestAnalysis['folderStatus']): string {
  switch (status) {
    case 'ready':
      return 'Ready';
    case 'empty':
      return 'Empty';
    case 'missing':
      return 'Missing';
    default:
      return 'Unbound';
  }
}

function renderSavedProfiles(searchWorkbench: SearchWorkbenchState): string {
  if (searchWorkbench.savedProfiles.length === 0) {
    return '<div class="muted">No saved search functions yet. Save the current draft to create one.</div>';
  }

  return `
    <div class="profile-list">
      ${sortProfiles(searchWorkbench.savedProfiles)
        .map((profile) => {
          const targets = parseTargets(profile.targetsText);
          const isBuiltIn = profile.id.startsWith('builtin-');
          return `
            <article class="profile-card stack">
              <div class="inline profile-card-header">
                <strong>${escapeHtml(profile.name)}</strong>
                <span class="inline">
                  ${isBuiltIn ? '<span class="badge">Built-in OSINT</span>' : ''}
                  <span class="muted">Updated ${escapeHtml(formatRelativeTimestamp(profile.updatedAt))}</span>
                </span>
              </div>
              <div class="tag-row">
                ${profile.selectedEngineIds.map((engineId) => renderEngineMini(engineId)).join('')}
                <span class="search-tag">${targets.length} target${targets.length === 1 ? '' : 's'}</span>
                <span class="search-tag">${profile.launchMode === 'combined' ? 'Combined' : 'Per target'}</span>
              </div>
              <div class="muted">${escapeHtml(profile.queryText || '(target-only query)')}</div>
              <div class="inline">
                <button class="primary" type="button" data-profile-load="${escapeHtml(profile.id)}">Load</button>
                ${
                  isBuiltIn
                    ? ''
                    : `<button class="ghost" type="button" data-profile-delete="${escapeHtml(profile.id)}">Delete</button>`
                }
              </div>
            </article>
          `;
        })
        .join('')}
    </div>
  `;
}

function renderCustomOperatorComposer(): string {
  return `
    <div class="custom-operator-form stack">
      <div class="search-grid search-grid-compact">
        <label class="stack">
          <span>Label</span>
          <input type="text" data-custom-field="label" placeholder='tech:"{value}"' />
        </label>
        <label class="stack">
          <span>Template</span>
          <input type="text" data-custom-field="template" placeholder='tech:"{value}"' />
        </label>
        <label class="stack">
          <span>Category</span>
          <select data-custom-field="category">
            ${SEARCH_OPERATOR_CATEGORY_ORDER.map(
              (category) =>
                `<option value="${escapeHtml(category)}">${escapeHtml(
                  SEARCH_OPERATOR_CATEGORY_LABELS[category]
                )}</option>`
            ).join('')}
          </select>
        </label>
      </div>
      <label class="stack">
        <span>Description</span>
        <input
          type="text"
          data-custom-field="description"
          placeholder="What this operator is intended to filter or match."
        />
      </label>
      <div class="stack">
        <span>Supported Engines</span>
        <div class="engine-checkbox-grid">
          ${SEARCH_ENGINES.map(
            (engine) => `
              <label class="engine-check" style="--engine-accent: ${escapeHtml(engine.accentColor)}">
                <input type="checkbox" data-custom-engine-id="${escapeHtml(engine.id)}" />
                <span class="engine-mini">${escapeHtml(engine.iconLabel)}</span>
                <span>${escapeHtml(engine.name)}</span>
              </label>
            `
          ).join('')}
        </div>
      </div>
      <div class="inline">
        <button class="primary" type="button" data-search-action="add-custom-operator">Add Custom Operator</button>
      </div>
    </div>
  `;
}

function renderCustomOperatorList(searchWorkbench: SearchWorkbenchState): string {
  if (searchWorkbench.customOperators.length === 0) {
    return '<div class="muted">No custom operators stored yet.</div>';
  }

  return `
    <div class="profile-list">
      ${sortCustomOperators(searchWorkbench.customOperators)
        .map(
          (operator) => `
            <article class="profile-card stack">
              <div class="inline profile-card-header">
                <strong>${escapeHtml(operator.label)}</strong>
                <span class="muted">Saved ${escapeHtml(formatRelativeTimestamp(operator.updatedAt))}</span>
              </div>
              <div class="muted">${escapeHtml(operator.description)}</div>
              <code class="search-code">${escapeHtml(operator.template)}</code>
              <div class="tag-row">
                ${operator.engineIds.map((engineId) => renderEngineMini(engineId)).join('')}
              </div>
              <div class="inline">
                <button class="ghost" type="button" data-custom-delete="${escapeHtml(operator.id)}">Delete</button>
              </div>
            </article>
          `
        )
        .join('')}
    </div>
  `;
}

function renderLaunchPreview(
  launchPlans: ReturnType<typeof buildSearchLaunchPlans>
): string {
  if (launchPlans.length === 0) {
    return '<div class="muted">Add targets, query terms, and at least one engine to generate a launch preview.</div>';
  }

  const initialPlans = launchPlans.slice(0, 16);
  const renderPlan = (plan: (typeof launchPlans)[number]) => `
    <li class="plan-card">
      <div class="inline">
        ${renderEngineMini(plan.engine.id)}
        <strong>${escapeHtml(plan.engine.name)}</strong>
        ${plan.target ? `<span class="search-tag">${escapeHtml(plan.target)}</span>` : ''}
      </div>
      <code class="search-code">${escapeHtml(plan.query)}</code>
    </li>`;
  return `
    <ol class="search-plan-list">
      ${initialPlans.map(renderPlan).join('')}
    </ol>
    ${
      launchPlans.length > initialPlans.length
        ? `<details data-disclosure-key="search-launch-preview:remaining">
            <summary>Showing ${initialPlans.length} of ${launchPlans.length} generated search launches · Show ${launchPlans.length - initialPlans.length} more</summary>
            <ol class="search-plan-list" start="${initialPlans.length + 1}">${launchPlans
              .slice(initialPlans.length)
              .map(renderPlan)
              .join('')}</ol>
          </details>`
        : ''
    }
  `;
}

function renderSettingField(field: ModuleSettingsFieldDefinition, value: JsonValue): string {
  const description = field.description ? `<div class="muted">${escapeHtml(field.description)}</div>` : '';
  if (field.type === 'boolean') {
    return `
      <label class="stack">
        <span>${escapeHtml(field.title)}</span>
        <input type="checkbox" data-setting-key="${escapeHtml(field.key)}"${
          value === true ? ' checked' : ''
        } />
        ${description}
      </label>
    `;
  }

  if (field.type === 'number') {
    return `
      <label class="stack">
        <span>${escapeHtml(field.title)}</span>
        <input type="number" data-setting-key="${escapeHtml(field.key)}" value="${Number(value ?? 0)}" />
        ${description}
      </label>
    `;
  }

  if (field.type === 'select') {
    return `
      <label class="stack">
        <span>${escapeHtml(field.title)}</span>
        <select data-setting-key="${escapeHtml(field.key)}">
          ${(field.options ?? [])
            .map(
              (option) => `
                <option value="${escapeHtml(option.value)}"${
                  option.value === value ? ' selected' : ''
                }>${escapeHtml(option.label)}</option>
              `
            )
            .join('')}
        </select>
        ${description}
      </label>
    `;
  }

  return `
    <label class="stack">
      <span>${escapeHtml(field.title)}</span>
      <input type="text" data-setting-key="${escapeHtml(field.key)}" value="${escapeHtml(String(value ?? ''))}" />
      ${description}
    </label>
  `;
}

function renderDocumentSettingField(field: ModuleSettingsFieldDefinition, value: JsonValue): string {
  const description = field.description ? `<div class="muted">${escapeHtml(field.description)}</div>` : '';
  if (field.type === 'boolean') {
    return `
      <label class="stack">
        <span>${escapeHtml(field.title)}</span>
        <span class="toggle-row">
          <input type="checkbox" data-document-setting-key="${escapeHtml(field.key)}"${
            value === true ? ' checked' : ''
          } />
          <span>${value === true ? 'Enabled' : 'Disabled'}</span>
        </span>
        ${description}
      </label>
    `;
  }

  if (field.type === 'number') {
    return `
      <label class="stack">
        <span>${escapeHtml(field.title)}</span>
        <input type="number" data-document-setting-key="${escapeHtml(field.key)}" value="${Number(value ?? 0)}" />
        ${description}
      </label>
    `;
  }

  if (field.type === 'select') {
    return `
      <label class="stack">
        <span>${escapeHtml(field.title)}</span>
        <select data-document-setting-key="${escapeHtml(field.key)}">
          ${(field.options ?? [])
            .map(
              (option) => `
                <option value="${escapeHtml(option.value)}"${
                  option.value === value ? ' selected' : ''
                }>${escapeHtml(option.label)}</option>
              `
            )
            .join('')}
        </select>
        ${description}
      </label>
    `;
  }

  if (field.key === 'interestingKeywords') {
    return `
      <label class="stack search-field-wide">
        <span>${escapeHtml(field.title)}</span>
        <textarea
          class="search-textarea settings-textarea"
          data-document-setting-key="${escapeHtml(field.key)}"
        >${escapeHtml(String(value ?? ''))}</textarea>
        ${description}
      </label>
    `;
  }

  return `
    <label class="stack">
      <span>${escapeHtml(field.title)}</span>
      <input type="text" data-document-setting-key="${escapeHtml(field.key)}" value="${escapeHtml(String(value ?? ''))}" />
      ${description}
    </label>
  `;
}

function renderExportSummary(snapshot?: HostStateSnapshot): string {
  if (!snapshot?.lastExport) {
    return '<div class="muted">No export has been collected yet.</div>';
  }

  const exportPayload = snapshot.lastExport;
  return `
    <div class="summary-grid">
      <div class="panelish"><strong>Artifacts</strong><div>${exportPayload.summary.artifactCount}</div></div>
      <div class="panelish"><strong>Warnings</strong><div>${exportPayload.summary.warningCount}</div></div>
      <div class="panelish"><strong>Errors</strong><div>${exportPayload.summary.errorCount}</div></div>
      <div class="panelish"><strong>Frames</strong><div>${exportPayload.page.frames.length}</div></div>
    </div>
    <div class="muted">Session ${escapeHtml(exportPayload.collection.sessionId)}</div>
    <textarea class="raw-json" readonly>${escapeHtml(
      JSON.stringify(exportPayload, null, 2)
    )}</textarea>
  `;
}

function renderLogs(snapshot?: HostStateSnapshot): string {
  if (!snapshot?.logs.length) {
    return '<div class="muted">No logs recorded yet.</div>';
  }

  return `
    <ul class="log-list">
      ${snapshot.logs
        .map(
          (entry) => `
            <li>
              <strong>[${escapeHtml(entry.level.toUpperCase())}] ${escapeHtml(entry.source)}</strong>
              ${escapeHtml(entry.message)}
            </li>
          `
        )
        .join('')}
    </ul>
  `;
}

function sortProfiles<T extends { updatedAt: string }>(profiles: T[]): T[] {
  return [...profiles].sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
}

function sortCustomOperators<T extends { label: string }>(operators: T[]): T[] {
  return [...operators].sort((left, right) => left.label.localeCompare(right.label));
}

function formatRelativeTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return timestamp;
  }

  return date.toLocaleString();
}

function formatPercent(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function formatBytes(value: number): string {
  if (value < 1024) {
    return `${value} B`;
  }

  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }

  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function formatCandidateValue(value: JsonValue | undefined): string {
  if (value === undefined) {
    return 'unknown';
  }
  if (typeof value === 'string') {
    return value;
  }
  return JSON.stringify(value);
}

function isTargetOutputKind(value: unknown): value is TargetOutputKind {
  return value === 'url' || value === 'params' || value === 'get' || value === 'post';
}

function targetOutputLabel(kind: TargetOutputKind): string {
  switch (kind) {
    case 'url':
      return 'Full URL';
    case 'params':
      return 'URL parameters';
    case 'get':
      return 'GET request';
    case 'post':
      return 'POST request';
  }
}

function buildTargetOutput(rawUrl: string, kind: TargetOutputKind): string {
  switch (kind) {
    case 'url':
      return rawUrl;
    case 'params':
      return getTargetUrlParameters(rawUrl);
    case 'get':
      return buildBurpGetRequest(rawUrl);
    case 'post':
      return buildBurpPostRequest(rawUrl);
  }
}

function formatTargetOutputPreview(rawUrl: string, kind: TargetOutputKind): string {
  try {
    const output = buildTargetOutput(rawUrl, kind);
    return output || '(empty output — this target URL has no parameters)';
  } catch {
    return `${targetOutputLabel(kind)} is unavailable for this target URL.`;
  }
}

function tryParseOrigin(rawUrl?: string): string | undefined {
  if (!rawUrl) {
    return undefined;
  }
  try {
    return new URL(rawUrl).origin;
  } catch {
    return undefined;
  }
}

function isHttpUrl(rawUrl?: string): boolean {
  if (!rawUrl) {
    return false;
  }
  try {
    const protocol = new URL(rawUrl).protocol;
    return protocol === 'http:' || protocol === 'https:';
  } catch {
    return false;
  }
}

function hasUrlParameters(rawUrl?: string): boolean {
  if (!rawUrl) {
    return false;
  }
  try {
    return getTargetUrlParameters(rawUrl).length > 0;
  } catch {
    return false;
  }
}

function normalizePageUrl(rawUrl?: string): string | undefined {
  if (!rawUrl) {
    return undefined;
  }
  try {
    const parsed = new URL(rawUrl);
    parsed.hash = '';
    return parsed.toString();
  } catch {
    return undefined;
  }
}

function maskPageUrl(rawUrl?: string): string | undefined {
  return maskStakeholderUrl(rawUrl);
}

function downloadTextFile(contents: string, filename: string, mimeType: string): void {
  const blobUrl = URL.createObjectURL(new Blob([contents], { type: mimeType }));
  const anchor = document.createElement('a');
  anchor.href = blobUrl;
  anchor.download = filename;
  anchor.rel = 'noopener';
  anchor.hidden = true;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
}

function createEmptyTrafficLedgerSummary(): TrafficLedgerSummary {
  return {
    entryCount: 0,
    byScope: {
      'in-scope': 0,
      'out-of-scope': 0,
      review: 0,
      unknown: 0
    },
    byPriority: {
      low: 0,
      medium: 0,
      high: 0,
      urgent: 0
    },
    handoffEligibleCount: 0,
    highestScore: 0
  };
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
