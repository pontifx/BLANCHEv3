import type {
  BlancheExportV1,
  JsonValue,
  PermissionsState,
  ScopePolicy
} from '../../../shared-schema/src';
import {
  analyzeInterestModel,
  bookmarkTabAsInterestSample,
  createInterestFolder
} from './interestModel';
import { registeredModules } from '../modules';
import type {
  HostStateSnapshot,
  ModuleActionRequest,
  ModuleActionResult,
  ModuleBackgroundController,
  ModuleDefinition,
  ModuleHostServices,
  ModulePersistedState,
  ModuleStateSnapshot
} from '../shared/contracts';
import {
  createDefaultEngagementProfilesState,
  createDefaultScopePolicy,
  normalizeEngagementProfilesState,
  type EngagementProfilesState
} from '../shared/engagementProfiles';
import { isJsonObject, toErrorDetails } from '../shared/helpers';
import { PersistentFeedManager } from './feedManager';
import {
  createDefaultInterestWorkbenchState,
  normalizeInterestWorkbenchState,
  type InterestCurrentTabAnalysis,
  type InterestWorkbenchState
} from '../shared/interestWorkbench';
import {
  createDefaultDocumentWorkbenchState,
  normalizeDocumentWorkbenchState,
  recalculateDocumentSessionCounts,
  type DocumentWorkbenchState
} from '../shared/documentWorkbench';
import {
  createDefaultLatentFeatureWorkbenchState,
  normalizeLatentFeatureWorkbenchState,
  type LatentFeatureWorkbenchState
} from '../shared/latentFeatureWorkbench';
import { createLogger, LogBuffer } from '../shared/logging';
import {
  SEARCH_ENGINES,
  normalizeSearchWorkbenchState,
  parseTargets,
  tryGetHostname,
  type SearchQueryDraft,
  type SearchWorkbenchState
} from '../shared/searchWorkbench';
import {
  createDefaultSearchExecutionState,
  type SearchExecutionState
} from '../shared/searchExecution';
import {
  createDefaultFindingsWorkbenchState,
  type FindingsWorkbenchState
} from '../shared/findingsWorkbench';
import {
  isRuntimeEnvelope,
  type RuntimeEnvelope,
  type RuntimeMessageMap,
  type RuntimeResponseEnvelope
} from '../shared/runtimeBus';
import { ExportBuilder } from './exporter';
import { PersistentSessionManager } from './sessionManager';
import { StateStore } from './stateStore';
import { FindingsManager } from './findingsManager';
import { SearchCoordinator } from './searchCoordinator';
import { TrafficLedgerManager } from './trafficLedgerManager';
import {
  buildDorkSuitePlan,
  buildPortableDorkSuitePlan,
  validateDorkSuitePlan
} from '../shared/searchDorkSuite';
import {
  buildNerdFormSubmission,
  buildNerdSearchUrl,
  discoverNerdSearchSurfacesOnPage,
  getNerdSearchSurfaceTarget,
  highlightNerdSearchSurfaceOnPage,
  pickNerdSearchSurfaceOnPage
} from '../shared/nerdSearch';

export class ExtensionHost {
  private readonly modules: ModuleDefinition[] = registeredModules;
  private readonly controllers = new Map<string, ModuleBackgroundController>();
  private readonly logBuffer = new LogBuffer();
  private readonly logger = createLogger(this.logBuffer, 'host');
  private readonly stateStore = new StateStore();
  private readonly exportBuilder = new ExportBuilder();
  private moduleState = new Map<string, ModulePersistedState>();
  private sessions = new PersistentSessionManager([], async () => {});
  private feed = new PersistentFeedManager([], async () => {});
  private searchWorkbench: SearchWorkbenchState = normalizeSearchWorkbenchState(undefined);
  private searchExecution: SearchExecutionState = createDefaultSearchExecutionState();
  private findingsWorkbench: FindingsWorkbenchState = createDefaultFindingsWorkbenchState();
  private findings?: FindingsManager;
  private searchCoordinator?: SearchCoordinator;
  private interestWorkbench: InterestWorkbenchState = createDefaultInterestWorkbenchState();
  private documentWorkbench: DocumentWorkbenchState = createDefaultDocumentWorkbenchState();
  private latentFeatureWorkbench: LatentFeatureWorkbenchState =
    createDefaultLatentFeatureWorkbenchState();
  private engagementProfiles: EngagementProfilesState = createDefaultEngagementProfilesState();
  private readonly trafficLedger = new TrafficLedgerManager({
    getScopePolicy: () => this.getActiveScopePolicy(),
    getTargetOrigin: ({ initiator }) => tryGetOrigin(initiator),
    deferCaptureUntilReady: true,
    onError: (error, operation) => {
      this.logger.warn('Traffic ledger operation failed', {
        operation,
        error: toErrorDetails(error)
      });
    }
  });
  private lastExport?: BlancheExportV1;
  private initialized = false;
  private readonly lastAutoCaptureKeyByTab = new Map<number, string>();
  private readonly lastAutoLatentFeatureKeyByTab = new Map<number, string>();
  private seededHostnames: string[] = [];

  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    const trafficLedgerInitialization = this.trafficLedger.initialize();
    const persistedState = await this.stateStore.load(this.modules);
    this.moduleState = new Map(Object.entries(persistedState.modules));
    this.lastExport = persistedState.lastExport;
    this.searchWorkbench = persistedState.searchWorkbench;
    this.searchExecution = persistedState.searchExecution;
    this.findingsWorkbench = persistedState.findingsWorkbench;
    this.interestWorkbench = persistedState.interestWorkbench;
    this.documentWorkbench = persistedState.documentWorkbench;
    this.latentFeatureWorkbench = persistedState.latentFeatureWorkbench;
    this.engagementProfiles = persistedState.engagementProfiles;
    await trafficLedgerInitialization;
    await this.trafficLedger.resumeCapture();
    this.seededHostnames = persistedState.seededHostnames;
    this.sessions = new PersistentSessionManager(persistedState.sessions, async () => {
      await this.persist();
    });
    this.feed = new PersistentFeedManager(persistedState.feed, async () => {
      await this.persist();
    });
    this.findings = new FindingsManager(this.findingsWorkbench, async (state) => {
      this.findingsWorkbench = state;
      await this.persist();
    });
    await this.findings.refreshBadge();
    this.searchCoordinator = new SearchCoordinator(
      this.searchExecution,
      async (state) => {
        this.searchExecution = state;
        await this.persist();
      },
      (finding) => this.findings!.add(finding).then(() => undefined),
      (message, context) => this.logger.error(message, context as never)
    );

    for (const module of this.modules) {
      this.controllers.set(
        module.descriptor.id,
        module.createBackgroundController({
          logger: this.logger.child(module.descriptor.id),
          sessions: this.sessions,
          host: this.buildHostServices()
        })
      );
    }

    this.searchCoordinator.resumePending();

    this.registerMessageListener();
    this.registerAutoCaptureListener();
    await this.configureSidePanel();

    for (const module of this.modules) {
      if (this.moduleState.get(module.descriptor.id)?.enabled) {
        await this.controllers.get(module.descriptor.id)?.onHostStart?.();
      }
    }

    this.logger.info('Initialized extension host', {
      moduleCount: this.modules.length,
      sessionCount: this.sessions.list().length
    });
    this.initialized = true;
  }

  private registerMessageListener(): void {
    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (!isRuntimeEnvelope(message)) {
        return false;
      }

      void this.handleRuntimeMessage(message)
        .then((response) => sendResponse(response))
        .catch((error) => {
          this.logger.error('Runtime message failed', {
            messageType: message.type,
            error: toErrorDetails(error)
          });
          sendResponse({
            ok: false,
            error: error instanceof Error ? error.message : String(error)
          } satisfies RuntimeResponseEnvelope<keyof RuntimeMessageMap>);
        });

      return true;
    });
  }

  /**
   * Wires Burp Bridge (and OSINT seeding) into ordinary browsing instead of requiring an operator
   * to open the side panel/DevTools panel and click a command on every page. Fires a non-reloading
   * passive capture whenever an in-scope top-level navigation completes, so Chromium-only data
   * ends up paired with the authorized host/endpoint in Burp automatically as the user browses.
   */
  private registerAutoCaptureListener(): void {
    if (!chrome.webNavigation?.onCompleted) {
      return;
    }

    chrome.webNavigation.onCompleted.addListener((details) => {
      if (details.frameId !== 0) {
        return;
      }
      void this.maybeAutoCapture(details.tabId, details.url);
      void this.maybeAutoSeedOsint(details.tabId, details.url);
      void this.maybeAutoDiscoverLatentFeatures(details.tabId, details.url);
    });
  }

  private async maybeAutoCapture(tabId: number, url: string): Promise<void> {
    if (!/^https?:/i.test(url)) {
      return;
    }

    const moduleId = 'burp-bridge';
    const persistedState = this.moduleState.get(moduleId);
    if (!persistedState?.enabled) {
      return;
    }

    if (persistedState.settings.autoCaptureOnNavigation === false) {
      return;
    }

    const captureKey = `${tabId}:${url}`;
    if (this.lastAutoCaptureKeyByTab.get(tabId) === captureKey) {
      return;
    }
    this.lastAutoCaptureKeyByTab.set(tabId, captureKey);

    try {
      const result = await this.runAction({
        moduleId,
        actionId: 'collectPassive',
        tabId,
        caller: 'background'
      });
      if (result.status === 'error') {
        if (this.lastAutoCaptureKeyByTab.get(tabId) === captureKey) {
          this.lastAutoCaptureKeyByTab.delete(tabId);
        }
        return;
      }
      this.logger.info('Auto-captured Burp Bridge snapshot on navigation', {
        tabId,
        url,
        status: result.status
      });
    } catch (error) {
      if (this.lastAutoCaptureKeyByTab.get(tabId) === captureKey) {
        this.lastAutoCaptureKeyByTab.delete(tabId);
      }
      this.logger.error('Auto-capture on navigation failed', {
        tabId,
        url,
        error: toErrorDetails(error)
      });
    }
  }

  /**
   * Chains a passive OSINT seed onto the first-sight of a new host, so recon starts without the
   * operator having to click "Seed OSINT From Tab" themselves. Debounced per hostname (not per
   * page) so revisiting the same host doesn't reseed it on every navigation.
   */
  private async maybeAutoSeedOsint(tabId: number, url: string): Promise<void> {
    if (!/^https?:/i.test(url)) {
      return;
    }

    const moduleId = 'osint-seed';
    const persistedState = this.moduleState.get(moduleId);
    if (!persistedState?.enabled) {
      return;
    }

    const hostname = extractHostname(url);
    if (!hostname || this.seededHostnames.includes(hostname)) {
      return;
    }
    this.markHostnameSeeded(hostname);

    try {
      const result = await this.runAction({
        moduleId,
        actionId: 'seedTarget',
        tabId,
        caller: 'background'
      });
      const deliveryRequired = persistedState.settings.autoSendToBurp !== false;
      const delivered = result.data?.delivered === true;
      if (result.status === 'error' || (deliveryRequired && !delivered)) {
        this.unmarkHostnameSeeded(hostname);
        return;
      }
      this.logger.info('Auto-chained OSINT seed on first-sight of new host', {
        hostname,
        tabId,
        status: result.status
      });
      this.feed.add({
        kind: 'osint-seed',
        sourceModuleId: moduleId,
        host: hostname,
        severity: 'info',
        title: `Auto-seeded OSINT for ${hostname}`,
        detail: result.message
      });
    } catch (error) {
      this.unmarkHostnameSeeded(hostname);
      this.logger.error('Auto-chained OSINT seed failed', {
        hostname,
        tabId,
        error: toErrorDetails(error)
      });
    } finally {
      await this.persist();
    }
  }

  private async maybeAutoDiscoverLatentFeatures(tabId: number, url: string): Promise<void> {
    if (!/^https?:/i.test(url)) {
      return;
    }

    const moduleId = 'latent-features';
    const persistedState = this.moduleState.get(moduleId);
    if (!persistedState?.enabled || persistedState.settings.autoDiscoverOnNavigation !== true) {
      return;
    }

    const captureKey = `${tabId}:${url}`;
    if (this.lastAutoLatentFeatureKeyByTab.get(tabId) === captureKey) {
      return;
    }
    this.lastAutoLatentFeatureKeyByTab.set(tabId, captureKey);

    try {
      const result = await this.runAction({
        moduleId,
        actionId: 'discover',
        tabId,
        caller: 'background',
        input: {
          automatic: true
        }
      });
      if (result.status === 'error') {
        if (this.lastAutoLatentFeatureKeyByTab.get(tabId) === captureKey) {
          this.lastAutoLatentFeatureKeyByTab.delete(tabId);
        }
        return;
      }
      this.logger.info('Auto-discovered latent client features on navigation', {
        tabId,
        url,
        status: result.status
      });
    } catch (error) {
      if (this.lastAutoLatentFeatureKeyByTab.get(tabId) === captureKey) {
        this.lastAutoLatentFeatureKeyByTab.delete(tabId);
      }
      this.logger.error('Latent feature auto-discovery failed', {
        tabId,
        url,
        error: toErrorDetails(error)
      });
    }
  }

  private markHostnameSeeded(hostname: string): void {
    this.seededHostnames.push(hostname);
    if (this.seededHostnames.length > 500) {
      this.seededHostnames = this.seededHostnames.slice(-500);
    }
  }

  private unmarkHostnameSeeded(hostname: string): void {
    this.seededHostnames = this.seededHostnames.filter((entry) => entry !== hostname);
  }

  private async configureSidePanel(): Promise<void> {
    if (!chrome.sidePanel?.setPanelBehavior) {
      return;
    }

    try {
      await chrome.sidePanel.setPanelBehavior({
        openPanelOnActionClick: true
      });
    } catch (error) {
      this.logger.warn('Unable to configure side panel behavior', {
        error: toErrorDetails(error)
      });
    }
  }

  private async handleRuntimeMessage(
    envelope: RuntimeEnvelope
  ): Promise<RuntimeResponseEnvelope<keyof RuntimeMessageMap>> {
    switch (envelope.type) {
      case 'core/getState': {
        const payload = envelope.payload as RuntimeMessageMap['core/getState']['request'];
        return {
          ok: true,
          payload: this.createHostStateSnapshot(payload.includeLogs ?? true)
        };
      }
      case 'core/toggleModule': {
        const payload = envelope.payload as RuntimeMessageMap['core/toggleModule']['request'];
        await this.toggleModule(payload.moduleId, payload.enabled);
        return {
          ok: true,
          payload: this.createHostStateSnapshot(true)
        };
      }
      case 'core/updateModuleSettings': {
        const payload =
          envelope.payload as RuntimeMessageMap['core/updateModuleSettings']['request'];
        await this.updateModuleSettings(payload.moduleId, payload.settings);
        return {
          ok: true,
          payload: this.createHostStateSnapshot(true)
        };
      }
      case 'core/updateSearchWorkbench': {
        const payload =
          envelope.payload as RuntimeMessageMap['core/updateSearchWorkbench']['request'];
        await this.updateSearchWorkbench(payload.searchWorkbench);
        return {
          ok: true,
          payload: this.createHostStateSnapshot(true)
        };
      }
      case 'core/startSearchSession': {
        const payload = envelope.payload as RuntimeMessageMap['core/startSearchSession']['request'];
        const draft = await this.resolveSearchDraft(payload.tabId);
        await this.searchCoordinator?.start(draft, payload.useDefaultRecipe !== false);
        return { ok: true, payload: this.createHostStateSnapshot(true) };
      }
      case 'core/startDorkSuite': {
        const payload = envelope.payload as RuntimeMessageMap['core/startDorkSuite']['request'];
        const draft = await this.resolveSearchDraft(payload.tabId);
        const plan = buildDorkSuitePlan(draft, this.searchWorkbench.dorkSuiteDraft);
        const validationError = validateDorkSuitePlan(plan);
        if (validationError) {
          throw new Error(validationError);
        }
        await this.searchCoordinator?.startGeneratedSuite({
          draft,
          label: `Dork suite: ${plan.targets.join(', ')}`,
          mode: 'dork-suite',
          targets: plan.targets,
          catalogReviewedAt: plan.catalogReviewedAt,
          tasks: plan.entries.map((entry) => {
            const engine = SEARCH_ENGINES.find((candidate) => candidate.id === entry.engineId);
            if (!engine || !entry.engineId || !entry.searchUrl) {
              throw new Error(`Unable to resolve dork destination ${String(entry.engineId)}.`);
            }
            return {
              category: entry.searchCategory,
              engineId: entry.engineId,
              engineName: engine.name,
              target: entry.target,
              targets: entry.targets,
              query: entry.query,
              searchUrl: entry.searchUrl,
              dorkId: entry.id,
              dorkTitle: entry.title,
              operatorIds: entry.operatorIds,
              dialect: entry.dialect,
              warnings: entry.warnings
            };
          })
        });
        return { ok: true, payload: this.createHostStateSnapshot(true) };
      }
      case 'core/discoverNerdSearchSurfaces': {
        const payload =
          envelope.payload as RuntimeMessageMap['core/discoverNerdSearchSurfaces']['request'];
        const tab = await chrome.tabs.get(payload.tabId);
        if (!/^https?:/i.test(tab.url ?? '')) {
          throw new Error('Site Search can inspect search controls only on HTTP(S) pages.');
        }
        const execution = await chrome.scripting.executeScript({
          target: { tabId: payload.tabId },
          func: discoverNerdSearchSurfacesOnPage
        });
        return {
          ok: true,
          payload: {
            surfaces: execution[0]?.result ?? []
          }
        };
      }
      case 'core/highlightNerdSearchSurface': {
        const payload =
          envelope.payload as RuntimeMessageMap['core/highlightNerdSearchSurface']['request'];
        if (!Number.isInteger(payload.tabId) || payload.tabId < 0) {
          throw new Error('Choose a valid HTTP(S) target tab for top-frame highlighting.');
        }
        if (typeof payload.inputSelector !== 'string' || !payload.inputSelector.trim() || payload.inputSelector.length > 1024) {
          throw new Error('The top-frame search selector must be between 1 and 1024 characters.');
        }
        const tab = await chrome.tabs.get(payload.tabId);
        if (!/^https?:/i.test(tab.url ?? '')) {
          throw new Error('Search highlighting is available only on HTTP(S) target tabs and inspects the top frame only.');
        }
        const execution = await chrome.scripting.executeScript({
          target: { tabId: payload.tabId, frameIds: [0] },
          func: highlightNerdSearchSurfaceOnPage,
          args: [payload.inputSelector]
        });
        const result = execution[0]?.result ?? {
          highlighted: false,
          reason: 'The top frame did not return a highlight result.'
        };
        return {
          ok: true,
          payload: { ...result, topFrameOnly: true }
        };
      }
      case 'core/pickNerdSearchSurface': {
        const payload =
          envelope.payload as RuntimeMessageMap['core/pickNerdSearchSurface']['request'];
        if (!Number.isInteger(payload.tabId) || payload.tabId < 0) {
          throw new Error('Choose a valid HTTP(S) target tab for top-frame search selection.');
        }
        const tab = await chrome.tabs.get(payload.tabId);
        if (!/^https?:/i.test(tab.url ?? '')) {
          throw new Error('Interactive search selection is available only on HTTP(S) target tabs and inspects the top frame only.');
        }
        const pickExecution = await chrome.scripting.executeScript({
          target: { tabId: payload.tabId, frameIds: [0] },
          func: pickNerdSearchSurfaceOnPage
        });
        const picked = pickExecution[0]?.result;
        if (!picked?.selector) {
          return {
            ok: true,
            payload: {
              topFrameOnly: true,
              reason: picked?.reason ?? 'No search control was selected in the top frame.'
            }
          };
        }
        if (picked.selector.length > 1024) {
          throw new Error('The selected top-frame search selector exceeded 1024 characters.');
        }
        const discoveryExecution = await chrome.scripting.executeScript({
          target: { tabId: payload.tabId, frameIds: [0] },
          func: discoverNerdSearchSurfacesOnPage
        });
        const surfaces = discoveryExecution[0]?.result ?? [];
        const surface = surfaces.find((candidate) => candidate.inputSelector === picked.selector);
        return {
          ok: true,
          payload: surface
            ? { surface, selector: picked.selector, topFrameOnly: true }
            : {
                selector: picked.selector,
                topFrameOnly: true,
                reason: 'The selected top-frame control changed before BLANCHE could review it.'
              }
        };
      }
      case 'core/startNerdSuite': {
        const payload = envelope.payload as RuntimeMessageMap['core/startNerdSuite']['request'];
        const surface = this.searchWorkbench.nerdSurfaces.find(
          (candidate) => candidate.id === payload.surfaceId
        );
        if (!surface) {
          throw new Error('Select a saved Site Search surface before launching the suite.');
        }
        const draft = await this.resolveSearchDraft(payload.tabId);
        const siteSearchTarget = getNerdSearchSurfaceTarget(surface);
        const siteSearchDraft = { ...draft, targetsText: siteSearchTarget };
        const plan = buildPortableDorkSuitePlan(
          siteSearchDraft,
          this.searchWorkbench.dorkSuiteDraft,
          siteSearchTarget
        );
        const validationError = validateDorkSuitePlan(plan);
        if (validationError) {
          throw new Error(validationError);
        }
        const nerdSubmission = buildNerdFormSubmission(surface);
        await this.searchCoordinator?.startGeneratedSuite({
          draft: siteSearchDraft,
          label: `Site Search: ${surface.name}`,
          mode: 'nerd',
          targets: plan.targets,
          catalogReviewedAt: plan.catalogReviewedAt,
          tasks: plan.entries.map((entry) => ({
            category: entry.searchCategory,
            engineId: 'nerd' as const,
            engineName: surface.name,
            target: entry.target,
            targets: entry.targets,
            query: entry.query,
            searchUrl: buildNerdSearchUrl(surface, entry.query),
            dorkId: entry.id,
            dorkTitle: entry.title,
            operatorIds: entry.operatorIds,
            dialect: entry.dialect,
            warnings: entry.warnings,
            nerdSurface: surface,
            nerdSubmission
          }))
        });
        return { ok: true, payload: this.createHostStateSnapshot(true) };
      }
      case 'core/updateSearchExecutionSettings': {
        const payload = envelope.payload as RuntimeMessageMap['core/updateSearchExecutionSettings']['request'];
        await this.searchCoordinator?.updateSettings(payload.settings);
        const latentState = this.moduleState.get('latent-features');
        if (latentState) {
          this.moduleState.set('latent-features', {
            ...latentState,
            settings: {
              ...latentState.settings,
              ...(typeof payload.settings.libraryProbeConcurrency === 'number'
                ? { libraryThreadCount: payload.settings.libraryProbeConcurrency }
                : {}),
              ...(typeof payload.settings.libraryProbeDelayMs === 'number'
                ? { libraryDelayMs: payload.settings.libraryProbeDelayMs }
                : {})
            }
          });
          await this.persist();
        }
        return { ok: true, payload: this.createHostStateSnapshot(true) };
      }
      case 'core/answerTesterQuestion': {
        const payload = envelope.payload as RuntimeMessageMap['core/answerTesterQuestion']['request'];
        const question = this.findingsWorkbench.questions.find((entry) => entry.id === payload.questionId);
        const finding = question
          ? this.findingsWorkbench.findings.find((entry) => entry.id === question.findingId)
          : undefined;
        if (payload.actionId === 'apply-probe') {
          const candidateId = finding?.context?.topCandidateId;
          if (typeof candidateId !== 'string' || !candidateId || typeof payload.tabId !== 'number') {
            throw new Error('The reversible candidate or its target tab is no longer available.');
          }
          const result = await this.runAction({
            moduleId: 'latent-features',
            actionId: 'probeCandidate',
            tabId: payload.tabId,
            caller: 'sidepanel',
            input: { candidateId }
          });
          if (result.status === 'error') throw new Error(result.message);
        }
        await this.findings?.answer(payload.questionId, payload.actionId);
        return { ok: true, payload: this.createHostStateSnapshot(true) };
      }
      case 'core/updateInterestWorkbench': {
        const payload =
          envelope.payload as RuntimeMessageMap['core/updateInterestWorkbench']['request'];
        await this.updateInterestWorkbench(payload.interestWorkbench);
        return {
          ok: true,
          payload: this.createHostStateSnapshot(true)
        };
      }
      case 'core/runInterestAction': {
        const payload =
          envelope.payload as RuntimeMessageMap['core/runInterestAction']['request'];
        await this.runInterestAction(payload.action, payload.tabId);
        return {
          ok: true,
          payload: this.createHostStateSnapshot(true)
        };
      }
      case 'core/updateEngagementProfiles': {
        const payload =
          envelope.payload as RuntimeMessageMap['core/updateEngagementProfiles']['request'];
        await this.updateEngagementProfiles(payload.engagementProfiles);
        return {
          ok: true,
          payload: this.createHostStateSnapshot(true)
        };
      }
      case 'core/activateEngagementProfile': {
        const payload =
          envelope.payload as RuntimeMessageMap['core/activateEngagementProfile']['request'];
        await this.activateEngagementProfile(payload.profileId);
        return {
          ok: true,
          payload: this.createHostStateSnapshot(true)
        };
      }
      case 'core/runAction': {
        const payload = envelope.payload as RuntimeMessageMap['core/runAction']['request'];
        return {
          ok: true,
          payload: await this.runAction(payload)
        };
      }
      case 'traffic/query': {
        const payload = envelope.payload as RuntimeMessageMap['traffic/query']['request'];
        return {
          ok: true,
          payload: await this.trafficLedger.query(payload)
        };
      }
      case 'traffic/export': {
        const payload = envelope.payload as RuntimeMessageMap['traffic/export']['request'];
        return {
          ok: true,
          payload: await this.trafficLedger.buildExport({
            sourceSessionId: payload.sourceSessionId ?? `operator_${Date.now().toString(36)}`,
            tabId: payload.tabId,
            targetOrigin: payload.targetOrigin,
            since: payload.since,
            limit: payload.limit
          })
        };
      }
      case 'traffic/updateSettings': {
        const payload =
          envelope.payload as RuntimeMessageMap['traffic/updateSettings']['request'];
        await this.trafficLedger.updateSettings(payload);
        return {
          ok: true,
          payload: this.trafficLedger.getSummary()
        };
      }
      case 'traffic/clear': {
        await this.trafficLedger.clear();
        return {
          ok: true,
          payload: this.trafficLedger.getSummary()
        };
      }
      default:
        return {
          ok: false,
          error: `Unhandled runtime message: ${String(envelope.type)}`
        };
    }
  }

  private createHostStateSnapshot(includeLogs: boolean): HostStateSnapshot {
    return {
      modules: this.createModuleStateSnapshots(),
      sessions: this.sessions.list(),
      logs: includeLogs ? this.logBuffer.getEntries(30) : [],
      searchWorkbench: this.searchWorkbench,
      searchExecution: this.searchExecution,
      findingsWorkbench: this.findingsWorkbench,
      interestWorkbench: this.interestWorkbench,
      documentWorkbench: this.documentWorkbench,
      latentFeatureWorkbench: this.latentFeatureWorkbench,
      engagementProfiles: this.engagementProfiles,
      feed: this.feed.list(),
      trafficLedgerSummary: this.trafficLedger.getSummary(),
      lastExport: this.lastExport
    };
  }

  private createModuleStateSnapshots(): ModuleStateSnapshot[] {
    return this.modules.map((module) => {
      const state = this.moduleState.get(module.descriptor.id);
      return {
        descriptor: module.descriptor,
        enabled: state?.enabled ?? true,
        settings: state?.settings ?? {}
      };
    });
  }

  private async toggleModule(moduleId: string, enabled: boolean): Promise<void> {
    const module = this.modules.find((candidate) => candidate.descriptor.id === moduleId);
    if (!module) {
      throw new Error(`Unknown module: ${moduleId}`);
    }

    const current = this.moduleState.get(moduleId);
    if (!current) {
      throw new Error(`No persisted state for module: ${moduleId}`);
    }

    if (current.enabled === enabled) {
      return;
    }

    this.moduleState.set(moduleId, {
      ...current,
      enabled
    });
    await this.persist();

    const controller = this.controllers.get(moduleId);
    if (enabled) {
      await controller?.onModuleEnabled?.();
    } else {
      await controller?.onModuleDisabled?.();
    }

    this.logger.info(`Module ${enabled ? 'enabled' : 'disabled'}`, {
      moduleId
    });
  }

  private async updateModuleSettings(
    moduleId: string,
    settings: Record<string, JsonValue>
  ): Promise<void> {
    const current = this.moduleState.get(moduleId);
    if (!current) {
      throw new Error(`Unknown module: ${moduleId}`);
    }

    this.moduleState.set(moduleId, {
      ...current,
      settings: {
        ...current.settings,
        ...settings
      }
    });
    await this.persist();
  }

  private async updateSearchWorkbench(searchWorkbench: SearchWorkbenchState): Promise<void> {
    this.searchWorkbench = normalizeSearchWorkbenchState(searchWorkbench);
    await this.persist();
  }

  private async resolveSearchDraft(tabId?: number): Promise<SearchQueryDraft> {
    const draft = { ...this.searchWorkbench.draft };
    if (parseTargets(draft.targetsText).length > 0) {
      return draft;
    }
    const tab = typeof tabId === 'number'
      ? await chrome.tabs.get(tabId)
      : (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
    const hostname = tryGetHostname(tab?.url);
    if (hostname) {
      draft.targetsText = hostname;
    }
    return draft;
  }

  private async updateInterestWorkbench(
    interestWorkbench: InterestWorkbenchState
  ): Promise<void> {
    this.interestWorkbench = normalizeInterestWorkbenchState(interestWorkbench);
    await this.persist();
  }

  private async updateEngagementProfiles(
    engagementProfiles: EngagementProfilesState
  ): Promise<void> {
    this.engagementProfiles = normalizeEngagementProfilesState(engagementProfiles);
    await this.persist();
  }

  /**
   * Applies a saved profile's bundled settings/enablement across every module in one call,
   * instead of the operator hand-toggling each module. Activating the profile also makes its
   * structured scope policy authoritative for capture and automatic actions; `scopeNotes`
   * remains descriptive operator context.
   */
  private async activateEngagementProfile(profileId: string): Promise<void> {
    const profile = this.engagementProfiles.savedProfiles.find((entry) => entry.id === profileId);
    if (!profile) {
      throw new Error(`Unknown engagement profile: ${profileId}`);
    }

    for (const module of this.modules) {
      const moduleId = module.descriptor.id;
      const current = this.moduleState.get(moduleId);
      if (!current) {
        continue;
      }

      const shouldEnable = profile.enabledModuleIds.includes(moduleId);
      const bundledSettings = profile.moduleSettings[moduleId];

      this.moduleState.set(moduleId, {
        enabled: shouldEnable,
        settings: bundledSettings ? { ...current.settings, ...bundledSettings } : current.settings
      });

      const controller = this.controllers.get(moduleId);
      if (current.enabled !== shouldEnable) {
        if (shouldEnable) {
          await controller?.onModuleEnabled?.();
        } else {
          await controller?.onModuleDisabled?.();
        }
      }
    }

    this.engagementProfiles = {
      ...this.engagementProfiles,
      activeProfileId: profile.id,
      activatedAt: new Date().toISOString()
    };
    await this.persist();
    this.logger.info('Activated engagement profile', {
      profileId,
      profileName: profile.name
    });
  }

  private async runInterestAction(
    action: RuntimeMessageMap['core/runInterestAction']['request']['action'],
    tabId?: number
  ): Promise<void> {
    const currentSettings = this.interestWorkbench.settings;

    switch (action) {
      case 'create-folder': {
        this.interestWorkbench = {
          ...this.interestWorkbench,
          settings: await createInterestFolder(currentSettings)
        };
        break;
      }
      case 'bookmark-tab': {
        const result = await bookmarkTabAsInterestSample(currentSettings, tabId);
        this.interestWorkbench = {
          settings: result.settings,
          lastAnalysis: result.analysis
        };
        break;
      }
      case 'analyze': {
        const result = await analyzeInterestModel(currentSettings, tabId);
        this.interestWorkbench = {
          settings: result.settings,
          lastAnalysis: result.analysis
        };
        this.recordInterestScoreFinding(result.analysis.currentTab);
        break;
      }
      default:
        throw new Error(`Unsupported interest action: ${String(action)}`);
    }

    await this.persist();
  }

  private recordInterestScoreFinding(currentTab: InterestCurrentTabAnalysis | undefined): void {
    if (!currentTab) {
      return;
    }

    const overallPercent = Math.round(currentTab.rating.overall * 100);
    this.feed.add({
      kind: 'interest-score',
      sourceModuleId: 'interest-model',
      host: currentTab.hostname,
      severity: overallPercent >= 60 ? 'notice' : 'info',
      title: `Interest score ${overallPercent}% for ${currentTab.hostname ?? currentTab.title}`,
      detail:
        currentTab.rating.matchedSignals.length > 0
          ? `Matched signals: ${currentTab.rating.matchedSignals.join(', ')}`
          : undefined,
      context: {
        url: currentTab.url
      }
    });
  }

  private async runAction(
    payload: RuntimeMessageMap['core/runAction']['request']
  ): Promise<ModuleActionResult> {
    const module = this.modules.find((candidate) => candidate.descriptor.id === payload.moduleId);
    if (!module) {
      return {
        status: 'error',
        message: `Unknown module: ${payload.moduleId}`
      };
    }

    const persistedState = this.moduleState.get(module.descriptor.id);
    if (!persistedState?.enabled) {
      return {
        status: 'error',
        message: `Module ${module.descriptor.name} is disabled`
      };
    }

    const scopeError = await this.getAutomatedScopeError(payload);
    if (scopeError) {
      this.logger.warn('Blocked automatic module action outside executable scope', {
        moduleId: payload.moduleId,
        actionId: payload.actionId,
        tabId: payload.tabId ?? null,
        reason: scopeError
      });
      return {
        status: 'error',
        message: scopeError,
        errors: [
          {
            code: 'TRAFFIC_SCOPE_BLOCKED',
            message: scopeError,
            recoverable: true
          }
        ]
      };
    }

    const controller = this.controllers.get(module.descriptor.id);
    if (!controller) {
      return {
        status: 'error',
        message: `No background controller registered for ${module.descriptor.id}`
      };
    }

    const request: ModuleActionRequest = {
      actionId: payload.actionId,
      tabId: payload.tabId,
      caller: payload.caller,
      input: payload.input
    };

    try {
      const result = await controller.runAction(request, {
        descriptor: module.descriptor,
        settings: persistedState.settings,
        logger: this.logger.child(`${module.descriptor.id}/action/${payload.actionId}`),
        sessions: this.sessions,
        services: this.buildHostServices()
      });

      if (result.status === 'error') {
        this.logger.error('Module action returned an error', {
          moduleId: module.descriptor.id,
          actionId: payload.actionId,
          message: result.message
        });
      }

      if (result.export) {
        this.lastExport = result.export;
        await this.persist();
      }

      return result;
    } catch (error) {
      this.logger.error('Module action threw', {
        moduleId: module.descriptor.id,
        actionId: payload.actionId,
        error: toErrorDetails(error)
      });
      return {
        status: 'error',
        message: error instanceof Error ? error.message : String(error),
        errors: [
          {
            code: 'ACTION_FAILED',
            message: error instanceof Error ? error.message : String(error),
            recoverable: true,
            context: isJsonObject(error) ? error : undefined
          }
        ]
      };
    }
  }

  /**
   * Single source of truth for the services handed to every module, at both construction time
   * (`createBackgroundController`'s `host` field) and per-action time (`runAction`'s `services`
   * field) — previously duplicated verbatim at both call sites.
   */
  private buildHostServices(): ModuleHostServices {
    return {
      buildExport: (input) => this.exportBuilder.build(input),
      getTrafficLedgerExport: (input) => this.trafficLedger.buildExport(input),
      evaluateTrafficScope: (rawUrl, method) =>
        this.trafficLedger.evaluateUrl(rawUrl, method),
      getDocumentWorkbenchState: () => this.documentWorkbench,
      getLatentFeatureWorkbenchState: () => this.latentFeatureWorkbench,
      getModuleStates: () => this.createModuleStateSnapshots(),
      getPermissionsState: () => this.getPermissionsState(),
      getProductVersion: () => chrome.runtime.getManifest().version,
      getRecentLogs: (limit) => this.logBuffer.getEntries(limit),
      saveLastExport: async (payload) => {
        this.lastExport = payload;
        await this.persist();
      },
      updateDocumentWorkbenchState: async (documentWorkbench) => {
        this.documentWorkbench = recalculateDocumentSessionCounts(
          normalizeDocumentWorkbenchState(documentWorkbench)
        );
        await this.persist();
      },
      updateLatentFeatureWorkbenchState: async (latentFeatureWorkbench) => {
        this.latentFeatureWorkbench =
          normalizeLatentFeatureWorkbenchState(latentFeatureWorkbench);
        await this.persist();
      },
      updateModulePersistedState: async (moduleId, state) => {
        this.moduleState.set(moduleId, state);
        await this.persist();
      },
      runModuleAction: (moduleId, actionId, tabId, input) =>
        this.runAction({ moduleId, actionId, tabId, caller: 'background', input }),
      recordFinding: async (entry) => {
        this.feed.add(entry);
      },
      recordIntelligenceFinding: async (entry) => {
        await this.findings?.add(entry);
      }
    };
  }

  private async getPermissionsState(): Promise<PermissionsState> {
    const granted = await chrome.permissions.getAll();
    return {
      grantedPermissions: granted.permissions ?? [],
      grantedHostPermissions: granted.origins ?? [],
      moduleRequirements: this.modules.map((module) => ({
        moduleId: module.descriptor.id,
        requiredPermissions: module.descriptor.requiredPermissions,
        requiredHostPermissions: module.descriptor.requiredHostPermissions
      }))
    };
  }

  private getActiveScopePolicy(): ScopePolicy {
    const activeProfile = this.engagementProfiles.savedProfiles.find(
      (profile) => profile.id === this.engagementProfiles.activeProfileId
    );
    return activeProfile?.scopePolicy ?? createDefaultScopePolicy();
  }

  private async getAutomatedScopeError(
    payload: RuntimeMessageMap['core/runAction']['request']
  ): Promise<string | undefined> {
    if (payload.caller !== 'background') {
      return undefined;
    }

    if (typeof payload.tabId !== 'number') {
      return `Automatic ${payload.moduleId}/${payload.actionId} was not run because it has no target tab to evaluate against executable scope.`;
    }

    const tab = await chrome.tabs.get(payload.tabId);
    if (!/^https?:/i.test(tab.url ?? '')) {
      return `Automatic ${payload.moduleId}/${payload.actionId} was not run because the target tab URL is not an http(s) scope target.`;
    }

    const decision = this.trafficLedger.evaluateUrl(tab.url!, 'GET');
    if (decision.disposition === 'in-scope') {
      return undefined;
    }

    return `Automatic ${payload.moduleId}/${payload.actionId} was not run because ${
      tab.url
    } is ${decision.disposition} under scope policy ${decision.policyId} v${
      decision.policyVersion
    }.`;
  }

  private async persist(): Promise<void> {
    await this.stateStore.save({
      modules: Object.fromEntries(this.moduleState.entries()),
      sessions: this.sessions.list(),
      searchWorkbench: this.searchWorkbench,
      searchExecution: this.searchExecution,
      findingsWorkbench: this.findingsWorkbench,
      interestWorkbench: this.interestWorkbench,
      documentWorkbench: this.documentWorkbench,
      latentFeatureWorkbench: this.latentFeatureWorkbench,
      engagementProfiles: this.engagementProfiles,
      feed: this.feed.list(),
      seededHostnames: this.seededHostnames,
      lastExport: this.lastExport
    });
  }
}

function extractHostname(url: string): string | undefined {
  try {
    const hostname = new URL(url).hostname.trim().toLowerCase();
    return hostname || undefined;
  } catch {
    return undefined;
  }
}

function tryGetOrigin(rawUrl?: string): string | undefined {
  if (!rawUrl) {
    return undefined;
  }
  try {
    const origin = new URL(rawUrl).origin;
    return origin === 'null' ? undefined : origin;
  } catch {
    return undefined;
  }
}
