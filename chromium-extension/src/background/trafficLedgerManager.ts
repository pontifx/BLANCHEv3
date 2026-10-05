import type {
  BlancheTrafficLedgerV1,
  ScopeDecision,
  ScopePolicy,
  TrafficLedgerEntry,
  TrafficLedgerSummary,
  TrafficScopeDisposition
} from '../../../shared-schema/src';
import {
  buildTrafficLedger,
  buildTrafficLedgerEntry,
  canonicalizeTrafficEndpoint,
  mergeTrafficLedgerEntries,
  queryTrafficLedger,
  summarizeTrafficLedgerEntries,
  type TrafficObservationInput
} from '../shared/trafficLedger';
import {
  evaluateTrafficScope,
  normalizeScopePolicy,
  type ScopeOriginContext
} from '../shared/scopePolicy';

const DEFAULT_STORAGE_KEY = 'blanche.trafficLedger.capture.v1';
const DEFAULT_TARGET_SESSION_STORAGE_KEY = 'blanche.trafficLedger.targets.v1';
const DEFAULT_COVERAGE_STORAGE_KEY = 'blanche.trafficLedger.coverage.v1';
const DEFAULT_COVERAGE_SESSION_STORAGE_KEY = 'blanche.trafficLedger.coverage.session.v1';
const STORAGE_VERSION = 1;
const DEFAULT_MAX_ENTRIES = 1_000;
const MIN_MAX_ENTRIES = 1;
const MAX_MAX_ENTRIES = 5_000;
const MAX_PERSISTED_BYTES = 3_000_000;
const MAX_PENDING_REQUESTS = 1_000;
const MAX_DEFERRED_EVENTS = 4_000;
const MAX_PENDING_AGE_MS = 5 * 60 * 1_000;
const MAX_COMMIT_REQUEST_REORDER_MS = 10_000;
const PERSIST_DEBOUNCE_MS = 750;
const MAX_COVERAGE_PERSIST_RETRIES = 3;
const MAX_METADATA_NAMES = 128;
const MAX_SOURCE_ORIGINS = 64;
const MAX_EVIDENCE_REFERENCES = 24;
const MAX_CONTEXT_VALUE_LENGTH = 128;

const WEB_REQUEST_FILTER: chrome.webRequest.RequestFilter = {
  urls: ['http://*/*', 'https://*/*', 'ws://*/*', 'wss://*/*']
};

export interface TrafficOriginLookup {
  tabId: number;
  requestUrl: string;
  initiator?: string;
}

export interface TrafficLedgerManagerSettings {
  enabled: boolean;
  maxEntries: number;
}

export interface TrafficLedgerManagerOptions {
  getScopePolicy: () => ScopePolicy;
  getTargetOrigin?: (context: TrafficOriginLookup) => string | undefined;
  deferCaptureUntilReady?: boolean;
  storageKey?: string;
  settings?: Partial<TrafficLedgerManagerSettings>;
  onError?: (error: unknown, operation: string) => void;
}

export interface TrafficLedgerManagerQuery {
  tabId?: number;
  sourceOrigin?: string;
  targetOrigin?: string;
  since?: string;
  scope?: TrafficScopeDisposition | TrafficScopeDisposition[];
  minScore?: number;
  limit?: number;
}

export interface TrafficLedgerManagerQueryResult {
  entries: TrafficLedgerEntry[];
  summary: TrafficLedgerSummary;
  totalMatchedEntries: number;
  truncated: boolean;
  observationWindowStart?: string;
}

export interface TrafficLedgerExportInput {
  sourceSessionId: string;
  tabId?: number;
  targetOrigin?: string;
  since?: string;
  limit?: number;
}

interface PendingTrafficObservation {
  generation: number;
  hop: number;
  requestId: string;
  tabId: number;
  sourceOrigin?: string;
  targetContextId?: string;
  targetStartedAt?: string;
  policy: ScopePolicy;
  scopeDecision: ScopeDecision;
  originContext: ScopeOriginContext;
  observation: TrafficObservationInput;
  lastEventAt: number;
}

interface PersistedTrafficRecord {
  entry: TrafficLedgerEntry;
  tabId: number;
  sourceOrigin?: string;
  targetOrigin?: string;
  targetContextId?: string;
  targetStartedAt?: string;
  lastCapturedAt: string;
}

interface PersistedTrafficLedgerState {
  version: typeof STORAGE_VERSION;
  updatedAt: string;
  settings: TrafficLedgerManagerSettings;
  records: PersistedTrafficRecord[];
  droppedEntryCount?: number;
  coverageGapCodes?: string[];
}

interface PersistedTrackedTargetState {
  version: typeof STORAGE_VERSION;
  targets: Record<string, TrackedTargetTab>;
  pendingNavigations?: Record<string, TrackedTargetTransition>;
  committedNavigations?: Record<string, CommittedNavigationMarker>;
}

interface PersistedCoverageMarker {
  version: typeof STORAGE_VERSION;
  reasonCodes: string[];
}

interface SanitizedTrafficUrl {
  url: string;
  queryParameterNames: string[];
}

interface SafeResponseMetadata {
  contentType?: string;
  contentLength?: number;
  protocol?: string;
}

interface TrackedTargetTab {
  targetOrigin: string;
  policyId: string;
  policyVersion: string;
  contextId?: string;
  startedAt?: string;
}

interface TrackedTargetTransition {
  tabId: number;
  sanitizedUrl: string;
  startedAt: string;
  lastObservedAt: string;
  nextTarget?: TrackedTargetTab;
  attributionTarget?: TrackedTargetTab;
  committedDocumentId?: string;
}

interface CommittedNavigationMarker {
  sanitizedUrl?: string;
  documentId: string;
  committedAt: string;
  contextId: string;
  startedAt: string;
  acceptLateRequest: boolean;
  target?: TrackedTargetTab;
}

/**
 * Passively records browser traffic. It never cancels, redirects, or modifies a request;
 * callers can use evaluateUrl separately when enforcing an active action boundary.
 */
export class TrafficLedgerManager {
  private readonly options: TrafficLedgerManagerOptions;
  private readonly storageKey: string;
  private readonly targetSessionStorageKey: string;
  private readonly coverageStorageKey: string;
  private readonly coverageSessionStorageKey: string;
  private readonly settingOverrides: Partial<TrafficLedgerManagerSettings>;
  private settings: TrafficLedgerManagerSettings;
  private readonly records = new Map<string, PersistedTrafficRecord>();
  private readonly pending = new Map<string, PendingTrafficObservation>();
  private readonly trackedTargetTabs = new Map<number, TrackedTargetTab>();
  private readonly trackedTargetTransitions = new Map<string, TrackedTargetTransition>();
  private readonly committedNavigations = new Map<number, CommittedNavigationMarker>();
  private readonly redirectHops = new Map<string, number>();
  private readonly redirectTargets = new Map<string, TrackedTargetTab>();
  private readonly ignoredRequestIds = new Set<string>();
  private readonly deferredEvents: Array<() => void> = [];
  private readonly coverageGapCodes = new Set<string>();
  private readonly finalizations = new Set<Promise<void>>();
  private initializationPromise?: Promise<void>;
  private writeTail: Promise<void> = Promise.resolve();
  private targetWriteTail: Promise<void> = Promise.resolve();
  private persistTimer?: ReturnType<typeof setTimeout>;
  private coveragePersistTimer?: ReturnType<typeof setTimeout>;
  private coveragePersistRetryCount = 0;
  private dirty = false;
  private listening = false;
  private captureReady = false;
  private captureStopped = false;
  private generation = 0;
  private droppedEntryCount = 0;

  constructor(options: TrafficLedgerManagerOptions) {
    this.options = options;
    this.storageKey = options.storageKey?.trim() || DEFAULT_STORAGE_KEY;
    this.targetSessionStorageKey =
      this.storageKey === DEFAULT_STORAGE_KEY
        ? DEFAULT_TARGET_SESSION_STORAGE_KEY
        : `${this.storageKey}.targets`;
    this.coverageStorageKey =
      this.storageKey === DEFAULT_STORAGE_KEY
        ? DEFAULT_COVERAGE_STORAGE_KEY
        : `${this.storageKey}.coverage`;
    this.coverageSessionStorageKey =
      this.storageKey === DEFAULT_STORAGE_KEY
        ? DEFAULT_COVERAGE_SESSION_STORAGE_KEY
        : `${this.storageKey}.coverage.session`;
    this.settingOverrides = { ...options.settings };
    this.settings = normalizeManagerSettings({
      enabled: options.settings?.enabled ?? true,
      maxEntries: options.settings?.maxEntries ?? DEFAULT_MAX_ENTRIES
    });

    // MV3 event listeners must be registered synchronously during service-worker startup.
    this.registerListeners();
    void this.initialize();
  }

  initialize(): Promise<void> {
    if (!this.captureStopped) {
      this.registerListeners();
    }
    if (!this.initializationPromise) {
      this.initializationPromise = this.loadPersistedState()
        .catch((error) => {
          return this.noteLoadFailure(error);
        })
        .then(() => {
          if (!this.options.deferCaptureUntilReady) {
            this.releaseDeferredEvents();
          }
        });
    }
    return this.initializationPromise;
  }

  async resumeCapture(): Promise<void> {
    await this.initializeWithoutRestart();
    this.releaseDeferredEvents();
  }

  start(): Promise<void> {
    this.captureStopped = false;
    this.registerListeners();
    return this.initializeWithoutRestart();
  }

  getSummary(): TrafficLedgerSummary {
    return summarizeTrafficLedgerEntries(this.currentEntries());
  }

  async query(
    input: TrafficLedgerManagerQuery = {}
  ): Promise<TrafficLedgerManagerQueryResult> {
    await this.initialize();
    await this.drainFinalizations();
    this.evictStaleTargetTransitions(Date.now());

    const sourceOrigin = input.sourceOrigin
      ? sanitizeOrigin(input.sourceOrigin)
      : undefined;
    const targetOrigin = input.targetOrigin
      ? sanitizeOrigin(input.targetOrigin)
      : undefined;
    const activeTarget =
      input.tabId !== undefined && targetOrigin
        ? this.getTrackedTarget(input.tabId, this.getPolicy())
        : undefined;
    const useActiveNavigationWindow =
      !input.since &&
      activeTarget?.targetOrigin === targetOrigin &&
      Boolean(activeTarget?.startedAt);
    const observationWindowStart = useActiveNavigationWindow
      ? activeTarget?.startedAt
      : input.since;
    const scopedEntries = this.entriesForContext(
      input.tabId,
      sourceOrigin,
      useActiveNavigationWindow ? undefined : targetOrigin,
      observationWindowStart,
      useActiveNavigationWindow ? activeTarget?.contextId : undefined
    );
    const scope = input.scope
      ? Array.isArray(input.scope)
        ? input.scope
        : [input.scope]
      : undefined;
    const matchedEntries = queryTrafficLedger(scopedEntries, {
      scope,
      minimumScore: input.minScore
    });
    const limit = normalizeLimit(input.limit, this.settings.maxEntries);
    const entries = matchedEntries.slice(0, limit);

    return {
      entries,
      summary: summarizeTrafficLedgerEntries(entries),
      totalMatchedEntries: matchedEntries.length,
      truncated: entries.length < matchedEntries.length,
      observationWindowStart
    };
  }

  async buildExport(input: TrafficLedgerExportInput): Promise<BlancheTrafficLedgerV1> {
    const sourceSessionId = input.sourceSessionId.trim();
    if (!sourceSessionId) {
      throw new Error('A non-empty sourceSessionId is required for a traffic ledger export.');
    }
    const since = input.since ? normalizeTimestamp(input.since) : undefined;
    if (input.since && !since) {
      throw new Error(`Invalid traffic ledger export timestamp: ${input.since}`);
    }

    const requestedTargetOrigin = sanitizeOptionalOrigin(input.targetOrigin);
    const queryResult = await this.query({
      tabId: input.tabId,
      targetOrigin: since ? undefined : requestedTargetOrigin,
      since,
      limit: input.limit
    });
    const { entries } = queryResult;
    const policy = this.getPolicy();
    const firstRequestUrl = entries[0]
      ? endpointToSanitizedUrl(entries[0].endpoint)
      : 'https://blanche.invalid/';
    const targetOrigin =
      requestedTargetOrigin ??
      sanitizeOptionalOrigin(
        this.resolveTargetOrigin({
          tabId: input.tabId ?? -1,
          requestUrl: firstRequestUrl
        })
      );
    const base = await buildTrafficLedger({
      sourceSessionId,
      observationWindowStart: queryResult.observationWindowStart,
      observationWindowBasis: queryResult.observationWindowStart
        ? 'retained-last-seen'
        : undefined,
      settings: {
        scopePolicy: policy,
        originContext: targetOrigin ? { targetOrigin } : {}
      },
      observations: []
    });

    return {
      ...base,
      metadata: {
        ...base.metadata,
        captureCoverage: {
          retainedEntryLimit: this.settings.maxEntries,
          persistedByteLimit: MAX_PERSISTED_BYTES,
          droppedEntryCount: this.droppedEntryCount,
          retentionLossScope: 'store-wide-conservative',
          availableEntryCount: queryResult.totalMatchedEntries,
          exportedEntryCount: entries.length,
          truncated:
            this.droppedEntryCount > 0 ||
            this.coverageGapCodes.size > 0 ||
            queryResult.truncated,
          reasonCodes: uniqueSorted([
            ...this.coverageGapCodes,
            ...(queryResult.truncated ? ['EXPORT_ENTRY_LIMIT_REACHED'] : [])
          ])
        }
      },
      entries,
      summary: summarizeTrafficLedgerEntries(entries)
    };
  }

  evaluateUrl(rawUrl: string, method?: string): ScopeDecision {
    const policy = this.getPolicy();
    const evaluatedAt = new Date().toISOString();
    try {
      const endpoint = canonicalizeTrafficEndpoint(rawUrl, method);
      return evaluateTrafficScope(policy, {
        endpoint,
        rawUrl,
        evaluatedAt
      });
    } catch {
      return {
        disposition: 'unknown',
        confidence: 'low',
        basis: 'default',
        policyId: policy.policyId,
        policyVersion: policy.version,
        matchedRuleIds: [],
        reasonCodes: ['SCOPE_URL_INVALID_OR_UNSUPPORTED'],
        evaluatedAt
      };
    }
  }

  async updateSettings(
    update: Partial<TrafficLedgerManagerSettings>
  ): Promise<void> {
    await this.initialize();
    const wasEnabled = this.settings.enabled;
    this.settings = normalizeManagerSettings({
      enabled: update.enabled ?? this.settings.enabled,
      maxEntries: update.maxEntries ?? this.settings.maxEntries
    });

    if (wasEnabled && !this.settings.enabled) {
      for (const pending of this.pending.values()) {
        addCoverageGap(pending.observation, 'CAPTURE_DISABLED_BEFORE_COMPLETION');
        this.queueFinalization(pending);
      }
      this.pending.clear();
      this.redirectHops.clear();
      this.redirectTargets.clear();
      this.trackedTargetTabs.clear();
      this.trackedTargetTransitions.clear();
      this.committedNavigations.clear();
      this.persistTrackedTargets();
      await this.drainFinalizations();
    }

    this.enforceEntryCapacity();
    this.markDirty();
    await this.flushPersistence();
  }

  async clear(): Promise<void> {
    this.generation += 1;
    for (const requestId of this.pending.keys()) {
      this.ignoredRequestIds.add(requestId);
    }
    this.pending.clear();
    this.redirectHops.clear();
    this.redirectTargets.clear();
    await this.initialize();
    await this.drainFinalizations();
    this.records.clear();
    this.droppedEntryCount = 0;
    this.coverageGapCodes.clear();
    this.markDirty();
    await this.flushPersistence();
    if (this.coveragePersistTimer) {
      clearTimeout(this.coveragePersistTimer);
      this.coveragePersistTimer = undefined;
    }
    this.coveragePersistRetryCount = 0;
    await Promise.all([
      chrome.storage.local.remove(this.coverageStorageKey),
      chrome.storage.session.remove(this.coverageSessionStorageKey)
    ]);
  }

  async stop(): Promise<void> {
    this.captureStopped = true;
    this.unregisterListeners();
    for (const pending of this.pending.values()) {
      addCoverageGap(pending.observation, 'CAPTURE_STOPPED_BEFORE_COMPLETION');
      this.queueFinalization(pending);
    }
    this.pending.clear();
    this.redirectHops.clear();
    this.redirectTargets.clear();
    this.deferredEvents.length = 0;
    this.trackedTargetTabs.clear();
    this.trackedTargetTransitions.clear();
    this.committedNavigations.clear();
    this.persistTrackedTargets();
    await this.initializeWithoutRestart();
    await this.drainFinalizations();
    await this.flushPersistence();
    await this.targetWriteTail;
  }

  private readonly onBeforeRequest = (
    details: chrome.webRequest.OnBeforeRequestDetails
  ): chrome.webRequest.BlockingResponse | undefined => {
    if (!this.captureReady) {
      this.deferEvent(() => this.onBeforeRequest(details));
      return undefined;
    }
    if (!this.settings.enabled || this.ignoredRequestIds.has(details.requestId)) {
      return undefined;
    }

    const existing = this.pending.get(details.requestId);
    if (existing) {
      addCoverageGap(existing.observation, 'REQUEST_ID_REUSED_BEFORE_TERMINAL_EVENT');
      this.queueFinalization(existing);
      this.pending.delete(details.requestId);
    }

    const pending = this.createPendingObservation(details);
    if (!pending) {
      return undefined;
    }
    const requestBodyFieldNames = metadataNames(
      details.requestBody?.formData ? Object.keys(details.requestBody.formData) : [],
      'field'
    );
    pending.observation.requestBodyFieldNames = requestBodyFieldNames;
    if (requestBodyFieldNames.length > 0) {
      addCoverageGap(pending.observation, 'REQUEST_BODY_VALUES_REDACTED');
    } else if (details.requestBody) {
      addCoverageGap(pending.observation, 'REQUEST_BODY_FIELDS_UNAVAILABLE');
    }
    if (details.requestBody?.error) {
      addCoverageGap(pending.observation, 'REQUEST_BODY_PARSE_ERROR');
    }

    this.pending.set(details.requestId, pending);
    this.evictStalePending(details.timeStamp);
    return undefined;
  };

  private readonly onBeforeSendHeaders = (
    details: chrome.webRequest.OnBeforeSendHeadersDetails
  ): chrome.webRequest.BlockingResponse | undefined => {
    if (!this.captureReady) {
      this.deferEvent(() => this.onBeforeSendHeaders(details));
      return undefined;
    }
    if (!this.settings.enabled || this.ignoredRequestIds.has(details.requestId)) {
      return undefined;
    }
    const pending = this.getOrCreatePending(details);
    if (!pending) {
      return undefined;
    }
    const names = headerNames(details.requestHeaders);
    pending.observation.requestHeaderNames = mergeNames(
      pending.observation.requestHeaderNames,
      names
    );
    if (names.length > 0) {
      addCoverageGap(pending.observation, 'REQUEST_HEADER_VALUES_REDACTED');
    }
    pending.lastEventAt = details.timeStamp;
    return undefined;
  };

  private readonly onHeadersReceived = (
    details: chrome.webRequest.OnHeadersReceivedDetails
  ): chrome.webRequest.BlockingResponse | undefined => {
    if (!this.captureReady) {
      this.deferEvent(() => this.onHeadersReceived(details));
      return undefined;
    }
    if (!this.settings.enabled || this.ignoredRequestIds.has(details.requestId)) {
      return undefined;
    }
    const pending = this.getOrCreatePending(details);
    if (!pending) {
      return undefined;
    }
    this.applyResponseMetadata(
      pending,
      details.responseHeaders,
      details.statusCode,
      details.statusLine
    );
    pending.lastEventAt = details.timeStamp;
    return undefined;
  };

  private readonly onBeforeRedirect = (
    details: chrome.webRequest.OnBeforeRedirectDetails
  ): void => {
    if (!this.captureReady) {
      this.deferEvent(() => this.onBeforeRedirect(details));
      return;
    }
    if (!this.settings.enabled) {
      this.finishIgnoredRequest(details.requestId);
      this.finishRequest(details.requestId);
      return;
    }
    if (this.ignoredRequestIds.has(details.requestId)) {
      return;
    }
    const pending = this.getOrCreatePending(details);
    if (!pending) {
      this.finishRequest(details.requestId);
      return;
    }
    this.applyResponseMetadata(
      pending,
      details.responseHeaders,
      details.statusCode,
      details.statusLine
    );
    pending.observation.cacheState = details.fromCache ? 'disk-cache' : 'network';
    addCoverageGap(pending.observation, 'REDIRECT_HOP');
    pending.lastEventAt = details.timeStamp;
    const redirectTargetOrigin = pending.originContext.targetOrigin;
    if (redirectTargetOrigin) {
      this.redirectTargets.set(details.requestId, {
        targetOrigin: redirectTargetOrigin,
        policyId: pending.policy.policyId,
        policyVersion: pending.policy.version,
        contextId: pending.targetContextId,
        startedAt: pending.targetStartedAt
      });
    }
    this.queueFinalization(pending);
    this.pending.delete(details.requestId);
    this.redirectHops.set(details.requestId, pending.hop + 1);
  };

  private readonly onCompleted = (details: chrome.webRequest.OnCompletedDetails): void => {
    if (!this.captureReady) {
      this.deferEvent(() => this.onCompleted(details));
      return;
    }
    if (!this.settings.enabled) {
      this.finishIgnoredRequest(details.requestId);
      this.finishRequest(details.requestId);
      return;
    }
    if (this.finishIgnoredRequest(details.requestId)) {
      return;
    }
    const pending =
      this.pending.get(details.requestId) ??
      (details.type === 'main_frame' ? undefined : this.getOrCreatePending(details));
    if (!pending) {
      this.finishRequest(details.requestId);
      return;
    }
    this.applyResponseMetadata(
      pending,
      details.responseHeaders,
      details.statusCode,
      details.statusLine
    );
    pending.observation.cacheState = details.fromCache ? 'disk-cache' : 'network';
    pending.lastEventAt = details.timeStamp;
    this.queueFinalization(pending);
    this.finishRequest(details.requestId);
  };

  private readonly onErrorOccurred = (
    details: chrome.webRequest.OnErrorOccurredDetails
  ): void => {
    if (!this.captureReady) {
      this.deferEvent(() => this.onErrorOccurred(details));
      return;
    }
    this.discardTrackedTargetTransition(details.requestId);
    if (!this.settings.enabled) {
      this.finishIgnoredRequest(details.requestId);
      this.finishRequest(details.requestId);
      return;
    }
    if (this.finishIgnoredRequest(details.requestId)) {
      return;
    }
    const pending =
      this.pending.get(details.requestId) ??
      (details.type === 'main_frame' ? undefined : this.getOrCreatePending(details));
    if (!pending) {
      this.finishRequest(details.requestId);
      return;
    }
    pending.observation.cacheState = details.fromCache ? 'disk-cache' : 'network';
    addCoverageGap(pending.observation, 'REQUEST_FAILED');
    pending.lastEventAt = details.timeStamp;
    this.queueFinalization(pending);
    this.finishRequest(details.requestId);
  };

  private readonly onNavigationCommitted = (
    details: chrome.webNavigation.WebNavigationTransitionCallbackDetails
  ): void => {
    if (!this.captureReady) {
      this.deferEvent(() => this.onNavigationCommitted(details));
      return;
    }
    if (!this.settings.enabled || details.frameId !== 0) {
      return;
    }
    this.commitTrackedTargetNavigation(
      details.tabId,
      details.url,
      details.timeStamp,
      details.documentId
    );
  };

  private readonly onNavigationError = (
    details: chrome.webNavigation.WebNavigationFramedErrorCallbackDetails
  ): void => {
    if (!this.captureReady) {
      this.deferEvent(() => this.onNavigationError(details));
      return;
    }
    if (!this.settings.enabled || details.frameId !== 0) {
      return;
    }
    this.observeTrackedTargetNavigationError(details.timeStamp);
  };

  private readonly onTabRemoved = (tabId: number): void => {
    if (!this.captureReady) {
      this.deferEvent(() => this.onTabRemoved(tabId));
      return;
    }
    let changed = this.trackedTargetTabs.delete(tabId);
    changed = this.committedNavigations.delete(tabId) || changed;
    for (const [requestId, transition] of this.trackedTargetTransitions) {
      if (transition.tabId === tabId) {
        this.trackedTargetTransitions.delete(requestId);
        changed = true;
      }
    }
    if (changed) {
      this.persistTrackedTargets();
    }
  };

  private deferEvent(callback: () => void): void {
    if (this.deferredEvents.length >= MAX_DEFERRED_EVENTS) {
      this.deferredEvents.shift();
      this.coverageGapCodes.add('COLD_START_EVENT_BUFFER_LIMIT_REACHED');
    }
    this.deferredEvents.push(callback);
  }

  private releaseDeferredEvents(): void {
    if (this.captureReady) {
      return;
    }
    this.captureReady = true;
    while (this.deferredEvents.length > 0) {
      const callback = this.deferredEvents.shift();
      try {
        callback?.();
      } catch (error) {
        this.reportError(error, 'replay-deferred-event');
      }
    }
    if (
      this.coverageGapCodes.has('COLD_START_EVENT_BUFFER_LIMIT_REACHED') &&
      !this.coverageGapCodes.has('PERSISTED_STATE_LOAD_FAILED')
    ) {
      this.markDirty();
    }
  }

  private registerListeners(): void {
    if (this.listening) {
      return;
    }
    chrome.webRequest.onBeforeRequest.addListener(this.onBeforeRequest, WEB_REQUEST_FILTER, [
      'requestBody'
    ]);
    chrome.webRequest.onBeforeSendHeaders.addListener(
      this.onBeforeSendHeaders,
      WEB_REQUEST_FILTER,
      ['requestHeaders', 'extraHeaders']
    );
    chrome.webRequest.onHeadersReceived.addListener(
      this.onHeadersReceived,
      WEB_REQUEST_FILTER,
      ['responseHeaders', 'extraHeaders']
    );
    chrome.webRequest.onBeforeRedirect.addListener(
      this.onBeforeRedirect,
      WEB_REQUEST_FILTER,
      ['responseHeaders', 'extraHeaders']
    );
    chrome.webRequest.onCompleted.addListener(this.onCompleted, WEB_REQUEST_FILTER, [
      'responseHeaders',
      'extraHeaders'
    ]);
    chrome.webRequest.onErrorOccurred.addListener(this.onErrorOccurred, WEB_REQUEST_FILTER);
    chrome.webNavigation?.onCommitted.addListener(this.onNavigationCommitted);
    chrome.webNavigation?.onErrorOccurred.addListener(this.onNavigationError);
    chrome.tabs.onRemoved.addListener(this.onTabRemoved);
    this.listening = true;
  }

  private unregisterListeners(): void {
    if (!this.listening) {
      return;
    }
    chrome.webRequest.onBeforeRequest.removeListener(this.onBeforeRequest);
    chrome.webRequest.onBeforeSendHeaders.removeListener(this.onBeforeSendHeaders);
    chrome.webRequest.onHeadersReceived.removeListener(this.onHeadersReceived);
    chrome.webRequest.onBeforeRedirect.removeListener(this.onBeforeRedirect);
    chrome.webRequest.onCompleted.removeListener(this.onCompleted);
    chrome.webRequest.onErrorOccurred.removeListener(this.onErrorOccurred);
    chrome.webNavigation?.onCommitted.removeListener(this.onNavigationCommitted);
    chrome.webNavigation?.onErrorOccurred.removeListener(this.onNavigationError);
    chrome.tabs.onRemoved.removeListener(this.onTabRemoved);
    this.listening = false;
  }

  private createPendingObservation(
    details:
      | chrome.webRequest.WebRequestDetails
      | chrome.webRequest.OnBeforeRequestDetails
  ): PendingTrafficObservation | undefined {
    if (isBlancheControlPlaneUrl(details.url)) {
      return undefined;
    }
    const observedAt = timestampFromMilliseconds(details.timeStamp);
    let sanitized: SanitizedTrafficUrl;
    let policy: ScopePolicy;
    let scopeDecision: ScopeDecision;
    try {
      policy = this.getPolicy();
      const endpoint = canonicalizeTrafficEndpoint(details.url, details.method);
      scopeDecision = evaluateTrafficScope(policy, {
        endpoint,
        rawUrl: details.url,
        evaluatedAt: observedAt
      });
      sanitized = sanitizeTrafficUrl(details.url, details.method);
    } catch (error) {
      this.reportError(error, 'capture-request');
      return undefined;
    }

    const requestOrigin = sanitizeOptionalOrigin(details.url);
    const isMainFrame = details.type === 'main_frame';
    const hop = this.redirectHops.get(details.requestId) ?? 0;
    const redirectTarget = hop > 0 ? this.redirectTargets.get(details.requestId) : undefined;
    let trackedTarget = this.getTrackedTarget(details.tabId, policy);
    if (isMainFrame && details.tabId >= 0) {
      this.evictStaleTargetTransitions(details.timeStamp);
      const existingTransition = this.trackedTargetTransitions.get(details.requestId);
      const relatedRedirectTarget =
        redirectTarget ?? existingTransition?.attributionTarget;
      const committedNavigation = this.committedNavigationForRequest(
        details.tabId,
        sanitized.url,
        details.timeStamp
      );
      const transitionStartedAt = existingTransition?.startedAt ??
        (committedNavigation
          ? earlierTimestamp(committedNavigation.startedAt, observedAt)
          : observedAt);
      const correlatedTarget =
        relatedRedirectTarget ??
        existingTransition?.nextTarget ??
        committedNavigation?.target;
      let nextTarget: TrackedTargetTab | undefined;
      if (scopeDecision.disposition === 'in-scope' && requestOrigin) {
        nextTarget = {
          targetOrigin: requestOrigin,
          policyId: policy.policyId,
          policyVersion: policy.version,
          contextId:
            correlatedTarget?.contextId ??
            committedNavigation?.contextId ??
            `${transitionStartedAt}:${details.requestId}`,
          startedAt: correlatedTarget?.startedAt
            ? earlierTimestamp(correlatedTarget.startedAt, transitionStartedAt)
            : transitionStartedAt
        };
      }
      const attributionTarget =
        nextTarget ?? (hop > 0 || existingTransition ? relatedRedirectTarget : undefined);
      if (committedNavigation) {
        const contextTarget = nextTarget ?? attributionTarget;
        const updatedMarker: CommittedNavigationMarker = {
          ...committedNavigation,
          contextId: contextTarget?.contextId ?? committedNavigation.contextId,
          startedAt: contextTarget?.startedAt
            ? earlierTimestamp(contextTarget.startedAt, transitionStartedAt)
            : transitionStartedAt,
          acceptLateRequest: false,
          target: nextTarget
        };
        this.committedNavigations.set(details.tabId, updatedMarker);
        if (nextTarget) {
          this.trackedTargetTabs.set(details.tabId, nextTarget);
        } else {
          this.trackedTargetTabs.delete(details.tabId);
        }
      }
      this.trackedTargetTransitions.set(details.requestId, {
        tabId: details.tabId,
        sanitizedUrl: sanitized.url,
        startedAt: transitionStartedAt,
        lastObservedAt: observedAt,
        nextTarget,
        attributionTarget,
        committedDocumentId: committedNavigation?.documentId
      });
      this.persistTrackedTargets();
      trackedTarget = attributionTarget;
    }

    // Capture starts only from an explicitly in-scope request or a tab whose main frame is in scope.
    if (scopeDecision.disposition !== 'in-scope' && !trackedTarget) {
      return undefined;
    }

    const sourceOrigin = sanitizeOptionalOrigin(details.initiator);
    const targetOrigin =
      trackedTarget?.targetOrigin ??
      (isMainFrame ? requestOrigin : undefined) ??
      this.resolveTargetOrigin({
        tabId: details.tabId,
        requestUrl: sanitized.url,
        initiator: sourceOrigin
      });
    const targetRegistrableDomain = targetOrigin
      ? apparentRegistrableDomain(new URL(targetOrigin).hostname)
      : undefined;
    const requestRegistrableDomain = apparentRegistrableDomain(new URL(details.url).hostname);
    const coverageGaps = ['CONTENT_TYPE_UNAVAILABLE_OR_REDACTED', 'PROTOCOL_UNAVAILABLE'];
    if (sanitized.queryParameterNames.length > 0) {
      coverageGaps.push('QUERY_VALUES_REDACTED');
    }
    if (details.tabId < 0) {
      coverageGaps.push('TAB_CONTEXT_UNAVAILABLE');
    }
    const frameType = 'frameType' in details ? details.frameType : undefined;

    return {
      generation: this.generation,
      hop,
      requestId: details.requestId,
      tabId: details.tabId,
      sourceOrigin,
      targetContextId: trackedTarget?.contextId,
      targetStartedAt: trackedTarget?.startedAt,
      policy,
      scopeDecision,
      originContext: targetOrigin
        ? { targetOrigin, targetRegistrableDomain }
        : {},
      observation: {
        url: sanitized.url,
        observedAt,
        source: 'chromium-web-request',
        method: details.method,
        sourceOrigin,
        frameId: details.frameId,
        initiatorType: frameType,
        resourceType: details.type,
        requestHeaderNames: [],
        responseHeaderNames: [],
        requestBodyFieldNames: [],
        coverageGaps,
        classification: requestRegistrableDomain
          ? {
              registrableDomain: requestRegistrableDomain,
              reasonCodes: ['REGISTRABLE_DOMAIN_HEURISTIC']
            }
          : undefined,
        evidence: [
          {
            kind: 'browser-request',
            id: `${details.requestId}:${hop}`,
            source: 'chrome.webRequest',
            observedAt
          }
        ]
      },
      lastEventAt: details.timeStamp
    };
  }

  private getOrCreatePending(
    details: chrome.webRequest.WebRequestDetails
  ): PendingTrafficObservation | undefined {
    const existing = this.pending.get(details.requestId);
    if (existing) {
      return existing;
    }
    const pending = this.createPendingObservation(details);
    if (pending) {
      addCoverageGap(pending.observation, 'REQUEST_START_EVENT_UNAVAILABLE');
      this.pending.set(details.requestId, pending);
      this.evictStalePending(details.timeStamp);
    }
    return pending;
  }

  private applyResponseMetadata(
    pending: PendingTrafficObservation,
    responseHeaders: chrome.webRequest.HttpHeader[] | undefined,
    statusCode: number,
    statusLine: string
  ): void {
    const names = headerNames(responseHeaders);
    const safeMetadata = extractSafeResponseMetadata(responseHeaders, statusLine);
    pending.observation.responseHeaderNames = mergeNames(
      pending.observation.responseHeaderNames,
      names
    );
    pending.observation.statusCode = statusCode;
    if (safeMetadata.contentType) {
      pending.observation.contentType = safeMetadata.contentType;
    }
    if (safeMetadata.protocol) {
      pending.observation.protocol = safeMetadata.protocol;
    }
    if (safeMetadata.contentLength !== undefined) {
      pending.observation.bytes = {
        transfer: safeMetadata.contentLength,
        encoded: safeMetadata.contentLength
      };
    }
    if (safeMetadata.protocol) {
      removeCoverageGap(pending.observation, 'PROTOCOL_UNAVAILABLE');
    }
    if (safeMetadata.contentType) {
      removeCoverageGap(pending.observation, 'CONTENT_TYPE_UNAVAILABLE_OR_REDACTED');
    }
    if (names.length > 0) {
      addCoverageGap(
        pending.observation,
        'NON_ALLOWLISTED_RESPONSE_HEADER_VALUES_REDACTED'
      );
    }
  }

  private queueFinalization(pending: PendingTrafficObservation): void {
    const task = this.finalizeObservation(pending).catch((error) => {
      this.reportError(error, 'finalize');
    });
    this.finalizations.add(task);
    void task.finally(() => {
      this.finalizations.delete(task);
    });
  }

  private async finalizeObservation(pending: PendingTrafficObservation): Promise<void> {
    const builtEntry = await buildTrafficLedgerEntry(pending.observation, {
      scopePolicy: pending.policy,
      originContext: pending.originContext
    });
    const entry: TrafficLedgerEntry = {
      ...builtEntry,
      scope: pending.scopeDecision
    };
    await this.initializeWithoutRestart();
    if (pending.generation !== this.generation) {
      return;
    }

    const sourceOrigin = pending.sourceOrigin;
    const targetOrigin = pending.originContext.targetOrigin;
    const recordKey = trafficRecordKey(
      entry.entryId,
      pending.tabId,
      sourceOrigin,
      targetOrigin,
      pending.targetContextId
    );
    const existing = this.records.get(recordKey);
    const mergedEntry = existing
      ? mergeTrafficLedgerEntries([existing.entry, entry])[0]
      : entry;
    if (!mergedEntry) {
      return;
    }
    const lastCapturedAt = timestampFromMilliseconds(pending.lastEventAt);
    this.records.delete(recordKey);
    this.records.set(recordKey, {
      entry: capAggregatedEntry(mergedEntry),
      tabId: pending.tabId,
      sourceOrigin,
      targetOrigin,
      targetContextId: pending.targetContextId,
      targetStartedAt: pending.targetStartedAt,
      lastCapturedAt
    });
    this.enforceEntryCapacity();
    this.markDirty();
  }

  private async drainFinalizations(): Promise<void> {
    const pending = [...this.finalizations];
    if (pending.length > 0) {
      await Promise.allSettled(pending);
    }
  }

  private finishRequest(requestId: string): void {
    this.pending.delete(requestId);
    this.redirectHops.delete(requestId);
    this.redirectTargets.delete(requestId);
    if (this.trackedTargetTransitions.get(requestId)?.committedDocumentId) {
      this.trackedTargetTransitions.delete(requestId);
      this.persistTrackedTargets();
    }
  }

  private discardTrackedTargetTransition(requestId: string): void {
    if (this.trackedTargetTransitions.delete(requestId)) {
      this.persistTrackedTargets();
    }
  }

  private commitTrackedTargetNavigation(
    tabId: number,
    rawUrl: string,
    timeStamp: number,
    documentId?: string
  ): void {
    if (tabId < 0) {
      return;
    }
    this.evictStaleTargetTransitions(timeStamp);
    let sanitizedUrl: string | undefined;
    try {
      sanitizedUrl = sanitizeTrafficUrl(rawUrl, 'GET').url;
    } catch {
      sanitizedUrl = undefined;
    }
    const committedAt = timestampFromMilliseconds(timeStamp);
    const safeDocumentId =
      normalizeOptionalIdentifier(documentId) ?? `${committedAt}:committed:${tabId}`;
    const currentMarker = this.committedNavigations.get(tabId);
    if (
      currentMarker?.documentId === safeDocumentId &&
      currentMarker.sanitizedUrl === sanitizedUrl
    ) {
      return;
    }
    const matching = [...this.trackedTargetTransitions.entries()]
      .filter(
        ([, transition]) =>
          transition.tabId === tabId &&
          transition.sanitizedUrl === sanitizedUrl &&
          new Date(transition.startedAt).getTime() <= new Date(committedAt).getTime()
      )
      .sort(
        (left, right) =>
          new Date(right[1].startedAt).getTime() -
            new Date(left[1].startedAt).getTime() ||
          new Date(right[1].lastObservedAt).getTime() -
            new Date(left[1].lastObservedAt).getTime()
      );
    const selected = matching[0];
    if (
      currentMarker &&
      ((selected &&
        new Date(selected[1].startedAt).getTime() <
          new Date(currentMarker.startedAt).getTime()) ||
        (!selected &&
          new Date(committedAt).getTime() <
            new Date(currentMarker.committedAt).getTime()))
    ) {
      if (selected) {
        this.trackedTargetTransitions.delete(selected[0]);
        this.persistTrackedTargets();
      }
      return;
    }

    let nextTarget = selected?.[1].nextTarget;
    if (!selected && sanitizedUrl) {
      try {
        const policy = this.getPolicy();
        const decision = evaluateTrafficScope(policy, {
          endpoint: canonicalizeTrafficEndpoint(rawUrl, 'GET'),
          rawUrl,
          evaluatedAt: timestampFromMilliseconds(timeStamp)
        });
        const targetOrigin = sanitizeOptionalOrigin(rawUrl);
        if (decision.disposition === 'in-scope' && targetOrigin) {
          const startedAt = timestampFromMilliseconds(timeStamp);
          nextTarget = {
            targetOrigin,
            policyId: policy.policyId,
            policyVersion: policy.version,
            contextId: safeDocumentId,
            startedAt
          };
        }
        this.coverageGapCodes.add('NAVIGATION_REQUEST_CONTEXT_UNAVAILABLE');
        this.markDirty();
      } catch (error) {
        this.reportError(error, 'navigation-commit-scope');
      }
    }

    const contextTarget = nextTarget ?? selected?.[1].attributionTarget;
    const marker: CommittedNavigationMarker = {
      sanitizedUrl,
      documentId: safeDocumentId,
      committedAt,
      contextId: contextTarget?.contextId ?? safeDocumentId,
      startedAt: contextTarget?.startedAt ?? selected?.[1].startedAt ?? committedAt,
      acceptLateRequest: !selected,
      target: nextTarget
    };
    this.committedNavigations.set(tabId, marker);
    if (nextTarget) {
      this.trackedTargetTabs.set(tabId, nextTarget);
    } else {
      this.trackedTargetTabs.delete(tabId);
    }
    if (selected) {
      const cutoff = new Date(selected[1].startedAt).getTime();
      for (const [requestId, transition] of this.trackedTargetTransitions) {
        if (
          transition.tabId === tabId &&
          new Date(transition.startedAt).getTime() <= cutoff
        ) {
          this.trackedTargetTransitions.delete(requestId);
        }
      }
    }
    this.persistTrackedTargets();
  }

  private committedNavigationForRequest(
    tabId: number,
    sanitizedUrl: string,
    requestTimeStamp: number
  ): CommittedNavigationMarker | undefined {
    const marker = this.committedNavigations.get(tabId);
    if (!marker || marker.sanitizedUrl !== sanitizedUrl) {
      return undefined;
    }
    const committedAt = new Date(marker.committedAt).getTime();
    const age = committedAt - requestTimeStamp;
    return (age >= 0 && age <= MAX_PENDING_AGE_MS) ||
      (marker.acceptLateRequest && age < 0 && -age <= MAX_COMMIT_REQUEST_REORDER_MS)
      ? marker
      : undefined;
  }

  private observeTrackedTargetNavigationError(timeStamp: number): void {
    // webNavigation errors have no request ID and safe URL templates can collide.
    // The exact webRequest error retires its candidate; ambiguous candidates expire by TTL.
    this.evictStaleTargetTransitions(timeStamp);
  }

  private finishIgnoredRequest(requestId: string): boolean {
    const ignored = this.ignoredRequestIds.delete(requestId);
    if (ignored) {
      this.finishRequest(requestId);
    }
    return ignored;
  }

  private evictStalePending(now: number): void {
    for (const [requestId, pending] of this.pending) {
      if (
        now - pending.lastEventAt <= MAX_PENDING_AGE_MS &&
        this.pending.size <= MAX_PENDING_REQUESTS
      ) {
        continue;
      }
      addCoverageGap(pending.observation, 'PENDING_REQUEST_EVICTED');
      this.queueFinalization(pending);
      this.pending.delete(requestId);
      this.redirectHops.delete(requestId);
      this.redirectTargets.delete(requestId);
      if (this.pending.size <= MAX_PENDING_REQUESTS) {
        break;
      }
    }
  }

  private evictStaleTargetTransitions(now: number): void {
    const ranked = [...this.trackedTargetTransitions.entries()].sort(
      (left, right) =>
        new Date(left[1].lastObservedAt).getTime() -
        new Date(right[1].lastObservedAt).getTime()
    );
    let changed = false;
    for (const [requestId, transition] of ranked) {
      const lastObservedAt = new Date(transition.lastObservedAt).getTime();
      if (
        now - lastObservedAt <= MAX_PENDING_AGE_MS &&
        this.trackedTargetTransitions.size <= MAX_PENDING_REQUESTS
      ) {
        continue;
      }
      this.trackedTargetTransitions.delete(requestId);
      changed = true;
    }
    if (changed) {
      this.persistTrackedTargets();
    }
  }

  private getPolicy(): ScopePolicy {
    return normalizeScopePolicy(this.options.getScopePolicy());
  }

  private getTrackedTarget(
    tabId: number,
    policy: ScopePolicy
  ): TrackedTargetTab | undefined {
    if (tabId < 0) {
      return undefined;
    }
    const tracked = this.trackedTargetTabs.get(tabId);
    if (!tracked) {
      return undefined;
    }
    if (tracked.policyId === policy.policyId && tracked.policyVersion === policy.version) {
      return tracked;
    }

    try {
      const decision = evaluateTrafficScope(policy, {
        endpoint: canonicalizeTrafficEndpoint(tracked.targetOrigin, 'GET'),
        rawUrl: tracked.targetOrigin
      });
      if (decision.disposition !== 'in-scope') {
        if (this.trackedTargetTabs.delete(tabId)) {
          this.persistTrackedTargets();
        }
        return undefined;
      }
      const updated = {
        ...tracked,
        policyId: policy.policyId,
        policyVersion: policy.version
      };
      this.trackedTargetTabs.set(tabId, updated);
      this.persistTrackedTargets();
      return updated;
    } catch {
      if (this.trackedTargetTabs.delete(tabId)) {
        this.persistTrackedTargets();
      }
      return undefined;
    }
  }

  private resolveTargetOrigin(context: TrafficOriginLookup): string | undefined {
    if (!this.options.getTargetOrigin) {
      return undefined;
    }
    try {
      return sanitizeOptionalOrigin(this.options.getTargetOrigin(context));
    } catch (error) {
      this.reportError(error, 'target-origin');
      return undefined;
    }
  }

  private currentEntries(): TrafficLedgerEntry[] {
    return this.entriesForContext();
  }

  private entriesForContext(
    tabId?: number,
    sourceOrigin?: string,
    targetOrigin?: string,
    rawSince?: string,
    targetContextId?: string
  ): TrafficLedgerEntry[] {
    const since = rawSince ? normalizeTimestamp(rawSince) : undefined;
    if (rawSince && !since) {
      throw new Error(`Invalid traffic ledger query timestamp: ${rawSince}`);
    }
    const entries = [...this.records.values()]
      .filter((record) => tabId === undefined || record.tabId === tabId)
      .filter((record) => sourceOrigin === undefined || record.sourceOrigin === sourceOrigin)
      .filter((record) => targetOrigin === undefined || record.targetOrigin === targetOrigin)
      .filter(
        (record) =>
          targetContextId === undefined || record.targetContextId === targetContextId
      )
      .filter((record) => !since || record.entry.observation.lastSeen >= since)
      .map((record) => this.rescopeEntry(record.entry))
      .map((entry) => markPreWindowHistory(entry, since));
    return mergeTrafficLedgerEntries(entries);
  }

  private rescopeEntry(entry: TrafficLedgerEntry): TrafficLedgerEntry {
    try {
      const policy = this.getPolicy();
      if (
        entry.scope.policyId === policy.policyId &&
        entry.scope.policyVersion === policy.version
      ) {
        return entry;
      }
      const scope = evaluateTrafficScope(policy, {
        endpoint: entry.endpoint,
        rawUrl: endpointToSanitizedUrl(entry.endpoint)
      });
      return {
        ...entry,
        observation: {
          ...entry.observation,
          coverageGaps: uniqueSorted([
            ...entry.observation.coverageGaps,
            'SCOPE_REEVALUATED_FROM_TEMPLATED_ENDPOINT'
          ])
        },
        scope: {
          ...scope,
          confidence: 'low',
          reasonCodes: uniqueSorted([
            ...scope.reasonCodes,
            'SCOPE_REEVALUATED_FROM_TEMPLATED_ENDPOINT'
          ])
        }
      };
    } catch (error) {
      this.reportError(error, 'rescope');
      return entry;
    }
  }

  private enforceEntryCapacity(): void {
    if (this.records.size <= this.settings.maxEntries) {
      return;
    }
    const previousSize = this.records.size;
    const retained = [...this.records.entries()]
      .sort((left, right) => compareRetention(right[1], left[1]))
      .slice(0, this.settings.maxEntries);
    this.records.clear();
    for (const [key, record] of retained) {
      this.records.set(key, record);
    }
    this.droppedEntryCount += previousSize - this.records.size;
    this.coverageGapCodes.add('RETAINED_ENTRY_LIMIT_REACHED');
  }

  private markDirty(): void {
    this.dirty = true;
    if (this.persistTimer) {
      return;
    }
    this.persistTimer = setTimeout(() => {
      this.persistTimer = undefined;
      void this.flushPersistence().catch(() => {});
    }, PERSIST_DEBOUNCE_MS);
  }

  private async flushPersistence(): Promise<void> {
    if (this.persistTimer) {
      clearTimeout(this.persistTimer);
      this.persistTimer = undefined;
    }
    if (!this.dirty) {
      await this.writeTail;
      return;
    }

    this.enforceStorageBudget();
    const state = this.buildPersistedState();
    this.dirty = false;
    const write = this.writeTail.catch(() => undefined).then(async () => {
      await chrome.storage.local.set({ [this.storageKey]: state });
    });
    this.writeTail = write;
    try {
      await write;
    } catch (error) {
      this.dirty = true;
      if (!this.persistTimer) {
        this.persistTimer = setTimeout(() => {
          this.persistTimer = undefined;
          void this.flushPersistence().catch(() => {});
        }, PERSIST_DEBOUNCE_MS * 4);
      }
      this.reportError(error, 'persist');
      throw error;
    }
  }

  private enforceStorageBudget(): void {
    let state = this.buildPersistedState();
    let byteLength = encodedByteLength(state);
    while (byteLength > MAX_PERSISTED_BYTES && this.records.size > 0) {
      const ranked = [...this.records.entries()].sort((left, right) =>
        compareRetention(left[1], right[1])
      );
      const excessRatio = Math.max(0, 1 - MAX_PERSISTED_BYTES / byteLength);
      const dropCount = Math.max(1, Math.ceil(ranked.length * excessRatio));
      for (const [key] of ranked.slice(0, dropCount)) {
        this.records.delete(key);
      }
      this.droppedEntryCount += Math.min(dropCount, ranked.length);
      this.coverageGapCodes.add('PERSISTED_BYTE_LIMIT_REACHED');
      state = this.buildPersistedState();
      byteLength = encodedByteLength(state);
    }
  }

  private buildPersistedState(): PersistedTrafficLedgerState {
    return {
      version: STORAGE_VERSION,
      updatedAt: new Date().toISOString(),
      settings: this.settings,
      records: [...this.records.values()],
      droppedEntryCount: this.droppedEntryCount,
      coverageGapCodes: [...this.coverageGapCodes].sort()
    };
  }

  private async loadPersistedState(): Promise<void> {
    const [localValues, sessionValues] = await Promise.all([
      chrome.storage.local.get([this.storageKey, this.coverageStorageKey]),
      chrome.storage.session.get([
        this.targetSessionStorageKey,
        this.coverageSessionStorageKey
      ])
    ]);
    this.restoreTrackedTargets(sessionValues[this.targetSessionStorageKey]);
    this.restoreCoverageMarker(localValues[this.coverageStorageKey]);
    this.restoreCoverageMarker(sessionValues[this.coverageSessionStorageKey]);
    const stored = localValues[this.storageKey];
    if (stored === undefined) {
      return;
    }
    if (!isPersistedTrafficLedgerState(stored)) {
      this.settings = {
        ...this.settings,
        enabled: false
      };
      this.coverageGapCodes.add('PERSISTED_STATE_INVALID');
      this.dirty = true;
      return;
    }
    this.settings = normalizeManagerSettings({
      ...stored.settings,
      ...this.settingOverrides
    });
    this.droppedEntryCount = normalizeNonNegativeInteger(stored.droppedEntryCount);
    for (const code of stored.coverageGapCodes ?? []) {
      if (typeof code === 'string' && code.trim()) {
        this.coverageGapCodes.add(code.trim());
      }
    }
    for (const rawRecord of stored.records) {
      const record = normalizePersistedRecord(rawRecord);
      if (!record) {
        this.droppedEntryCount += 1;
        this.coverageGapCodes.add('PERSISTED_RECORD_INVALID');
        this.dirty = true;
        continue;
      }
      const key = trafficRecordKey(
        record.entry.entryId,
        record.tabId,
        record.sourceOrigin,
        record.targetOrigin,
        record.targetContextId
      );
      const existing = this.records.get(key);
      if (!existing) {
        this.records.set(key, record);
        continue;
      }
      const merged = mergeTrafficLedgerEntries([existing.entry, record.entry])[0];
      if (merged) {
        this.records.set(key, {
          entry: capAggregatedEntry(merged),
          tabId: record.tabId,
          sourceOrigin: record.sourceOrigin,
          targetOrigin: record.targetOrigin,
          targetContextId: record.targetContextId,
          targetStartedAt: record.targetStartedAt,
          lastCapturedAt: laterTimestamp(existing.lastCapturedAt, record.lastCapturedAt)
        });
      }
    }
    this.enforceEntryCapacity();
  }

  private restoreTrackedTargets(value: unknown): void {
    if (value === undefined) {
      return;
    }
    if (!isPersistedTrackedTargetState(value)) {
      this.coverageGapCodes.add('TARGET_CONTEXT_STATE_INVALID');
      this.dirty = true;
      return;
    }
    for (const [rawTabId, rawTarget] of Object.entries(value.targets)) {
      const tabId = Number(rawTabId);
      const target = normalizeTrackedTarget(rawTarget);
      if (!Number.isInteger(tabId) || tabId < 0 || !target) {
        this.coverageGapCodes.add('TARGET_CONTEXT_STATE_INVALID');
        this.dirty = true;
        continue;
      }
      this.trackedTargetTabs.set(tabId, target);
    }
    for (const [rawRequestId, rawTransition] of Object.entries(
      value.pendingNavigations ?? {}
    )) {
      const requestId = normalizeOptionalIdentifier(rawRequestId);
      const transition = normalizeTrackedTargetTransition(rawTransition);
      if (!requestId || !transition) {
        this.coverageGapCodes.add('TARGET_CONTEXT_STATE_INVALID');
        this.dirty = true;
        continue;
      }
      this.trackedTargetTransitions.set(requestId, transition);
    }
    for (const [rawTabId, rawMarker] of Object.entries(
      value.committedNavigations ?? {}
    )) {
      const tabId = Number(rawTabId);
      const marker = normalizeCommittedNavigationMarker(rawMarker);
      if (!Number.isInteger(tabId) || tabId < 0 || !marker) {
        this.coverageGapCodes.add('TARGET_CONTEXT_STATE_INVALID');
        this.dirty = true;
        continue;
      }
      this.committedNavigations.set(tabId, marker);
    }
  }

  private restoreCoverageMarker(value: unknown): void {
    if (value === undefined) {
      return;
    }
    if (!isPersistedCoverageMarker(value)) {
      this.coverageGapCodes.add('COVERAGE_MARKER_INVALID');
      this.dirty = true;
      return;
    }
    for (const code of value.reasonCodes) {
      if (typeof code === 'string' && code.trim()) {
        this.coverageGapCodes.add(code.trim());
      }
    }
  }

  private async persistCoverageMarker(): Promise<void> {
    const marker: PersistedCoverageMarker = {
      version: STORAGE_VERSION,
      reasonCodes: [...this.coverageGapCodes].sort()
    };
    const results = await Promise.allSettled([
      chrome.storage.local.set({ [this.coverageStorageKey]: marker }),
      chrome.storage.session.set({ [this.coverageSessionStorageKey]: marker })
    ]);
    const failures = results.flatMap((result, index) =>
      result.status === 'rejected' ? [{ index, error: result.reason }] : []
    );
    for (const failure of failures) {
      this.reportError(
        failure.error,
        failure.index === 0
          ? 'persist-coverage-marker-local'
          : 'persist-coverage-marker-session'
      );
    }
    if (failures.length === 0) {
      this.coveragePersistRetryCount = 0;
      return;
    }
    if (
      this.coveragePersistRetryCount < MAX_COVERAGE_PERSIST_RETRIES &&
      !this.coveragePersistTimer
    ) {
      this.coveragePersistRetryCount += 1;
      this.coveragePersistTimer = setTimeout(() => {
        this.coveragePersistTimer = undefined;
        void this.persistCoverageMarker();
      }, PERSIST_DEBOUNCE_MS * 4);
    } else if (this.coveragePersistRetryCount >= MAX_COVERAGE_PERSIST_RETRIES) {
      this.coverageGapCodes.add('COVERAGE_MARKER_PERSIST_FAILED');
    }
  }

  private persistTrackedTargets(): void {
    const state: PersistedTrackedTargetState = {
      version: STORAGE_VERSION,
      targets: Object.fromEntries(
        [...this.trackedTargetTabs.entries()].map(([tabId, target]) => [String(tabId), target])
      ),
      pendingNavigations: Object.fromEntries(this.trackedTargetTransitions),
      committedNavigations: Object.fromEntries(
        [...this.committedNavigations.entries()].map(([tabId, marker]) => [
          String(tabId),
          marker
        ])
      )
    };
    const write = this.targetWriteTail
      .catch(() => undefined)
      .then(() => chrome.storage.session.set({ [this.targetSessionStorageKey]: state }));
    this.targetWriteTail = write.catch((error) => {
        this.coverageGapCodes.add('TARGET_CONTEXT_PERSIST_FAILED');
        this.markDirty();
        this.reportError(error, 'persist-target-context');
      });
  }

  private initializeWithoutRestart(): Promise<void> {
    if (!this.initializationPromise) {
      this.initializationPromise = this.loadPersistedState().catch((error) => {
        return this.noteLoadFailure(error);
      });
    }
    return this.initializationPromise;
  }

  private async noteLoadFailure(error: unknown): Promise<void> {
    this.settings = {
      ...this.settings,
      enabled: false
    };
    this.coverageGapCodes.add('PERSISTED_STATE_LOAD_FAILED');
    await this.persistCoverageMarker();
    this.reportError(error, 'load');
  }

  private reportError(error: unknown, operation: string): void {
    try {
      this.options.onError?.(error, operation);
    } catch {
      // Error reporting must not break capture listeners.
    }
  }
}

function normalizeManagerSettings(
  settings: TrafficLedgerManagerSettings
): TrafficLedgerManagerSettings {
  return {
    enabled: Boolean(settings.enabled),
    maxEntries: Math.max(
      MIN_MAX_ENTRIES,
      Math.min(MAX_MAX_ENTRIES, Math.trunc(settings.maxEntries || DEFAULT_MAX_ENTRIES))
    )
  };
}

function sanitizeTrafficUrl(rawUrl: string, method?: string): SanitizedTrafficUrl {
  const parsed = new URL(rawUrl);
  const endpoint = canonicalizeTrafficEndpoint(rawUrl, method);
  const queryParameterNames = uniqueSorted(
    endpoint.queryParameterNames
      .map(sanitizeQueryParameterName)
      .filter((value): value is string => Boolean(value))
  ).slice(0, MAX_METADATA_NAMES);
  const safePath = pathTemplateToSafePath(endpoint.pathTemplate);
  const query = queryParameterNames.map((name) => `${encodeURIComponent(name)}=`).join('&');
  return {
    url: `${parsed.protocol}//${parsed.host}${safePath}${query ? `?${query}` : ''}`,
    queryParameterNames
  };
}

function sanitizeQueryParameterName(value: string): string | undefined {
  const candidate = value
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .trim()
    .slice(0, MAX_CONTEXT_VALUE_LENGTH);
  return candidate || undefined;
}

function pathTemplateToSafePath(pathTemplate: string): string {
  return pathTemplate
    .split('/')
    .map((segment) => {
      switch (segment) {
        case '{int}':
          return '0';
        case '{uuid}':
          return '00000000-0000-4000-8000-000000000000';
        case '{hex}':
          return '0000000000000000';
        case '{token}':
          return 'redacted0000000000000001';
        case '{secret}':
          return 'redacted';
        default:
          return segment;
      }
    })
    .join('/');
}

function sanitizeOrigin(rawOrigin: string): string {
  const parsed = new URL(rawOrigin);
  const scheme = parsed.protocol.toLowerCase();
  if (!['http:', 'https:', 'ws:', 'wss:'].includes(scheme)) {
    throw new Error(`Unsupported origin scheme: ${parsed.protocol}`);
  }
  return parsed.origin;
}

function sanitizeOptionalOrigin(rawOrigin: string | undefined): string | undefined {
  if (!rawOrigin || rawOrigin === 'null') {
    return undefined;
  }
  try {
    return sanitizeOrigin(rawOrigin);
  } catch {
    return undefined;
  }
}

function isBlancheControlPlaneUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    const hostname = parsed.hostname
      .toLowerCase()
      .replace(/^\[|\]$/g, '')
      .replace(/\.$/, '');
    if (hostname === 'blanche.invalid') {
      return true;
    }
    const loopback =
      hostname === 'localhost' ||
      hostname.endsWith('.localhost') ||
      hostname === '127.0.0.1' ||
      hostname === '::1';
    return loopback && /^\/api\/blanche(?:\/|$)/i.test(parsed.pathname);
  } catch {
    return false;
  }
}

function headerNames(headers: chrome.webRequest.HttpHeader[] | undefined): string[] {
  return metadataNames((headers ?? []).map((header) => header.name), 'header');
}

function extractSafeResponseMetadata(
  headers: chrome.webRequest.HttpHeader[] | undefined,
  statusLine: string
): SafeResponseMetadata {
  let contentType: string | undefined;
  let contentLength: number | undefined;

  for (const header of headers ?? []) {
    const name = header.name.trim().toLowerCase();
    if (name === 'content-type' && contentType === undefined && typeof header.value === 'string') {
      const candidate = (header.value.split(';', 1)[0] ?? '').trim().toLowerCase();
      if (
        candidate.length <= MAX_CONTEXT_VALUE_LENGTH &&
        /^[a-z0-9][a-z0-9.+_-]*\/[a-z0-9][a-z0-9.+_-]*$/.test(candidate)
      ) {
        contentType = candidate;
      }
      continue;
    }
    if (
      name === 'content-length' &&
      contentLength === undefined &&
      typeof header.value === 'string'
    ) {
      const candidate = header.value.trim();
      if (/^(?:0|[1-9]\d{0,15})$/.test(candidate)) {
        const parsed = Number(candidate);
        if (Number.isSafeInteger(parsed) && parsed >= 0) {
          contentLength = parsed;
        }
      }
    }
  }

  const protocolMatch = /^((?:HTTP\/(?:0\.9|1\.0|1\.1|2|3)))\s/i.exec(statusLine.trim());
  const protocol = protocolMatch?.[1]?.toLowerCase();
  return { contentType, contentLength, protocol };
}

function metadataNames(values: string[], kind: 'header' | 'field'): string[] {
  const pattern =
    kind === 'header'
      ? /^[!#$%&'*+.^_`|~0-9a-z-]+$/
      : /^[a-z0-9_.\[\]/-]+$/;
  return uniqueSorted(
    values.flatMap((value) => {
      const delimiterIndex = kind === 'header' ? value.indexOf(':') : value.search(/[:=]/);
      const candidate = (delimiterIndex < 0 ? value : value.slice(0, delimiterIndex))
        .trim()
        .toLowerCase()
        .slice(0, MAX_CONTEXT_VALUE_LENGTH);
      return candidate && pattern.test(candidate) ? [candidate] : [];
    })
  ).slice(0, MAX_METADATA_NAMES);
}

function mergeNames(left: string[] | undefined, right: string[]): string[] {
  return uniqueSorted([...(left ?? []), ...right]).slice(0, MAX_METADATA_NAMES);
}

function addCoverageGap(observation: TrafficObservationInput, gap: string): void {
  observation.coverageGaps = uniqueSorted([...(observation.coverageGaps ?? []), gap]);
}

function removeCoverageGap(observation: TrafficObservationInput, gap: string): void {
  observation.coverageGaps = (observation.coverageGaps ?? []).filter(
    (candidate) => candidate !== gap
  );
}

function timestampFromMilliseconds(value: number): string {
  const timestamp = Number.isFinite(value) ? new Date(value) : new Date();
  return timestamp.toISOString();
}

function trafficRecordKey(
  entryId: string,
  tabId: number,
  sourceOrigin?: string,
  targetOrigin?: string,
  targetContextId?: string
): string {
  return `${entryId}\n${tabId}\n${sourceOrigin ?? ''}\n${targetOrigin ?? ''}\n${
    targetContextId ?? ''
  }`;
}

function capAggregatedEntry(entry: TrafficLedgerEntry): TrafficLedgerEntry {
  const contextWasTruncated = [
    entry.observation.sourceOrigins,
    entry.observation.frameIds,
    entry.observation.initiatorTypes,
    entry.observation.resourceTypes,
    entry.observation.statusCodes,
    entry.observation.contentTypes,
    entry.observation.protocols,
    entry.observation.cacheStates
  ].some((values) => values.length > MAX_SOURCE_ORIGINS) || [
    entry.observation.requestHeaderNames,
    entry.observation.responseHeaderNames,
    entry.observation.requestBodyFieldNames
  ].some((values) => values.length > MAX_METADATA_NAMES);
  const evidenceWasTruncated = entry.evidence.length > MAX_EVIDENCE_REFERENCES;
  const evidence = entry.evidence.slice(-MAX_EVIDENCE_REFERENCES);
  const retainedEvidenceIds = new Set(evidence.map((reference) => reference.id));
  return {
    ...entry,
    observation: {
      ...entry.observation,
      sourceOrigins: entry.observation.sourceOrigins.slice(0, MAX_SOURCE_ORIGINS),
      frameIds: entry.observation.frameIds.slice(0, MAX_SOURCE_ORIGINS),
      initiatorTypes: entry.observation.initiatorTypes.slice(0, MAX_SOURCE_ORIGINS),
      resourceTypes: entry.observation.resourceTypes.slice(0, MAX_SOURCE_ORIGINS),
      statusCodes: entry.observation.statusCodes.slice(0, MAX_SOURCE_ORIGINS),
      contentTypes: entry.observation.contentTypes.slice(0, MAX_SOURCE_ORIGINS),
      protocols: entry.observation.protocols.slice(0, MAX_SOURCE_ORIGINS),
      cacheStates: entry.observation.cacheStates.slice(0, MAX_SOURCE_ORIGINS),
      requestHeaderNames: retainMetadataNames(entry.observation.requestHeaderNames),
      responseHeaderNames: retainMetadataNames(entry.observation.responseHeaderNames),
      requestBodyFieldNames: retainMetadataNames(entry.observation.requestBodyFieldNames),
      coverageGaps: uniqueSorted([
        ...entry.observation.coverageGaps,
        ...(contextWasTruncated ? ['RETAINED_CONTEXT_LIMIT_REACHED'] : []),
        ...(evidenceWasTruncated ? ['EVIDENCE_REFERENCE_LIMIT_REACHED'] : [])
      ])
    },
    priority: {
      ...entry.priority,
      factors: entry.priority.factors.map((factor) => ({
        ...factor,
        evidenceRefs: factor.evidenceRefs.filter((id) => retainedEvidenceIds.has(id))
      }))
    },
    evidence
  };
}

function retainMetadataNames(names: string[]): string[] {
  const sensitivity = /(?:auth|cookie|credential|csrf|key|password|permission|role|secret|session|token)/;
  return [...names]
    .sort((left, right) => {
      const sensitivityDifference = Number(sensitivity.test(right)) - Number(sensitivity.test(left));
      return sensitivityDifference || left.localeCompare(right);
    })
    .slice(0, MAX_METADATA_NAMES)
    .sort((left, right) => left.localeCompare(right));
}

function endpointToSanitizedUrl(endpoint: TrafficLedgerEntry['endpoint']): string {
  const host = endpoint.host.includes(':') ? `[${endpoint.host}]` : endpoint.host;
  const defaultPort =
    (endpoint.scheme === 'http' && endpoint.port === 80) ||
    (endpoint.scheme === 'https' && endpoint.port === 443) ||
    (endpoint.scheme === 'ws' && endpoint.port === 80) ||
    (endpoint.scheme === 'wss' && endpoint.port === 443);
  const port = defaultPort ? '' : `:${endpoint.port}`;
  const query = endpoint.queryParameterNames
    .map((name) => `${encodeURIComponent(name)}=`)
    .join('&');
  return `${endpoint.scheme}://${host}${port}${pathTemplateToSafePath(endpoint.pathTemplate)}${
    query ? `?${query}` : ''
  }`;
}

function markPreWindowHistory(
  entry: TrafficLedgerEntry,
  since: string | undefined
): TrafficLedgerEntry {
  if (!since || entry.observation.firstSeen >= since) {
    return entry;
  }
  return {
    ...entry,
    observation: {
      ...entry.observation,
      coverageGaps: uniqueSorted([
        ...entry.observation.coverageGaps,
        'OBSERVATION_COUNT_INCLUDES_PRE_WINDOW_HISTORY'
      ])
    }
  };
}

function apparentRegistrableDomain(rawHostname: string): string | undefined {
  const hostname = rawHostname.trim().toLowerCase().replace(/\.$/, '');
  if (!hostname || hostname === 'localhost' || hostname.includes(':') || /^\d+(?:\.\d+){3}$/.test(hostname)) {
    return undefined;
  }
  const labels = hostname.split('.').filter(Boolean);
  if (labels.length < 2) {
    return undefined;
  }
  const countryCodeSecondLevels = new Set(['ac', 'co', 'com', 'edu', 'gov', 'net', 'org']);
  const suffixLength =
    labels.at(-1)?.length === 2 && countryCodeSecondLevels.has(labels.at(-2) ?? '') ? 3 : 2;
  return labels.slice(-Math.min(suffixLength, labels.length)).join('.');
}

function compareRetention(
  left: PersistedTrafficRecord,
  right: PersistedTrafficRecord
): number {
  const scopeRank: Record<TrafficScopeDisposition, number> = {
    'in-scope': 4,
    review: 3,
    unknown: 2,
    'out-of-scope': 1
  };
  return (
    scopeRank[left.entry.scope.disposition] - scopeRank[right.entry.scope.disposition] ||
    left.entry.priority.score - right.entry.priority.score ||
    new Date(left.lastCapturedAt).getTime() - new Date(right.lastCapturedAt).getTime()
  );
}

function normalizeLimit(limit: number | undefined, fallback: number): number {
  if (limit === undefined || !Number.isFinite(limit)) {
    return fallback;
  }
  return Math.max(0, Math.min(fallback, Math.trunc(limit)));
}

function normalizeNonNegativeInteger(value: number | undefined): number {
  return typeof value === 'number' && Number.isFinite(value)
    ? Math.max(0, Math.trunc(value))
    : 0;
}

function encodedByteLength(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

function isPersistedTrafficLedgerState(
  value: unknown
): value is PersistedTrafficLedgerState {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const candidate = value as Partial<PersistedTrafficLedgerState>;
  return (
    candidate.version === STORAGE_VERSION &&
    Boolean(candidate.settings) &&
    Array.isArray(candidate.records)
  );
}

function isPersistedTrackedTargetState(
  value: unknown
): value is PersistedTrackedTargetState {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const candidate = value as Partial<PersistedTrackedTargetState>;
  return (
    candidate.version === STORAGE_VERSION &&
    Boolean(candidate.targets) &&
    typeof candidate.targets === 'object' &&
    !Array.isArray(candidate.targets) &&
    (candidate.pendingNavigations === undefined ||
      (Boolean(candidate.pendingNavigations) &&
        typeof candidate.pendingNavigations === 'object' &&
        !Array.isArray(candidate.pendingNavigations))) &&
    (candidate.committedNavigations === undefined ||
      (Boolean(candidate.committedNavigations) &&
        typeof candidate.committedNavigations === 'object' &&
        !Array.isArray(candidate.committedNavigations)))
  );
}

function isPersistedCoverageMarker(value: unknown): value is PersistedCoverageMarker {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const candidate = value as Partial<PersistedCoverageMarker>;
  return candidate.version === STORAGE_VERSION && Array.isArray(candidate.reasonCodes);
}

function normalizeTrackedTarget(value: unknown): TrackedTargetTab | undefined {
  if (!value || typeof value !== 'object') {
    return undefined;
  }
  const candidate = value as Partial<TrackedTargetTab>;
  const targetOrigin = sanitizeOptionalOrigin(candidate.targetOrigin);
  const policyId = normalizeOptionalIdentifier(candidate.policyId);
  const policyVersion = normalizeOptionalIdentifier(candidate.policyVersion);
  const contextId = normalizeOptionalIdentifier(candidate.contextId);
  const startedAt = candidate.startedAt ? normalizeTimestamp(candidate.startedAt) : undefined;
  if (!targetOrigin || !policyId || !policyVersion || !contextId || !startedAt) {
    return undefined;
  }
  return {
    targetOrigin,
    policyId,
    policyVersion,
    contextId,
    startedAt
  };
}

function normalizeTrackedTargetTransition(
  value: unknown
): TrackedTargetTransition | undefined {
  if (!value || typeof value !== 'object') {
    return undefined;
  }
  const candidate = value as Partial<TrackedTargetTransition>;
  if (!Number.isInteger(candidate.tabId) || (candidate.tabId ?? -1) < 0) {
    return undefined;
  }
  let sanitizedUrl: string;
  try {
    sanitizedUrl = sanitizeTrafficUrl(candidate.sanitizedUrl ?? '', 'GET').url;
  } catch {
    return undefined;
  }
  const startedAt = candidate.startedAt ? normalizeTimestamp(candidate.startedAt) : undefined;
  const lastObservedAt = candidate.lastObservedAt
    ? normalizeTimestamp(candidate.lastObservedAt)
    : undefined;
  const nextTarget = candidate.nextTarget
    ? normalizeTrackedTarget(candidate.nextTarget)
    : undefined;
  const attributionTarget = candidate.attributionTarget
    ? normalizeTrackedTarget(candidate.attributionTarget)
    : undefined;
  const committedDocumentId = normalizeOptionalIdentifier(candidate.committedDocumentId);
  if (
    !startedAt ||
    !lastObservedAt ||
    (candidate.nextTarget !== undefined && !nextTarget) ||
    (candidate.attributionTarget !== undefined && !attributionTarget) ||
    (candidate.committedDocumentId !== undefined && !committedDocumentId)
  ) {
    return undefined;
  }
  return {
    tabId: candidate.tabId as number,
    sanitizedUrl,
    startedAt,
    lastObservedAt,
    nextTarget,
    attributionTarget,
    committedDocumentId
  };
}

function normalizeCommittedNavigationMarker(
  value: unknown
): CommittedNavigationMarker | undefined {
  if (!value || typeof value !== 'object') {
    return undefined;
  }
  const candidate = value as Partial<CommittedNavigationMarker>;
  let sanitizedUrl: string | undefined;
  if (candidate.sanitizedUrl !== undefined) {
    try {
      sanitizedUrl = sanitizeTrafficUrl(candidate.sanitizedUrl, 'GET').url;
    } catch {
      return undefined;
    }
  }
  const documentId = normalizeOptionalIdentifier(candidate.documentId);
  const contextId = normalizeOptionalIdentifier(candidate.contextId);
  const committedAt = candidate.committedAt
    ? normalizeTimestamp(candidate.committedAt)
    : undefined;
  const startedAt = candidate.startedAt ? normalizeTimestamp(candidate.startedAt) : undefined;
  const target = candidate.target ? normalizeTrackedTarget(candidate.target) : undefined;
  if (
    !documentId ||
    !contextId ||
    !committedAt ||
    !startedAt ||
    (candidate.target !== undefined && !target)
  ) {
    return undefined;
  }
  return {
    sanitizedUrl,
    documentId,
    committedAt,
    contextId,
    startedAt,
    acceptLateRequest: candidate.acceptLateRequest === true,
    target
  };
}

function normalizePersistedRecord(
  rawRecord: PersistedTrafficRecord
): PersistedTrafficRecord | undefined {
  if (
    !rawRecord ||
    typeof rawRecord !== 'object' ||
    !Number.isInteger(rawRecord.tabId) ||
    !rawRecord.entry ||
    typeof rawRecord.entry.entryId !== 'string' ||
    !rawRecord.entry.observation ||
    !Array.isArray(rawRecord.entry.evidence)
  ) {
    return undefined;
  }
  const sourceOrigin = sanitizeOptionalOrigin(rawRecord.sourceOrigin);
  const targetOrigin = sanitizeOptionalOrigin(rawRecord.targetOrigin);
  const targetContextId = normalizeOptionalIdentifier(rawRecord.targetContextId);
  const targetStartedAt = targetContextId && rawRecord.targetStartedAt
    ? normalizeTimestamp(rawRecord.targetStartedAt)
    : undefined;
  const lastCapturedAt = normalizeTimestamp(rawRecord.lastCapturedAt);
  if (!lastCapturedAt) {
    return undefined;
  }
  const observation = rawRecord.entry.observation;
  const entry = capAggregatedEntry({
    ...rawRecord.entry,
    observation: {
      ...observation,
      requestHeaderNames: metadataNames(observation.requestHeaderNames ?? [], 'header'),
      responseHeaderNames: metadataNames(observation.responseHeaderNames ?? [], 'header'),
      requestBodyFieldNames: metadataNames(observation.requestBodyFieldNames ?? [], 'field')
    }
  });
  return {
    entry,
    tabId: rawRecord.tabId,
    sourceOrigin,
    targetOrigin,
    targetContextId: targetStartedAt ? targetContextId : undefined,
    targetStartedAt,
    lastCapturedAt
  };
}

function normalizeOptionalIdentifier(value: string | undefined): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const normalized = value.trim().slice(0, 256);
  return normalized || undefined;
}

function normalizeTimestamp(value: string): string | undefined {
  const timestamp = new Date(value);
  return Number.isFinite(timestamp.getTime()) ? timestamp.toISOString() : undefined;
}

function laterTimestamp(left: string, right: string): string {
  return new Date(left).getTime() >= new Date(right).getTime() ? left : right;
}

function earlierTimestamp(left: string, right: string): string {
  return new Date(left).getTime() <= new Date(right).getTime() ? left : right;
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort((left, right) => left.localeCompare(right));
}
