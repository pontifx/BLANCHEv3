import type {
  ExportWarning,
  JsonObject,
  JsonValue,
  TrafficLedgerEntryV1
} from '../../../../shared-schema/src';
import type {
  Logger,
  ModuleActionContext,
  ModuleActionResult,
  ModuleBackgroundController,
  ModuleDescriptor,
  ModuleHostServices
} from '../../shared/contracts';
import { createId, isInspectableUrl } from '../../shared/helpers';
import type {
  LatentFeatureCandidate,
  JavascriptFullTestRun,
  JavascriptTestCell,
  LatentFeatureMutationRecord,
  LatentFeatureProbeChange,
  LatentFeatureProbeRecord,
  LatentFeatureScanRecord
} from '../../shared/latentFeatureWorkbench';
import { createScriptArtifactFingerprint } from '../../shared/latentFeatureWorkbench';
import type { ContentInstrumentationResponse } from '../burpBridge/types';
import {
  analyzeLatentFeatures,
  type LatentFeatureTextSource,
  type RuntimeObservedFeatureCandidate
} from './analyzer';
import { analyzeScriptPurpose } from './scriptPurposeAnalyzer';
import {
  SCRIPT_PURPOSE_RUBRIC_VERSION,
  type ScriptBehaviorAxis,
  type ScriptPurposeAnalysisResult,
  type ScriptPurposeCategory,
  type ScriptPurposeSourceInput,
  type ScriptRuntimeObservationInput
} from './scriptPurposeRubric';
import {
  collectLatentFeaturePageSignals,
  type LatentFeaturePageSignals
} from './pageSignalsScript';
import {
  assessDependencies,
  detectDependencies,
  type DependencyAssessment
} from '../../background/dependencyIntelligence';
import {
  captureLatentFeatureDomSignatures,
  diffLatentFeatureDomSignatures,
  highlightLatentFeatureDomChanges,
  type LatentFeatureDomDiff,
  type LatentFeatureDomSnapshot
} from './domToggleObservation';

const CONTENT_MESSAGE_CHANNEL = 'blanche-burp-bridge';
const MAX_SCOPED_REDIRECT_HOPS = 10;
const MAX_SCRIPT_ASSESSMENTS_PER_SCAN = 64;
const MAX_PROBE_ORIGINAL_VALUE_CHARACTERS = 65_536;
const MAX_TOGGLE_DOM_SIGNATURES = 1_000;
const MAX_TOGGLE_DOM_DIFF_PER_KIND = 30;
const TOGGLE_HIGHLIGHT_DURATION_MS = 5_000;
const TOGGLE_OBSERVATION_SETTLE_MS = 350;
const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);

interface LatentFeatureSettings {
  autoDiscoverOnNavigation: boolean;
  probeLoadedLibraries: boolean;
  includeThirdPartyLibraries: boolean;
  libraryThreadCount: number;
  libraryDelayMs: number;
  maxLibrariesPerScan: number;
  maxLibraryBytes: number;
  maxTotalLibraryBytes: number;
  maxCandidates: number;
  javascriptObservationMs: number;
  reloadAfterProbe: boolean;
  checkDependencyAdvisories: boolean;
}

interface LoadedLibraryReadResult {
  sources: LatentFeatureTextSource[];
  loadedCount: number;
  readCount: number;
  failureCount: number;
  bytesRead: number;
  warnings: string[];
}

type ScopedLibraryFetchResult =
  | {
      ok: true;
      response: Response;
      finalUrl: string;
    }
  | {
      ok: false;
      blockedUrl: string;
      reason: string;
    };

export function createLatentFeaturesBackgroundController(input: {
  descriptor: ModuleDescriptor;
  logger: Logger;
  host: ModuleHostServices;
}): ModuleBackgroundController {
  type TabActionKind =
    | 'automatic-passive-discovery'
    | 'manual-passive-discovery'
    | 'startup-observation'
    | 'probe-candidate'
    | 'set-candidate-state'
    | 'restore-probe';
  const scheduledTabActions = new Map<
    number,
    { kind: TabActionKind; promise: Promise<ModuleActionResult> }
  >();
  const scheduleTabAction = (
    tabId: number,
    kind: TabActionKind,
    operation: () => Promise<ModuleActionResult>,
    coalesceSameKind = false
  ): Promise<ModuleActionResult> => {
    const existing = scheduledTabActions.get(tabId);
    if (coalesceSameKind && existing?.kind === kind) return existing.promise;
    const predecessor = existing?.promise;
    let scheduled!: Promise<ModuleActionResult>;
    scheduled = (async () => {
      if (predecessor) {
        try {
          await predecessor;
        } catch {
          // A queued action still receives its own attempt and result.
        }
      }
      return operation();
    })().finally(() => {
      if (scheduledTabActions.get(tabId)?.promise === scheduled) {
        scheduledTabActions.delete(tabId);
      }
    });
    scheduledTabActions.set(tabId, { kind, promise: scheduled });
    return scheduled;
  };

  return {
    async onHostStart() {
      input.logger.info('Latent Features background controller ready');
    },
    async runAction(request, context) {
      switch (request.actionId) {
        case 'discover': {
          if (!request.tabId) {
            return errorResult('Latent feature discovery requires a target tab.');
          }
          const automatic = request.input?.automatic === true;
          return scheduleTabAction(
            request.tabId,
            automatic ? 'automatic-passive-discovery' : 'manual-passive-discovery',
            () =>
              runDiscovery(
                input.descriptor,
                request.tabId!,
                {
                  automatic,
                  fullJavascriptTest: false
                },
                context
              ),
            true
          );
        }
        case 'testJavascript': {
          if (!request.tabId) {
            return errorResult('The JavaScript startup observation requires a target tab.');
          }
          return scheduleTabAction(request.tabId, 'startup-observation', () =>
            runDiscovery(
              input.descriptor,
              request.tabId!,
              {
                automatic: false,
                fullJavascriptTest: true
              },
              context
            ),
            true
          );
        }
        case 'probeCandidate': {
          if (!request.tabId) {
            return errorResult('A target tab is required to probe a local feature.');
          }
          return scheduleTabAction(request.tabId, 'probe-candidate', () =>
            runCandidateStateChange(
              request.tabId,
              request.input?.candidateId,
              'enabled',
              context
            )
          );
        }
        case 'setCandidateState': {
          if (!request.tabId) {
            return errorResult('A target tab is required to change a local feature state.');
          }
          const requestedState = request.input?.state;
          if (requestedState !== 'enabled' && requestedState !== 'disabled') {
            return errorResult('Local feature state must be either enabled or disabled.');
          }
          return scheduleTabAction(request.tabId, 'set-candidate-state', () =>
            runCandidateStateChange(
              request.tabId,
              request.input?.candidateId,
              requestedState,
              context
            )
          );
        }
        case 'restoreProbe': {
          if (!request.tabId) {
            return errorResult('A target tab is required to restore a local feature probe.');
          }
          return scheduleTabAction(request.tabId, 'restore-probe', () =>
            restoreActiveProbe(request.tabId, context)
          );
        }
        default:
          return errorResult(`Unsupported Latent Features action: ${request.actionId}`);
      }
    }
  };
}

async function runDiscovery(
  descriptor: ModuleDescriptor,
  tabId: number,
  options: {
    automatic: boolean;
    fullJavascriptTest: boolean;
  },
  context: ModuleActionContext
): Promise<ModuleActionResult> {
  const settings = resolveSettings(context.settings);
  let tab = await chrome.tabs.get(tabId);
  if (!isInspectableUrl(tab.url) || !tab.url?.startsWith('http')) {
    return errorResult(
      `Latent feature discovery supports http(s) tabs. Current URL: ${tab.url ?? 'unknown'}`
    );
  }

  const startingUrl = tab.url;
  const startingOrigin = new URL(startingUrl).origin;
  const initialScopeDecision = context.services.evaluateTrafficScope(startingUrl, 'GET');
  let effectiveScopeDecision = initialScopeDecision;
  let testTrafficLedger:
    | Awaited<ReturnType<ModuleHostServices['getTrafficLedgerExport']>>
    | undefined;
  if (options.fullJavascriptTest && initialScopeDecision.disposition !== 'in-scope') {
    return errorResult(
      `The JavaScript startup observation requires the current tab to be explicitly in scope. ${sanitizeRecordedUrl(startingUrl) ?? startingOrigin} is ${initialScopeDecision.disposition} under scope policy ${initialScopeDecision.policyId} v${initialScopeDecision.policyVersion}.`
    );
  }
  if (options.fullJavascriptTest && context.services.getLatentFeatureWorkbenchState().activeProbe) {
    return errorResult(
      'Restore the active local feature probe before observing JavaScript startup so the baseline is explicit.'
    );
  }

  const session = context.sessions.begin({
    moduleId: descriptor.id,
    tabId,
    mode: options.fullJavascriptTest ? 'instrumented' : 'passive',
    reloadTriggered: options.fullJavascriptTest,
    note: options.fullJavascriptTest
      ? 'Bounded delivered JavaScript startup observation'
      : options.automatic
        ? 'Automatic latent feature and JavaScript analysis'
        : 'Latent feature and JavaScript analysis'
  });

  try {
    if (options.fullJavascriptTest) {
      await reloadAndWaitForTopLevelLoad(tabId);
      if (settings.javascriptObservationMs > 0) {
        await delay(settings.javascriptObservationMs);
      }
      tab = await chrome.tabs.get(tabId);
      if (!tab.url || !/^https?:/i.test(tab.url)) {
        throw new Error('The startup observation reload left the inspectable HTTP(S) page.');
      }
      const finalOrigin = new URL(tab.url).origin;
      const finalScopeDecision = context.services.evaluateTrafficScope(tab.url, 'GET');
      effectiveScopeDecision = finalScopeDecision;
      if (finalOrigin !== startingOrigin || finalScopeDecision.disposition !== 'in-scope') {
        throw new Error(
          `The startup observation stopped after navigation to ${sanitizeRecordedUrl(tab.url) ?? finalOrigin}; the final page must retain origin ${startingOrigin} and an explicit in-scope decision.`
        );
      }
      // Freeze the ledger view at the end of the configured startup observation window. Source
      // acquisition below can make separate anonymous reads and must not extend this runtime window.
      testTrafficLedger = await context.services.getTrafficLedgerExport({
        sourceSessionId: session.sessionId,
        tabId,
        targetOrigin: startingOrigin,
        since: session.startedAt,
        limit: 1000
      });
    }
    // Snapshot page-world events at the same cutoff as the Traffic ledger. Static page/source
    // collection below can take longer and must not silently extend the runtime window.
    const instrumentation = await collectRuntimeInstrumentation(tabId);
    if (instrumentation?.frameUrl) {
      let instrumentationFrameUrl: URL;
      try {
        instrumentationFrameUrl = new URL(instrumentation.frameUrl);
      } catch {
        throw new Error('Discarded runtime instrumentation with an invalid frame URL.');
      }
      if (
        !instrumentation.topFrame ||
        !/^https?:$/.test(instrumentationFrameUrl.protocol) ||
        instrumentationFrameUrl.origin !== startingOrigin
      ) {
        throw new Error(
          `Discarded runtime instrumentation for ${sanitizeRecordedUrl(instrumentationFrameUrl.href) ?? instrumentationFrameUrl.origin}; the top frame must retain starting origin ${startingOrigin}.`
        );
      }
    }
    const pageSignals = await collectPageSignals(tabId);
    let signalPageUrl: URL;
    try {
      signalPageUrl = new URL(pageSignals.pageUrl);
    } catch {
      throw new Error('The collected page signals did not identify a valid HTTP(S) document URL.');
    }
    const signalScopeDecision = context.services.evaluateTrafficScope(signalPageUrl.href, 'GET');
    if (
      !/^https?:$/.test(signalPageUrl.protocol) ||
      pageSignals.origin !== signalPageUrl.origin ||
      signalPageUrl.origin !== startingOrigin
    ) {
      throw new Error(
        `Discarded page signals for ${sanitizeRecordedUrl(signalPageUrl.href) ?? signalPageUrl.origin}; the collected document must retain starting origin ${startingOrigin}.`
      );
    }
    effectiveScopeDecision = signalScopeDecision;
    if (options.fullJavascriptTest && signalScopeDecision.disposition !== 'in-scope') {
      throw new Error(
        `Discarded startup page signals because ${sanitizeRecordedUrl(signalPageUrl.href) ?? signalPageUrl.origin} is ${signalScopeDecision.disposition} under scope policy ${signalScopeDecision.policyId} v${signalScopeDecision.policyVersion}; an explicit in-scope decision is required.`
      );
    }
    const runtimeObservedCandidates = collectRuntimeObservedCandidates(instrumentation);
    const libraryReads = settings.probeLoadedLibraries
      ? await readLoadedLibraries(
          pageSignals,
          settings,
          (rawUrl, method) => context.services.evaluateTrafficScope(rawUrl, method)
        )
      : emptyLibraryReadResult(pageSignals.loadedScriptUrls.length);

    const textSources: LatentFeatureTextSource[] = [
      ...(pageSignals.rawDocumentSource
        ? [
            {
              sourceKind: 'document' as const,
              label: pageSignals.rawDocumentSource.label,
              sourceUrl: sanitizeRecordedUrl(pageSignals.pageUrl),
              contentType: pageSignals.rawDocumentSource.contentType,
              truncated: pageSignals.rawDocumentSource.truncated,
              text: pageSignals.rawDocumentSource.text
            }
          ]
        : []),
      ...pageSignals.inlineScripts.map((script) => ({
        sourceKind: 'inline-script' as const,
        label: script.label,
        sourceUrl: sanitizeRecordedUrl(pageSignals.pageUrl),
        contentType: 'inline',
        truncated: script.truncated,
        text: script.text
      })),
      ...libraryReads.sources
    ];

    const candidates = analyzeLatentFeatures({
      textSources,
      storageEntries: pageSignals.storageEntries.map((entry) => ({
        area: entry.area,
        key: entry.key,
        value: entry.value
      })),
      structuredSources: [
        ...pageSignals.runtimeGlobals.map((signal) => ({
          sourceKind: 'runtime-global' as const,
          label: signal.label,
          value: signal.value
        })),
        ...pageSignals.domSignals.map((signal) => ({
          sourceKind: 'dom' as const,
          label: signal.label,
          value: signal.value
        }))
      ],
      runtimeObservedCandidates,
      maxCandidates: settings.maxCandidates
    });
    const assessmentSources = textSources.slice(0, MAX_SCRIPT_ASSESSMENTS_PER_SCAN);
    const omittedAssessmentSourceCount = Math.max(0, textSources.length - assessmentSources.length);
    const scriptAssessments = await analyzeDeliveredScripts({
      sources: assessmentSources,
      pageUrl: pageSignals.pageUrl,
      pageOrigin: pageSignals.origin,
      instrumentation,
      evaluateTrafficScope: context.services.evaluateTrafficScope
    });
    const dependencies = detectDependencies(textSources).slice(0, settings.maxLibrariesPerScan);
    const dependencyAssessments: DependencyAssessment[] = settings.checkDependencyAdvisories
      ? await assessDependencies(dependencies, {
          concurrency: settings.libraryThreadCount,
          delayMs: settings.libraryDelayMs
        })
      : dependencies.map((dependency) => ({
          ...dependency,
          vulnerabilityIds: [],
          advisoryUrls: [],
          latestVersion: undefined,
          status: 'unknown' as const,
          note: 'Public advisory lookup is disabled.'
        }));

    if (options.fullJavascriptTest) {
      const persistenceTab = await chrome.tabs.get(tabId);
      if (!persistenceTab.url || !/^https?:/i.test(persistenceTab.url)) {
        throw new Error(
          'The startup observation left the inspectable HTTP(S) page before results could be persisted.'
        );
      }
      const persistenceOrigin = new URL(persistenceTab.url).origin;
      const persistenceScopeDecision = context.services.evaluateTrafficScope(
        persistenceTab.url,
        'GET'
      );
      const persistedDocumentUrl = new URL(persistenceTab.url);
      const collectedDocumentUrl = new URL(pageSignals.pageUrl);
      persistedDocumentUrl.hash = '';
      collectedDocumentUrl.hash = '';
      if (
        persistenceOrigin !== startingOrigin ||
        persistedDocumentUrl.href !== collectedDocumentUrl.href ||
        persistenceScopeDecision.disposition !== 'in-scope'
      ) {
        throw new Error(
          `Discarded startup results after navigation to ${sanitizeRecordedUrl(persistenceTab.url) ?? persistenceOrigin}; persistence requires origin ${startingOrigin} and an explicit in-scope decision.`
        );
      }
      effectiveScopeDecision = persistenceScopeDecision;
    }

    const previousScan = context.services.getLatentFeatureWorkbenchState().lastScan;
    const previousCandidateIds =
      previousScan?.tabId === tabId && previousScan.origin === pageSignals.origin
        ? new Set(previousScan.candidates.map((candidate) => candidate.id))
        : new Set<string>();
    const scan: LatentFeatureScanRecord = {
      scanId: createId('latent-scan'),
      scannedAt: new Date().toISOString(),
      tabId,
      pageUrl: sanitizeRecordedUrl(pageSignals.pageUrl) ?? pageSignals.origin,
      origin: pageSignals.origin,
      title: pageSignals.title || tab.title,
      candidates,
      newCandidateIds: candidates
        .filter((candidate) => !previousCandidateIds.has(candidate.id))
        .map((candidate) => candidate.id),
      scriptAssessments,
      stats: {
        pageSignalCount:
          pageSignals.storageEntries.length +
          pageSignals.runtimeGlobals.length +
          pageSignals.domSignals.length,
        inlineScriptCount: pageSignals.inlineScripts.length,
        runtimeObservationCount: runtimeObservedCandidates.length,
        loadedLibraryCount: libraryReads.loadedCount,
        libraryReadCount: libraryReads.readCount,
        libraryFailureCount: libraryReads.failureCount,
        libraryBytesRead: libraryReads.bytesRead,
        libraryThreadCount: settings.libraryThreadCount,
        libraryDelayMs: settings.libraryDelayMs
      },
      warnings: [
        ...pageSignals.warnings,
        ...libraryReads.warnings,
        ...(omittedAssessmentSourceCount > 0
          ? [
              `${omittedAssessmentSourceCount} delivered source bod${omittedAssessmentSourceCount === 1 ? 'y was' : 'ies were'} omitted at the ${MAX_SCRIPT_ASSESSMENTS_PER_SCAN}-assessment persistence cap.`
            ]
          : [])
      ]
        .map((warning) => sanitizePersistedText(warning))
        .slice(0, 50)
    };

    const javascriptTest = options.fullJavascriptTest
      ? buildJavascriptFullTest({
          sessionStartedAt: session.startedAt,
          scanId: scan.scanId,
          tabId,
          pageUrl: pageSignals.pageUrl,
          origin: pageSignals.origin,
          scopeDecision: effectiveScopeDecision,
          scriptAssessments,
          instrumentation,
          trafficEntries: testTrafficLedger?.entries ?? [],
          scanWarnings: scan.warnings
        })
      : undefined;

    const currentWorkbench = context.services.getLatentFeatureWorkbenchState();
    await context.services.updateLatentFeatureWorkbenchState({
      ...currentWorkbench,
      lastScan: scan,
      // A new passive scan can have different artifact hashes even on the same origin. Clear the
      // old startup run instead of rendering it beside evidence it did not test.
      lastJavascriptTest: javascriptTest
    });

    const hostname = new URL(pageSignals.pageUrl).hostname;
    const topScriptAssessment = scriptAssessments[0];
    const opaqueScriptCount = scriptAssessments.filter(
      (assessment) =>
        assessment.transform.detected.includes('packed') ||
        assessment.transform.detected.includes('obfuscated')
    ).length;
    await context.services.recordFinding({
      kind: 'javascript-analysis',
      sourceModuleId: descriptor.id,
      host: hostname,
      severity: 'info',
      title: `Assessed ${scriptAssessments.length} delivered JavaScript source${
        scriptAssessments.length === 1 ? '' : 's'
      }`,
      detail: [
        `${opaqueScriptCount} packed or obfuscated.`,
        topScriptAssessment
          ? `Highest review priority ${topScriptAssessment.reviewPriority.score}/100 (${topScriptAssessment.reviewPriority.band}); this is triage, not vulnerability severity.`
          : 'No script body was available within scope and collection caps.',
        options.fullJavascriptTest && javascriptTest
          ? `Startup observation ${javascriptTest.overallStatus} with ${javascriptTest.runtimeStats.eventCount} bounded runtime events.`
          : ''
      ]
        .filter(Boolean)
        .join(' '),
      context: {
        scanId: scan.scanId,
        rubricVersion: SCRIPT_PURPOSE_RUBRIC_VERSION,
        assessmentCount: scriptAssessments.length,
        opaqueScriptCount,
        fullTestRunId: javascriptTest?.testRunId ?? null
      }
    });
    if (topScriptAssessment) {
      const primaryPurposes = topScriptAssessment.purposeClaims
        .filter((claim) => claim.role === 'primary' || claim.role === 'secondary')
        .slice(0, 4);
      await context.services.recordIntelligenceFinding({
        kind: 'client-script',
        score: topScriptAssessment.reviewPriority.score,
        title: `${scriptAssessments.length} delivered script source${scriptAssessments.length === 1 ? '' : 's'} assessed`,
        summary: `Highest review priority is ${topScriptAssessment.reviewPriority.score}/100 (${topScriptAssessment.reviewPriority.band}). Purpose: ${primaryPurposes.map((claim) => claim.category).join(', ') || 'unknown'}. The score ranks review and is not vulnerability severity.`,
        host: hostname,
        evidence: scriptAssessments.slice(0, 8).map((assessment) => ({
          label: assessment.artifact.label,
          detail: `${assessment.transform.detected.join(', ')} · ${assessment.purposeClaims[0]?.category ?? 'unknown'} · ${assessment.coverage.status} coverage · priority ${assessment.reviewPriority.score}`,
          url: assessment.artifact.finalUrl ?? assessment.artifact.sourceUrl
        })),
        context: {
          scanId: scan.scanId,
          rubricVersion: SCRIPT_PURPOSE_RUBRIC_VERSION,
          topArtifactId: topScriptAssessment.artifact.artifactId,
          fullTestRunId: javascriptTest?.testRunId ?? null
        },
        question:
          topScriptAssessment.reviewPriority.score >= 75
            ? {
                prompt: `Review the urgent delivered-script assessment for ${topScriptAssessment.artifact.label}?`,
                reason: 'Raised from the rubric’s behavior factors and evidence maturity; the score is review priority, not proof of a vulnerability.',
                actions: [
                  { id: 'inspect', label: 'Inspect in Labs', kind: 'inspect' },
                  { id: 'dismiss', label: 'Dismiss', kind: 'dismiss' }
                ]
              }
            : undefined
      });
    }
    const probeableCount = candidates.filter((candidate) => candidate.probeable).length;
    const topNames = candidates
      .slice(0, 5)
      .map((candidate) => candidate.key)
      .join(', ');
    await context.services.recordFinding({
      kind: 'latent-feature',
      sourceModuleId: descriptor.id,
      host: hostname,
      severity: candidates.length > 0 ? 'notice' : 'info',
      title: `Discovered ${candidates.length} latent feature candidate${
        candidates.length === 1 ? '' : 's'
      }`,
      detail: [
        `${probeableCount} reversible local candidate${probeableCount === 1 ? '' : 's'}.`,
        topNames ? `Top signals: ${topNames}.` : ''
      ]
        .filter(Boolean)
        .join(' '),
      context: {
        scanId: scan.scanId,
        origin: scan.origin,
        automatic: options.automatic,
        libraryReadCount: scan.stats.libraryReadCount,
        libraryThreadCount: scan.stats.libraryThreadCount,
        libraryDelayMs: scan.stats.libraryDelayMs
      }
    });
    const testerCandidates = candidates.filter((candidate) =>
      candidate.probeable ||
      candidate.controlSurface === 'runtime-response' ||
      candidate.controlSurface === 'opaque-pair' ||
      /feature|flag|experiment|variant|gate|preview|beta|rollout|enabled/i.test(candidate.key) ||
      candidate.evidence.some((entry) => /flag-client callsite|browser storage/i.test(entry.detail))
    );
    if (testerCandidates.length > 0) {
      const topCandidate = testerCandidates[0];
      const testerProbeableCount = testerCandidates.filter((candidate) => candidate.probeable).length;
      const score = Math.min(
        96,
        55 + (topCandidate?.confidence === 'high' ? 20 : 8) + (topCandidate?.probeable ? 15 : 0)
      );
      await context.services.recordIntelligenceFinding({
        kind: 'client-feature',
        score,
        title: `${testerCandidates.length} shipped client feature candidate${testerCandidates.length === 1 ? '' : 's'}`,
        summary: `${testerProbeableCount} can be changed reversibly in browser storage; bundle-only and opaque pairs remain evidence-only until correlated.`,
        host: hostname,
        evidence: testerCandidates.slice(0, 8).map((candidate) => ({
          label: candidate.key,
          detail: `${candidate.confidence} confidence · ${candidate.controlSurface} · ${candidate.probeable ? 'reversible local probe' : 'evidence only'}`,
          url: candidate.evidence.find((entry) => entry.sourceUrl)?.sourceUrl
        })),
        context: {
          scanId: scan.scanId,
          topCandidateId: topCandidate?.id ?? '',
          probeableCount: testerProbeableCount
        },
        question: topCandidate?.probeable
          ? {
              prompt: `BLANCHE found ${topCandidate.key} disabled in browser-controlled state. Apply the reversible local probe?`,
              reason: 'Raised from a high-confidence shipped toggle with its original value captured for restore.',
              actions: [
                { id: 'apply-probe', label: 'Apply reversible probe', kind: 'follow-up' },
                { id: 'report', label: 'Mark reportable', kind: 'report' },
                { id: 'dismiss', label: 'Dismiss', kind: 'dismiss' }
              ]
            }
          : undefined
      });
    }
    for (const dependency of dependencyAssessments.filter((entry) => entry.status === 'vulnerable' || entry.status === 'outdated')) {
      const score = dependency.status === 'vulnerable' ? 96 : 76;
      await context.services.recordIntelligenceFinding({
        kind: 'library',
        score,
        title: `${dependency.displayName} ${dependency.version} is ${dependency.status}`,
        summary: dependency.status === 'vulnerable'
          ? `OSV returned ${dependency.vulnerabilityIds.length} advisory identifier${dependency.vulnerabilityIds.length === 1 ? '' : 's'} for the shipped npm version.`
          : `The shipped version differs from npm's latest ${dependency.latestVersion ?? 'published'} version.`,
        host: hostname,
        evidence: [
          { label: 'Shipped version', detail: `${dependency.packageName}@${dependency.version}`, url: dependency.sourceUrl },
          ...(dependency.latestVersion ? [{ label: 'Latest npm version', detail: dependency.latestVersion }] : []),
          ...(dependency.latestPublishedAt ? [{ label: 'Latest release published', detail: dependency.latestPublishedAt }] : []),
          ...dependency.vulnerabilityIds.slice(0, 8).map((id, index) => ({ label: 'OSV advisory', detail: id, url: dependency.advisoryUrls[index] }))
        ],
        question: {
          prompt: `${dependency.displayName} ${dependency.version} appears ${dependency.status}. Add it to the tester's report?`,
          reason: `Raised from a version string in a script the page already loaded, checked against npm metadata and the public OSV database.`
        }
      });
    }

    context.sessions.complete(
      session.sessionId,
      options.fullJavascriptTest
        ? `Startup observation assessed ${scriptAssessments.length} scripts and retained ${javascriptTest?.runtimeStats.eventCount ?? 0} runtime events`
        : `Assessed ${scriptAssessments.length} scripts and discovered ${candidates.length} latent feature candidates`
    );

    return {
      status:
        javascriptTest?.overallStatus === 'failed'
          ? 'error'
          : scan.warnings.length > 0 || javascriptTest?.overallStatus === 'partial'
            ? 'partial'
            : 'ok',
      message: `${options.fullJavascriptTest ? 'Bounded startup observation completed. ' : ''}Assessed ${scriptAssessments.length} delivered JavaScript source${scriptAssessments.length === 1 ? '' : 's'} and discovered ${candidates.length} latent feature candidate${
        candidates.length === 1 ? '' : 's'
      } (${probeableCount} reversible local). Read ${scan.stats.libraryReadCount} of ${
        scan.stats.loadedLibraryCount
      } already-loaded libraries with ${settings.libraryThreadCount} worker${
        settings.libraryThreadCount === 1 ? '' : 's'
      } and ${settings.libraryDelayMs} ms spacing.`,
      sessionId: session.sessionId,
      data: {
        scanId: scan.scanId,
        scriptAssessmentCount: scriptAssessments.length,
        highestScriptReviewPriority: topScriptAssessment?.reviewPriority.score ?? 0,
        javascriptTestRunId: javascriptTest?.testRunId ?? null,
        javascriptRuntimeEventCount: javascriptTest?.runtimeStats.eventCount ?? 0,
        candidateCount: candidates.length,
        probeableCount,
        libraryReadCount: scan.stats.libraryReadCount,
        libraryFailureCount: scan.stats.libraryFailureCount,
        libraryBytesRead: scan.stats.libraryBytesRead,
        libraryThreadCount: scan.stats.libraryThreadCount,
        libraryDelayMs: scan.stats.libraryDelayMs
      }
    };
  } catch (error) {
    if (options.fullJavascriptTest) {
      const failureMessage = error instanceof Error ? error.message : String(error);
      try {
        const workbench = context.services.getLatentFeatureWorkbenchState();
        const failureUrl = tab.url ?? startingUrl;
        const failureScopeDecision = /^https?:/i.test(failureUrl)
          ? context.services.evaluateTrafficScope(failureUrl, 'GET')
          : effectiveScopeDecision;
        await context.services.updateLatentFeatureWorkbenchState({
          ...workbench,
          lastJavascriptTest: buildFailedJavascriptFullTest({
            sessionStartedAt: session.startedAt,
            tabId,
            pageUrl: failureUrl,
            origin: sourceOrigin(failureUrl) ?? startingOrigin,
            scopeDecision: failureScopeDecision,
            failureMessage: sanitizePersistedText(failureMessage)
          })
        });
      } catch (persistenceError) {
        context.logger.warn('Unable to persist failed JavaScript startup-observation trace', {
          error:
            persistenceError instanceof Error
              ? persistenceError.message
              : String(persistenceError)
        });
      }
    }
    context.sessions.fail(
      session.sessionId,
      error instanceof Error ? error.message : String(error)
    );
    throw error;
  }
}

async function runCandidateStateChange(
  tabId: number | undefined,
  requestedCandidateId: JsonValue | undefined,
  requestedState: 'enabled' | 'disabled',
  context: ModuleActionContext
): Promise<ModuleActionResult> {
  if (!tabId) {
    return errorResult('A target tab is required to change a local feature state.');
  }

  const tab = await chrome.tabs.get(tabId);
  if (!tab.url || !/^https?:/i.test(tab.url)) {
    return errorResult(`Local feature toggles require an http(s) tab: ${tab.url ?? 'unknown'}`);
  }
  const scopeDecision = context.services.evaluateTrafficScope(tab.url, 'GET');
  if (scopeDecision.disposition !== 'in-scope') {
    return errorResult(
      `Local feature toggles require an explicitly in-scope page. The current page is ${scopeDecision.disposition} under scope policy ${scopeDecision.policyId} v${scopeDecision.policyVersion}.`
    );
  }

  const workbench = context.services.getLatentFeatureWorkbenchState();
  const scan = workbench.lastScan;
  if (!scan) {
    return errorResult('Run latent feature discovery before changing a candidate.');
  }
  const origin = new URL(tab.url).origin;
  if (scan.tabId !== tabId || scan.origin !== origin) {
    return errorResult(
      `The last discovery does not belong to this tab and origin. Scan tab ${tabId} at ${origin} before changing a feature.`
    );
  }
  if (
    workbench.activeProbe &&
    (workbench.activeProbe.tabId !== tabId || workbench.activeProbe.origin !== origin)
  ) {
    return errorResult(
      `The active probe belongs to tab ${workbench.activeProbe.tabId} at ${workbench.activeProbe.origin}. Restore it in that tab before changing this page.`
    );
  }

  const candidateId =
    typeof requestedCandidateId === 'string' ? requestedCandidateId : undefined;
  const candidate = candidateId
    ? scan.candidates.find((entry) => entry.id === candidateId)
    : scan.candidates.find((entry) => entry.probeable);
  if (!candidate) {
    return errorResult(
      candidateId
        ? 'The selected candidate is no longer present in the last scan.'
        : 'No reversible local feature candidate is available in the last scan.'
    );
  }
  const appliedValue =
    requestedState === 'enabled' ? candidate.enabledValue : candidate.disabledValue;
  if (
    !candidate.probeable ||
    !candidate.storageLocation ||
    candidate.currentValue === undefined ||
    appliedValue === undefined
  ) {
    return errorResult(
      `${candidate.key} was discovered, but it does not expose an explicit reversible browser-storage toggle.`
    );
  }

  const existingCandidateChange = workbench.activeProbe?.changes.find(
    (change) => change.candidateId === candidate.id
  );
  if (
    existingCandidateChange &&
    !sameStorageLocation(existingCandidateChange, candidate.storageLocation)
  ) {
    return errorResult(
      `${candidate.key} moved to a different storage location after its baseline was recorded. Restore the active probe before rescanning or changing it again.`
    );
  }

  let beforeSnapshot: LatentFeatureDomSnapshot;
  try {
    beforeSnapshot = await captureToggleDomSnapshot(tabId, origin);
  } catch (error) {
    return errorResult(
      `Unable to capture the required pre-toggle DOM signature: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  const [execution] = await chrome.scripting.executeScript({
    target: {
      tabId,
      allFrames: false
    },
    world: 'MAIN',
    func: applyStorageFeatureState,
    args: [
      {
        expectedOrigin: origin,
        area: candidate.storageLocation.area,
        storageKey: candidate.storageLocation.storageKey,
        jsonPath: candidate.storageLocation.jsonPath,
        format: candidate.storageLocation.format,
        expectedValue: candidate.currentValue,
        appliedValue,
        maxOriginalValueCharacters: MAX_PROBE_ORIGINAL_VALUE_CHARACTERS
      }
    ]
  });
  const applied = execution?.result as StorageFeatureStateResult | undefined;
  if (!applied?.ok) {
    return errorResult(
      `Unable to set ${candidate.key} ${requestedState}: ${applied?.error ?? 'page script returned no result'}`
    );
  }
  if (!applied.changed) {
    return {
      status: 'ok',
      message: `${candidate.key} is already ${requestedState}; its live value matched the scan and no write or reload was needed.`,
      data: {
        candidateId: candidate.id,
        key: candidate.key,
        requestedState,
        changed: false,
        origin
      }
    };
  }

  const settings = resolveSettings(context.settings);
  const existingContainerBaseline = workbench.activeProbe?.changes.find((change) =>
    sameStorageContainer(change, candidate.storageLocation!)
  );
  const change: LatentFeatureProbeChange = {
    candidateId: candidate.id,
    key: candidate.key,
    area: candidate.storageLocation.area,
    storageKey: candidate.storageLocation.storageKey,
    jsonPath: candidate.storageLocation.jsonPath,
    hadOriginalValue:
      existingCandidateChange?.hadOriginalValue ??
      existingContainerBaseline?.hadOriginalValue ??
      applied.hadOriginalValue,
    originalValue:
      existingCandidateChange?.originalValue ??
      existingContainerBaseline?.originalValue ??
      applied.originalValue,
    originalCandidateValue:
      existingCandidateChange?.originalCandidateValue ?? applied.previousCandidateValue,
    appliedValue
  };
  const changes = workbench.activeProbe
    ? replaceProbeChange(workbench.activeProbe.changes, change)
    : [change];
  const probe: LatentFeatureProbeRecord = workbench.activeProbe
    ? {
        ...workbench.activeProbe,
        changes,
        reloadTriggered: workbench.activeProbe.reloadTriggered || settings.reloadAfterProbe
      }
    : {
        probeId: createId('latent-probe'),
        createdAt: new Date().toISOString(),
        tabId,
        pageUrl: sanitizeRecordedUrl(tab.url) ?? origin,
        origin,
        changes,
        reloadTriggered: settings.reloadAfterProbe
      };
  const updatedScan: LatentFeatureScanRecord = {
    ...scan,
    candidates: scan.candidates.map((entry) =>
      entry.id === candidate.id
        ? {
            ...entry,
            status: 'active' as const,
            currentValue: appliedValue
          }
        : entry
    )
  };

  try {
    await context.services.updateLatentFeatureWorkbenchState({
      ...workbench,
      lastScan: updatedScan,
      activeProbe: probe
    });
    const persistedProbe = context.services.getLatentFeatureWorkbenchState().activeProbe;
    const persistedChange = persistedProbe?.changes.find(
      (entry) => entry.candidateId === candidate.id
    );
    if (
      persistedProbe?.probeId !== probe.probeId ||
      !persistedChange ||
      persistedChange.hadOriginalValue !== change.hadOriginalValue ||
      persistedChange.originalValue !== change.originalValue ||
      !Object.is(persistedChange.originalCandidateValue, change.originalCandidateValue)
    ) {
      throw new Error('The recovery record did not survive workbench normalization.');
    }
  } catch (error) {
    const rollback = await restoreSinglePreWriteValue(
      tabId,
      origin,
      candidate,
      applied
    );
    try {
      await context.services.updateLatentFeatureWorkbenchState(workbench);
    } catch {
      // The return message below makes the residual persistence uncertainty explicit.
    }
    if (!rollback.ok) {
      return errorResult(
        `The storage write succeeded but its recovery record could not be persisted, and automatic rollback also failed (${rollback.error}). The page may remain changed; do not close this tab before manually restoring ${candidate.storageLocation.area}.${candidate.storageLocation.storageKey}.`
      );
    }
    return errorResult(
      `The storage write was rolled back because its recovery record could not be persisted: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  const warnings: ExportWarning[] = [];
  if (settings.reloadAfterProbe) {
    try {
      await reloadAndWaitForTopLevelLoad(tabId);
    } catch (error) {
      warnings.push(toggleWarning(
        `The toggle was applied and recovery was saved, but the reload did not complete cleanly: ${error instanceof Error ? error.message : String(error)}`
      ));
    }
  }
  await delay(TOGGLE_OBSERVATION_SETTLE_MS);

  let pageDiff: LatentFeatureDomDiff = {
    added: [],
    changed: [],
    removed: [],
    truncated: false,
    limitations: [
      'The post-toggle DOM signature could not be captured; no claim about page changes is made.'
    ]
  };
  let highlightedCount = 0;
  try {
    const currentTab = await chrome.tabs.get(tabId);
    if (!currentTab.url || new URL(currentTab.url).origin !== origin) {
      throw new Error('the tab navigated away from the scanned origin');
    }
    const afterSnapshot = await captureToggleDomSnapshot(tabId, origin);
    pageDiff = diffLatentFeatureDomSignatures(
      beforeSnapshot,
      afterSnapshot,
      MAX_TOGGLE_DOM_DIFF_PER_KIND
    );
    try {
      const highlight = await highlightToggleDomDiff(tabId, origin, pageDiff);
      highlightedCount = highlight.highlightedCount;
      if (highlight.missedCount > 0) {
        warnings.push(toggleWarning(
          `${highlight.missedCount} observed DOM change${highlight.missedCount === 1 ? '' : 's'} could not be highlighted because the matching node was no longer present.`
        ));
      }
    } catch (error) {
      warnings.push(toggleWarning(
        `The toggle and DOM observation succeeded, but temporary page highlighting failed: ${error instanceof Error ? error.message : String(error)}`
      ));
    }
  } catch (error) {
    warnings.push(toggleWarning(
      `The toggle was applied, but the post-toggle DOM observation was unavailable: ${error instanceof Error ? error.message : String(error)}`
    ));
  }

  const mutation: LatentFeatureMutationRecord = {
    mutationId: createId('latent-mutation'),
    observedAt: new Date().toISOString(),
    tabId,
    pageUrl: sanitizeRecordedUrl(tab.url) ?? origin,
    origin,
    candidateId: candidate.id,
    key: candidate.key,
    requestedState,
    previousValue: applied.previousCandidateValue,
    appliedValue,
    reloadTriggered: settings.reloadAfterProbe,
    outcome: warnings.length > 0 ? 'applied-with-warnings' : 'applied',
    codeDiff: {
      before: formatStorageToggleCode(candidate, applied.previousCandidateValue),
      after: formatStorageToggleCode(candidate, appliedValue)
    },
    pageDiff: {
      ...pageDiff,
      highlightedCount
    }
  };
  try {
    const latestWorkbench = context.services.getLatentFeatureWorkbenchState();
    await context.services.updateLatentFeatureWorkbenchState({
      ...latestWorkbench,
      lastMutation: mutation
    });
  } catch (error) {
    warnings.push(toggleWarning(
      `The toggle and its recovery record were saved, but the DOM-diff observation record could not be persisted: ${error instanceof Error ? error.message : String(error)}`
    ));
  }

  try {
    await context.services.recordFinding({
      kind: 'latent-feature',
      sourceModuleId: 'latent-features',
      host: new URL(tab.url).hostname,
      severity: 'notice',
      title: `Set local feature ${candidate.key} ${requestedState}`,
      detail: `Changed ${candidate.storageLocation.area}.${candidate.storageLocation.storageKey}${
        candidate.storageLocation.jsonPath.length
          ? ` at ${candidate.storageLocation.jsonPath.join('.')}`
          : ''
      }. ${pageDiff.added.length + pageDiff.changed.length + pageDiff.removed.length} bounded DOM differences were observed afterward; this temporal comparison does not prove causation.`,
      context: {
        probeId: probe.probeId,
        mutationId: mutation.mutationId,
        candidateId: candidate.id,
        requestedState,
        origin,
        reloadTriggered: settings.reloadAfterProbe
      }
    });
  } catch (error) {
    warnings.push(toggleWarning(
      `The toggle succeeded, but the finding-feed entry could not be recorded: ${error instanceof Error ? error.message : String(error)}`
    ));
  }

  return {
    status: warnings.length > 0 ? 'partial' : 'ok',
    message: `Set ${candidate.key} ${requestedState}${
      settings.reloadAfterProbe ? ' and reloaded once' : ''
    }. Recovery now covers ${probe.changes.length} feature change${probe.changes.length === 1 ? '' : 's'}; ${pageDiff.added.length + pageDiff.changed.length + pageDiff.removed.length} bounded DOM differences were observed afterward.`,
    warnings: warnings.length > 0 ? warnings : undefined,
    data: {
      probeId: probe.probeId,
      mutationId: mutation.mutationId,
      candidateId: candidate.id,
      key: candidate.key,
      requestedState,
      changed: true,
      origin,
      reloadTriggered: settings.reloadAfterProbe,
      activeChangeCount: probe.changes.length,
      addedNodeCount: pageDiff.added.length,
      changedNodeCount: pageDiff.changed.length,
      removedNodeCount: pageDiff.removed.length,
      highlightedCount
    }
  };
}

async function restoreActiveProbe(
  tabId: number | undefined,
  context: ModuleActionContext
): Promise<ModuleActionResult> {
  if (!tabId) {
    return errorResult('A target tab is required to restore a local feature probe.');
  }
  const tab = await chrome.tabs.get(tabId);
  if (!tab.url || !/^https?:/i.test(tab.url)) {
    return errorResult(`Probe restoration requires an http(s) tab: ${tab.url ?? 'unknown'}`);
  }

  const workbench = context.services.getLatentFeatureWorkbenchState();
  const probe = workbench.activeProbe;
  if (!probe) {
    return errorResult('There is no active local feature probe to restore.');
  }
  const origin = new URL(tab.url).origin;
  if (probe.tabId !== tabId || probe.origin !== origin) {
    return errorResult(
      `The active probe belongs to tab ${probe.tabId} at ${probe.origin}. Restore it from that exact tab and origin.`
    );
  }

  const [execution] = await chrome.scripting.executeScript({
    target: {
      tabId,
      allFrames: false
    },
    world: 'MAIN',
    func: restoreStorageFeatureProbe,
    args: [
      {
        expectedOrigin: origin,
        changes: probe.changes
      }
    ]
  });
  const restored = execution?.result as StorageFeatureRestoreResult | undefined;
  if (!restored?.ok) {
    return errorResult(
      `Unable to restore the local probe: ${restored?.error ?? 'page script returned no result'}`
    );
  }

  const restoredChanges = new Map(
    probe.changes.map((change) => [change.candidateId, change] as const)
  );
  const lastScan = workbench.lastScan
    ? {
        ...workbench.lastScan,
        candidates: workbench.lastScan.candidates.map((candidate) =>
          restoredChanges.has(candidate.id)
            ? {
                ...candidate,
                status: 'restored' as const,
                currentValue: restoredChanges.get(candidate.id)?.originalCandidateValue
              }
            : candidate
        )
      }
    : undefined;
  const warnings: ExportWarning[] = [];
  try {
    await context.services.updateLatentFeatureWorkbenchState({
      ...workbench,
      lastScan,
      activeProbe: undefined
    });
  } catch (error) {
    warnings.push(toggleWarning(
      `All exact storage baselines were restored, but clearing the persisted recovery record failed: ${error instanceof Error ? error.message : String(error)}`
    ));
  }

  const settings = resolveSettings(context.settings);
  if (settings.reloadAfterProbe) {
    try {
      await reloadAndWaitForTopLevelLoad(tabId);
    } catch (error) {
      warnings.push(toggleWarning(
        `The exact storage baselines were restored, but the reload did not complete cleanly: ${error instanceof Error ? error.message : String(error)}`
      ));
    }
  }

  return {
    status: warnings.length > 0 ? 'partial' : 'ok',
    message: `Restored ${restored.restoredCount} local feature change${
      restored.restoredCount === 1 ? '' : 's'
    } across ${restored.restoredContainerCount} storage container${
      restored.restoredContainerCount === 1 ? '' : 's'
    }${settings.reloadAfterProbe ? ' and reloaded once' : ''}.`,
    warnings: warnings.length > 0 ? warnings : undefined,
    data: {
      probeId: probe.probeId,
      restoredCount: restored.restoredCount,
      restoredContainerCount: restored.restoredContainerCount,
      origin,
      reloadTriggered: settings.reloadAfterProbe
    }
  };
}

type StorageFeatureStateResult =
  | {
      ok: true;
      changed: boolean;
      hadOriginalValue: boolean;
      originalValue?: string;
      previousCandidateValue: JsonValue;
    }
  | {
      ok: false;
      code: 'ORIGIN_CHANGED' | 'STALE_VALUE' | 'UNSAFE_PATH' | 'UNAVAILABLE';
      error: string;
    };

type StorageFeatureRestoreResult =
  | {
      ok: true;
      restoredCount: number;
      restoredContainerCount: number;
    }
  | {
      ok: false;
      error: string;
    };

async function captureToggleDomSnapshot(
  tabId: number,
  expectedOrigin: string
): Promise<LatentFeatureDomSnapshot> {
  const [execution] = await chrome.scripting.executeScript({
    target: {
      tabId,
      allFrames: false
    },
    world: 'MAIN',
    func: captureLatentFeatureDomSignatures,
    args: [
      {
        expectedOrigin,
        maxElements: MAX_TOGGLE_DOM_SIGNATURES
      }
    ]
  });
  if (!execution?.result) {
    throw new Error('the page returned no DOM signature result');
  }
  return execution.result;
}

async function highlightToggleDomDiff(
  tabId: number,
  expectedOrigin: string,
  diff: LatentFeatureDomDiff
): Promise<{ highlightedCount: number; missedCount: number }> {
  const [execution] = await chrome.scripting.executeScript({
    target: {
      tabId,
      allFrames: false
    },
    world: 'MAIN',
    func: highlightLatentFeatureDomChanges,
    args: [
      {
        expectedOrigin,
        added: diff.added,
        changed: diff.changed,
        removed: diff.removed,
        durationMs: TOGGLE_HIGHLIGHT_DURATION_MS
      }
    ]
  });
  if (!execution?.result) {
    throw new Error('the page returned no highlight result');
  }
  return execution.result;
}

async function restoreSinglePreWriteValue(
  tabId: number,
  expectedOrigin: string,
  candidate: LatentFeatureCandidate,
  applied: Extract<StorageFeatureStateResult, { ok: true }>
): Promise<StorageFeatureRestoreResult> {
  if (!candidate.storageLocation) {
    return { ok: false, error: 'the storage location was unavailable during rollback' };
  }
  try {
    const rollbackChange: LatentFeatureProbeChange = {
      candidateId: candidate.id,
      key: candidate.key,
      area: candidate.storageLocation.area,
      storageKey: candidate.storageLocation.storageKey,
      jsonPath: candidate.storageLocation.jsonPath,
      hadOriginalValue: applied.hadOriginalValue,
      originalValue: applied.originalValue,
      originalCandidateValue: applied.previousCandidateValue,
      appliedValue: candidate.currentValue ?? null
    };
    const [execution] = await chrome.scripting.executeScript({
      target: {
        tabId,
        allFrames: false
      },
      world: 'MAIN',
      func: restoreStorageFeatureProbe,
      args: [
        {
          expectedOrigin,
          changes: [rollbackChange]
        }
      ]
    });
    return (
      (execution?.result as StorageFeatureRestoreResult | undefined) ?? {
        ok: false,
        error: 'the page returned no rollback result'
      }
    );
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

function replaceProbeChange(
  existing: LatentFeatureProbeChange[],
  replacement: LatentFeatureProbeChange
): LatentFeatureProbeChange[] {
  const output: LatentFeatureProbeChange[] = [];
  let replaced = false;
  for (const change of existing) {
    if (change.candidateId !== replacement.candidateId) {
      output.push(change);
    } else if (!replaced) {
      output.push(replacement);
      replaced = true;
    }
  }
  if (!replaced) output.push(replacement);
  return output;
}

function sameStorageContainer(
  left: Pick<LatentFeatureProbeChange, 'area' | 'storageKey'>,
  right: Pick<LatentFeatureProbeChange, 'area' | 'storageKey'>
): boolean {
  return left.area === right.area && left.storageKey === right.storageKey;
}

function sameStorageLocation(
  left: Pick<LatentFeatureProbeChange, 'area' | 'storageKey' | 'jsonPath'>,
  right: Pick<LatentFeatureProbeChange, 'area' | 'storageKey' | 'jsonPath'>
): boolean {
  return (
    sameStorageContainer(left, right) &&
    left.jsonPath.length === right.jsonPath.length &&
    left.jsonPath.every((segment, index) => segment === right.jsonPath[index])
  );
}

function toggleWarning(message: string): ExportWarning {
  return {
    code: 'LATENT_FEATURE_TOGGLE_OBSERVATION_GAP',
    message: sanitizePersistedText(message),
    collectorId: 'latent-features',
    severity: 'warning'
  };
}

function formatStorageToggleCode(
  candidate: LatentFeatureCandidate,
  value: JsonValue
): string {
  const location = candidate.storageLocation;
  if (!location) return `// effective browser-storage value\n${serializeToggleValue(value)}`;
  const area = location.area;
  const key = JSON.stringify(location.storageKey);
  if (location.format === 'direct') {
    const storedValue = typeof value === 'string' ? value : String(value);
    return `// effective browser-storage control (shipped source is unchanged)\n${area}.setItem(${key}, ${JSON.stringify(storedValue)});`.slice(0, 2_000);
  }
  const path = location.jsonPath.map((segment) => `[${JSON.stringify(segment)}]`).join('');
  return `// effective browser-storage control (shipped source is unchanged)\nJSON.parse(${area}.getItem(${key}))${path} = ${serializeToggleValue(value)};`.slice(0, 2_000);
}

function serializeToggleValue(value: JsonValue): string {
  try {
    return (JSON.stringify(value) ?? 'null').slice(0, 500);
  } catch {
    return 'null';
  }
}

async function collectPageSignals(tabId: number): Promise<LatentFeaturePageSignals> {
  const [result] = await chrome.scripting.executeScript({
    target: {
      tabId,
      allFrames: false
    },
    world: 'MAIN',
    func: collectLatentFeaturePageSignals
  });
  if (!result?.result) {
    throw new Error('The target page did not return latent feature signals.');
  }
  return result.result as LatentFeaturePageSignals;
}

async function collectRuntimeInstrumentation(
  tabId: number
): Promise<ContentInstrumentationResponse | undefined> {
  try {
    return (await chrome.tabs.sendMessage(
      tabId,
      {
        channel: CONTENT_MESSAGE_CHANNEL,
        type: 'content/getInstrumentationSnapshot'
      },
      {
        frameId: 0
      }
    )) as ContentInstrumentationResponse;
  } catch {
    return undefined;
  }
}

function collectRuntimeObservedCandidates(
  response: ContentInstrumentationResponse | undefined
): RuntimeObservedFeatureCandidate[] {
  if (response?.integrity !== 'extension-verified') {
    return [];
  }
  const observed: RuntimeObservedFeatureCandidate[] = [];
  for (const event of response?.snapshot?.events ?? []) {
    if (event.type !== 'feature-candidates-observed') {
      continue;
    }
    const sourceUrl =
      typeof event.attributes.responseUrl === 'string'
        ? event.attributes.responseUrl
        : event.url;
    const values = Array.isArray(event.attributes.candidates)
      ? event.attributes.candidates
      : [];
    for (const value of values) {
      if (!isRecord(value) || typeof value.key !== 'string') {
        continue;
      }
      observed.push({
        key: value.key,
        currentValue: isJsonValue(value.currentValue) ? value.currentValue : undefined,
        suggestedValue: isJsonValue(value.suggestedValue)
          ? value.suggestedValue
          : undefined,
        confidence:
          value.confidence === 'high' || value.confidence === 'low'
            ? value.confidence
            : 'medium',
        sourceUrl,
        detail:
          typeof value.detail === 'string'
            ? value.detail
            : 'Flag-shaped value observed in a response already delivered to the page.'
      });
      if (observed.length >= 300) {
        return observed;
      }
    }
  }
  return observed;
}

async function analyzeDeliveredScripts(input: {
  sources: LatentFeatureTextSource[];
  pageUrl: string;
  pageOrigin: string;
  instrumentation: ContentInstrumentationResponse | undefined;
  evaluateTrafficScope: ModuleHostServices['evaluateTrafficScope'];
}): Promise<ScriptPurposeAnalysisResult[]> {
  const acquiredAt = new Date().toISOString();
  const deliveryCounts = new Map<string, number>();
  const deliveredSources = input.sources.map((source) => {
    const locator = [source.sourceKind, source.label, source.sourceUrl ?? ''].join('\n');
    const deliveryIndex = deliveryCounts.get(locator) ?? 0;
    deliveryCounts.set(locator, deliveryIndex + 1);
    return { source, deliveryIndex };
  });
  const assessments = await Promise.all(
    deliveredSources.map(async ({ source, deliveryIndex }) => {
      const sourceUrl = source.sourceUrl ?? input.pageUrl;
      const scopeDecision = input.evaluateTrafficScope(sourceUrl, 'GET');
      const sourceInput: ScriptPurposeSourceInput = {
        sourceKind:
          source.sourceKind === 'bundle'
            ? 'external'
            : source.sourceKind === 'document'
              ? 'document'
              : 'inline',
        label: source.label,
        sourceUrl,
        finalUrl: source.sourceKind === 'bundle' ? sourceUrl : undefined,
        text: source.text,
        contentType: source.contentType,
        sha256: await sha256Text(source.text),
        declaredByteLength: new TextEncoder().encode(source.text).byteLength,
        acquiredAt,
        truncated: source.truncated === true,
        deliveryIndex
      };
      const runtimeObservations = buildRuntimeObservationsForSource(
        input.instrumentation,
        sourceInput,
        input.pageUrl,
        input.pageOrigin
      );
      return analyzeScriptPurpose(sourceInput, {
        scope: {
          disposition: scopeDecision.disposition,
          // Origin equality is evidence of target delivery. A different origin alone does not
          // establish corporate ownership, delegation, or a third-party relationship.
          ownership: sourceOrigin(sourceUrl) === input.pageOrigin ? 'target' : 'unknown',
          policyId: scopeDecision.policyId,
          policyVersion: scopeDecision.policyVersion,
          matchedRuleIds: scopeDecision.matchedRuleIds
        },
        runtimeObservations
      });
    })
  );

  return assessments.sort((left, right) => {
    const priority = right.reviewPriority.score - left.reviewPriority.score;
    if (priority !== 0) return priority;
    return left.artifact.label.localeCompare(right.artifact.label);
  });
}

function buildRuntimeObservationsForSource(
  instrumentation: ContentInstrumentationResponse | undefined,
  source: ScriptPurposeSourceInput,
  pageUrl: string,
  pageOrigin: string
): ScriptRuntimeObservationInput[] {
  if (instrumentation?.integrity !== 'extension-verified') {
    return [];
  }
  const observations: ScriptRuntimeObservationInput[] = [];
  for (const event of instrumentation?.snapshot?.events ?? []) {
    if (!runtimeEventMatchesSource(event, source, pageUrl)) {
      continue;
    }
    const targetUrl = typeof event.url === 'string' ? event.url : undefined;
    const method =
      typeof event.attributes.method === 'string'
        ? event.attributes.method.toUpperCase().slice(0, 16)
        : undefined;
    const add = (
      axis: ScriptBehaviorAxis,
      detail: string,
      purposeHints?: ScriptPurposeCategory[]
    ) => {
      observations.push({
        axis,
        detail,
        targetUrl,
        method,
        // One browser event can support several axes. Give each claim a distinct evidence
        // signature so the rubric does not collapse the later details into the first record.
        evidenceId: `${event.id}:${axis}`,
        purposeHints
      });
    };

    switch (event.type) {
      case 'network-request':
        add('network', `${event.attributes.transport ?? 'browser'} ${method ?? 'GET'} request observed.`, ['api-data']);
        if (method && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
          add('server-state-change', `${method} request observed during page startup.`, ['api-data']);
        }
        if (targetUrl && sourceOrigin(targetUrl) && sourceOrigin(targetUrl) !== pageOrigin) {
          add('cross-origin-transfer', 'A request crossed the current page origin boundary.', [
            'third-party-integration'
          ]);
        }
        break;
      case 'beacon-sent':
        add('network', 'A browser beacon send was observed.', ['telemetry-analytics']);
        if (targetUrl && sourceOrigin(targetUrl) && sourceOrigin(targetUrl) !== pageOrigin) {
          add('cross-origin-transfer', 'A beacon crossed the current page origin boundary.', [
            'telemetry-analytics',
            'third-party-integration'
          ]);
        }
        break;
      case 'storage-write':
        add('client-storage', `A ${String(event.attributes.operation ?? 'storage')} operation was observed.`, [
          'storage-offline'
        ]);
        break;
      case 'route-change':
        add('dom-ui', 'A client-side history route change was observed.', ['app-shell-ui']);
        break;
      case 'worker-constructed':
      case 'shared-worker-constructed':
      case 'websocket-constructed':
      case 'eventsource-constructed':
        add('persistence-background-realtime', `${event.type} was observed.`, [
          'realtime-messaging'
        ]);
        break;
      case 'script-added':
        add('dynamic-code-loading', 'A script element was added at runtime.', ['loader-runtime']);
        break;
      case 'feature-candidates-observed':
        add('latent-debug-admin', 'Feature-shaped delivered configuration was observed.', [
          'feature-configuration'
        ]);
        break;
      default:
        break;
    }
    if (observations.length >= 80) break;
  }
  return observations;
}

function runtimeEventMatchesSource(
  event: NonNullable<ContentInstrumentationResponse['snapshot']>['events'][number],
  source: ScriptPurposeSourceInput,
  _pageUrl: string
): boolean {
  // A page URL in a stack does not identify which inline script initiated an action, and a raw
  // JavaScript document is collected as text rather than executed. Keep those events at page level.
  if (source.sourceKind !== 'external') {
    return false;
  }
  const initiator =
    typeof event.attributes.initiator === 'string' ? event.attributes.initiator : undefined;
  if (!initiator) {
    return false;
  }
  const expected = source.finalUrl ?? source.sourceUrl;
  return Boolean(expected && comparableUrl(initiator) === comparableUrl(expected));
}

function comparableUrl(rawUrl: string): string | undefined {
  try {
    const url = new URL(rawUrl);
    return `${url.origin}${url.pathname}`;
  } catch {
    return undefined;
  }
}

function sanitizeRecordedUrl(rawUrl: string): string | undefined {
  try {
    const url = new URL(rawUrl);
    if (!['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol)) {
      return `${url.protocol}[value omitted]`;
    }
    url.username = '';
    url.password = '';
    url.hash = '';
    url.pathname = url.pathname
      .split('/')
      .map((segment) =>
        /^(?:\d{7,}|[a-f\d]{16,}|[A-Za-z0-9_-]{32,}|[a-f\d]{8}-[a-f\d-]{27,})$/i.test(
          decodeUrlSegment(segment)
        )
          ? ':id'
          : segment
      )
      .join('/');
    const queryNames = [...new Set([...url.searchParams.keys()])]
      .map((name) => name.replace(/[^A-Za-z0-9_.:-]/g, '').slice(0, 80))
      .filter(Boolean)
      .sort()
      .slice(0, 32);
    url.search = '';
    for (const name of queryNames) {
      url.searchParams.append(name, '');
    }
    return url.toString().slice(0, 2048);
  } catch {
    return undefined;
  }
}

function decodeUrlSegment(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function sanitizePersistedText(value: string): string {
  return value
    .replace(/https?:\/\/[^\s"'<>]+/gi, (match) => sanitizeRecordedUrl(match) ?? '[URL omitted]')
    .replace(/\b((?:access|auth|id|refresh|session)[_-]?token|api[_-]?key|signature)=([^\s&]+)/gi, '$1=[value omitted]')
    .slice(0, 1000);
}

function sourceOrigin(rawUrl: string): string | undefined {
  try {
    return new URL(rawUrl).origin;
  } catch {
    return undefined;
  }
}

function trafficEntryUrl(entry: TrafficLedgerEntryV1): string | undefined {
  const endpoint = entry.endpoint;
  const defaultPort =
    (endpoint.scheme === 'http' || endpoint.scheme === 'ws') ? 80 : 443;
  const port = endpoint.port === defaultPort ? '' : `:${endpoint.port}`;
  const query = endpoint.queryParameterNames.length
    ? `?${endpoint.queryParameterNames.map((name) => `${encodeURIComponent(name)}=`).join('&')}`
    : '';
  return sanitizeRecordedUrl(
    `${endpoint.scheme}://${endpoint.host}${port}${endpoint.pathTemplate}${query}`
  );
}

async function sha256Text(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)]
    .map((value) => value.toString(16).padStart(2, '0'))
    .join('');
}

function buildJavascriptFullTest(input: {
  sessionStartedAt: string;
  scanId: string;
  tabId: number;
  pageUrl: string;
  origin: string;
  scopeDecision: ReturnType<ModuleHostServices['evaluateTrafficScope']>;
  scriptAssessments: ScriptPurposeAnalysisResult[];
  instrumentation: ContentInstrumentationResponse | undefined;
  trafficEntries: TrafficLedgerEntryV1[];
  scanWarnings: string[];
}): JavascriptFullTestRun {
  const allEvents = input.instrumentation?.snapshot?.events ?? [];
  const trustedTrafficEntries = input.trafficEntries.filter((entry) =>
    entry.observation.sources.some((source) => source !== 'chromium-instrumentation')
  );
  const retainedTrafficEntries = trustedTrafficEntries.slice(0, 50);
  const trafficEvidence = retainedTrafficEntries.map((entry) => ({
    evidenceId: `traffic-${entry.entryId}`,
    type: 'traffic-ledger-entry' as const,
    observedAt: entry.observation.lastSeen,
    url: trafficEntryUrl(entry),
    attributes: {
      entryId: entry.entryId,
      method: entry.endpoint.method,
      scheme: entry.endpoint.scheme,
      host: entry.endpoint.host,
      port: entry.endpoint.port,
      pathTemplate: entry.endpoint.pathTemplate,
      queryParameterNames: entry.endpoint.queryParameterNames,
      scopeDisposition: entry.scope.disposition,
      scopePolicyId: entry.scope.policyId,
      scopePolicyVersion: entry.scope.policyVersion,
      observationSources: entry.observation.sources,
      boundary: entry.classification.boundary
    }
  }));
  const events = allEvents.slice(0, Math.max(0, 200 - trafficEvidence.length));
  const count = (...types: Array<(typeof events)[number]['type']>) =>
    events.filter((event) => types.includes(event.type)).length;
  const runtimeStats = {
    eventCount: events.length,
    lifecycleCount: count('lifecycle'),
    trafficEntryCount: trustedTrafficEntries.length,
    networkRequestCount: count('network-request', 'beacon-sent'),
    domMutationCount: count('dom-mutation'),
    storageWriteCount: count('storage-write'),
    routeChangeCount: count('route-change'),
    workerCount: count('worker-constructed', 'shared-worker-constructed'),
    realtimeCount: count('websocket-constructed', 'eventsource-constructed'),
    runtimeErrorCount: count('runtime-error', 'unhandled-rejection')
  };
  const allArtifactIds = input.scriptAssessments.map(
    (assessment) => assessment.artifact.artifactId
  );
  const artifactFingerprints = input.scriptAssessments
    .map(createScriptArtifactFingerprint)
    .filter((value): value is string => Boolean(value));
  const cells: JavascriptTestCell[] = [];
  const addCell = (cell: JavascriptTestCell) => cells.push(cell);
  addCell({
    testId: 'source-acquisition',
    stage: 'static',
    title: 'Bounded source acquisition',
    status: input.scriptAssessments.length > 0 ? 'passed' : 'failed',
    detail:
      input.scriptAssessments.length > 0
        ? `${input.scriptAssessments.length} delivered source body${input.scriptAssessments.length === 1 ? '' : 'ies'} hashed and assessed.`
        : 'No JavaScript source body was available within scope and collection caps.',
    evidenceRefs: [],
    artifactIds: allArtifactIds
  });
  addCell({
    testId: 'instrumentation',
    stage: 'instrumented',
    title: 'Document-start instrumentation',
    status: input.instrumentation?.instrumented ? 'passed' : 'blocked',
    detail: input.instrumentation?.instrumented
      ? `${events.length} bounded page-world event${events.length === 1 ? '' : 's'} retained from the startup reload (${input.instrumentation.integrity}).`
      : 'The content bridge did not confirm document-start instrumentation.',
    evidenceRefs: events.slice(0, 20).map((event) => event.id),
    artifactIds: []
  });
  addCell({
    testId: 'traffic-window',
    stage: 'instrumented',
    title: 'Startup traffic window',
    status:
      trustedTrafficEntries.length > 0
        ? 'observed'
        : runtimeStats.networkRequestCount > 0
          ? input.instrumentation?.integrity === 'extension-verified'
            ? 'observed'
            : 'observed-unverified'
          : 'not-observed',
    detail: `${trustedTrafficEntries.length} independently extension-recorded sanitized traffic shape${trustedTrafficEntries.length === 1 ? '' : 's'} and ${runtimeStats.networkRequestCount} page-world fetch/XHR/beacon event${runtimeStats.networkRequestCount === 1 ? '' : 's'} retained.`,
    evidenceRefs:
      trafficEvidence.length > 0
        ? trafficEvidence.slice(0, 20).map((entry) => entry.evidenceId)
        : events
            .filter((event) => event.type === 'network-request' || event.type === 'beacon-sent')
            .slice(0, 20)
            .map((event) => event.id),
    artifactIds: []
  });

  const axisEvents: Record<ScriptBehaviorAxis, string[]> = {
    network: ['network-request', 'beacon-sent'],
    'dom-ui': ['dom-mutation', 'route-change'],
    'data-handling': [],
    'identity-session-authorization': [],
    'server-state-change': ['network-request'],
    'client-storage': ['storage-write'],
    'dynamic-code-loading': ['script-added', 'worker-constructed', 'shared-worker-constructed'],
    'persistence-background-realtime': [
      'worker-constructed',
      'shared-worker-constructed',
      'websocket-constructed',
      'eventsource-constructed'
    ],
    'cross-origin-transfer': ['network-request', 'beacon-sent'],
    'latent-debug-admin': ['feature-candidates-observed']
  };
  for (const axis of Object.keys(axisEvents) as ScriptBehaviorAxis[]) {
    const staticArtifacts = artifactIdsForAxis(input.scriptAssessments, axis);
    const matchingEvents = events.filter((event) => {
      if (!axisEvents[axis].includes(event.type)) return false;
      if (axis === 'server-state-change') {
        const method = typeof event.attributes.method === 'string'
          ? event.attributes.method.toUpperCase()
          : 'GET';
        return !['GET', 'HEAD', 'OPTIONS'].includes(method);
      }
      if (axis === 'cross-origin-transfer') {
        return Boolean(event.url && sourceOrigin(event.url) && sourceOrigin(event.url) !== input.origin);
      }
      return true;
    });
    const matchingTrafficEvidence = trafficEvidence.filter((entry) => {
      const attributes = entry.attributes;
      if (axis === 'network') return true;
      if (axis === 'server-state-change') {
        const method = typeof attributes.method === 'string' ? attributes.method : 'GET';
        return !['GET', 'HEAD', 'OPTIONS'].includes(method);
      }
      if (axis === 'cross-origin-transfer') {
        return attributes.boundary !== 'same-origin' && attributes.boundary !== 'unknown';
      }
      return false;
    });
    const hasVerifiedPageEvents =
      matchingEvents.length > 0 && input.instrumentation?.integrity === 'extension-verified';
    const hasUnverifiedPageEvents =
      matchingEvents.length > 0 && input.instrumentation?.integrity !== 'extension-verified';
    const attributableArtifactIds = artifactIdsAttributedToEvents(
      input.scriptAssessments,
      hasVerifiedPageEvents ? matchingEvents : []
    );
    addCell({
      testId: `behavior-${axis}`,
      stage: 'instrumented',
      title: behaviorAxisTitle(axis),
      status:
        matchingTrafficEvidence.length > 0 || hasVerifiedPageEvents
          ? 'observed'
          : hasUnverifiedPageEvents
            ? 'observed-unverified'
          : staticArtifacts.length > 0
            ? 'static-only'
            : 'not-observed',
      detail:
        matchingTrafficEvidence.length > 0
          ? `${matchingTrafficEvidence.length} extension-recorded traffic shape${matchingTrafficEvidence.length === 1 ? '' : 's'} supported this page-level behavior during the bounded startup path.`
          : hasVerifiedPageEvents
            ? `${matchingEvents.length} verified runtime event${matchingEvents.length === 1 ? '' : 's'} observed during the bounded startup path.`
            : hasUnverifiedPageEvents
              ? `${matchingEvents.length} page-world event${matchingEvents.length === 1 ? '' : 's'} reported this behavior; same-window transport integrity is unverified.`
          : staticArtifacts.length > 0
            ? `Static evidence appears in ${staticArtifacts.length} artifact${staticArtifacts.length === 1 ? '' : 's'}; no attributable runtime event was retained.`
            : 'No supporting evidence was retained in this run. This is not evidence of absence.',
      evidenceRefs:
        matchingTrafficEvidence.length > 0
          ? matchingTrafficEvidence.slice(0, 20).map((entry) => entry.evidenceId)
          : matchingEvents.slice(0, 20).map((event) => event.id),
      artifactIds:
        matchingTrafficEvidence.length > 0 || matchingEvents.length > 0
          ? attributableArtifactIds
          : staticArtifacts
    });
  }
  const errorEvents = events.filter(
    (event) => event.type === 'runtime-error' || event.type === 'unhandled-rejection'
  );
  addCell({
    testId: 'runtime-errors',
    stage: 'instrumented',
    title: 'Runtime errors and rejected promises',
    status:
      errorEvents.length > 0
        ? input.instrumentation?.integrity === 'extension-verified'
          ? 'observed'
          : 'observed-unverified'
        : 'not-observed',
    detail:
      errorEvents.length > 0
        ? `${errorEvents.length} bounded runtime error event${errorEvents.length === 1 ? '' : 's'} retained for review.`
        : 'No window error or unhandled rejection was retained during this startup path.',
    evidenceRefs: errorEvents.slice(0, 20).map((event) => event.id),
    artifactIds: []
  });
  addCell({
    testId: 'isolated-standalone-execution',
    stage: 'active',
    title: 'Isolated standalone execution',
    status: 'blocked',
    detail: 'Acquired code was not executed inside the extension. A separate disposable browser or VM with outbound traffic blocked is required for this stage.',
    evidenceRefs: [],
    artifactIds: allArtifactIds
  });
  addCell({
    testId: 'interactive-workflows',
    stage: 'active',
    title: 'Interactive and transaction paths',
    status: 'manual-required',
    detail: 'The bounded startup observation does not click controls, submit forms, replay transactions, or cross authorization boundaries.',
    evidenceRefs: [],
    artifactIds: allArtifactIds
  });

  const gaps = [
    ...input.scanWarnings,
    ...input.instrumentation?.warnings ?? [],
    ...input.instrumentation?.snapshot?.warnings ?? [],
    ...(allEvents.length > events.length
      ? [`${allEvents.length - events.length} runtime event${allEvents.length - events.length === 1 ? '' : 's'} exceeded the persisted evidence cap.`]
      : []),
    ...(input.trafficEntries.length > retainedTrafficEntries.length
      ? [`${input.trafficEntries.length - retainedTrafficEntries.length} traffic ledger entr${input.trafficEntries.length - retainedTrafficEntries.length === 1 ? 'y lacked an independent retained evidence record or exceeded' : 'ies lacked independent retained evidence records or exceeded'} the persisted test-evidence cap.`]
      : []),
    ...input.scriptAssessments.flatMap((assessment) =>
      assessment.coverage.gaps
        .filter((gap) => gap.material)
        .map((gap) => `${assessment.artifact.label}: ${gap.detail}`)
    ),
    'Only the startup path reached by one reload was observed; interaction, account, entitlement, timing, and backend-dependent branches remain outside this run.'
  ];
  const uniqueGaps = [...new Set(gaps)].slice(0, 100);
  const hasFailure = cells.some((cell) => cell.status === 'failed');
  const hasIncomplete = cells.some(
    (cell) =>
      cell.status === 'blocked' ||
      cell.status === 'manual-required' ||
      cell.status === 'observed-unverified'
  );
  return {
    testRunId: createId('javascript-test'),
    scanId: input.scanId,
    rubricVersion: SCRIPT_PURPOSE_RUBRIC_VERSION,
    startedAt: input.sessionStartedAt,
    completedAt: new Date().toISOString(),
    tabId: input.tabId,
    pageUrl: sanitizeRecordedUrl(input.pageUrl) ?? input.origin,
    origin: input.origin,
    scopeDisposition: input.scopeDecision.disposition,
    scopePolicyId: input.scopeDecision.policyId,
    scopePolicyVersion: input.scopeDecision.policyVersion,
    reloadTriggered: true,
    instrumentationAvailable: input.instrumentation?.instrumented === true,
    instrumentationIntegrity: input.instrumentation?.integrity ?? 'none',
    overallStatus: hasFailure ? 'failed' : hasIncomplete || uniqueGaps.length > 0 ? 'partial' : 'complete',
    artifactIds: allArtifactIds,
    artifactFingerprints,
    evidence: [
      ...trafficEvidence,
      ...events.map((event) => ({
        evidenceId: event.id,
        type: event.type,
        observedAt: event.observedAt,
        url: event.url ? sanitizeRecordedUrl(event.url) : undefined,
        attributes: event.attributes
      }))
    ],
    cells,
    runtimeStats,
    gaps: uniqueGaps
  };
}

function buildFailedJavascriptFullTest(input: {
  sessionStartedAt: string;
  tabId: number;
  pageUrl: string;
  origin: string;
  scopeDecision: ReturnType<ModuleHostServices['evaluateTrafficScope']>;
  failureMessage: string;
}): JavascriptFullTestRun {
  return {
    testRunId: createId('javascript-test'),
    scanId: createId('javascript-attempt'),
    rubricVersion: SCRIPT_PURPOSE_RUBRIC_VERSION,
    startedAt: input.sessionStartedAt,
    completedAt: new Date().toISOString(),
    tabId: input.tabId,
    pageUrl: sanitizeRecordedUrl(input.pageUrl) ?? input.origin,
    origin: input.origin,
    scopeDisposition: input.scopeDecision.disposition,
    scopePolicyId: input.scopeDecision.policyId,
    scopePolicyVersion: input.scopeDecision.policyVersion,
    reloadTriggered: true,
    instrumentationAvailable: false,
    instrumentationIntegrity: 'none',
    overallStatus: 'failed',
    artifactIds: [],
    artifactFingerprints: [],
    evidence: [],
    cells: [
      {
        testId: 'startup-observation-run',
        stage: 'instrumented',
        title: 'Instrumented reload and collection',
        status: 'failed',
        detail: sanitizePersistedText(input.failureMessage),
        evidenceRefs: [],
        artifactIds: []
      }
    ],
    runtimeStats: {
      eventCount: 0,
      lifecycleCount: 0,
      trafficEntryCount: 0,
      networkRequestCount: 0,
      domMutationCount: 0,
      storageWriteCount: 0,
      routeChangeCount: 0,
      workerCount: 0,
      realtimeCount: 0,
      runtimeErrorCount: 0
    },
    gaps: [sanitizePersistedText(input.failureMessage)]
  };
}

function artifactIdsForAxis(
  assessments: ScriptPurposeAnalysisResult[],
  axis: ScriptBehaviorAxis
): string[] {
  return assessments
    .filter((assessment) =>
      assessment.behaviorClaims.some((claim) => claim.axis === axis && claim.maturity > 0)
    )
    .map((assessment) => assessment.artifact.artifactId);
}

function artifactIdsAttributedToEvents(
  assessments: ScriptPurposeAnalysisResult[],
  events: NonNullable<ContentInstrumentationResponse['snapshot']>['events']
): string[] {
  const initiators = new Set(
    events
      .map((event) =>
        typeof event.attributes.initiator === 'string'
          ? comparableUrl(event.attributes.initiator)
          : undefined
      )
      .filter((value): value is string => Boolean(value))
  );
  return assessments
    .filter((assessment) => {
      if (assessment.artifact.sourceKind !== 'external') return false;
      const sourceUrl = assessment.artifact.finalUrl ?? assessment.artifact.sourceUrl;
      const comparable = sourceUrl ? comparableUrl(sourceUrl) : undefined;
      return Boolean(comparable && initiators.has(comparable));
    })
    .map((assessment) => assessment.artifact.artifactId);
}

function behaviorAxisTitle(axis: ScriptBehaviorAxis): string {
  const titles: Record<ScriptBehaviorAxis, string> = {
    network: 'Network behavior',
    'dom-ui': 'DOM and interface behavior',
    'data-handling': 'Data handling',
    'identity-session-authorization': 'Identity, session, and authorization',
    'server-state-change': 'Server-side state change',
    'client-storage': 'Client storage',
    'dynamic-code-loading': 'Dynamic code loading',
    'persistence-background-realtime': 'Background and realtime behavior',
    'cross-origin-transfer': 'Cross-origin transfer',
    'latent-debug-admin': 'Latent, debug, and administration controls'
  };
  return titles[axis];
}

async function readLoadedLibraries(
  pageSignals: LatentFeaturePageSignals,
  settings: LatentFeatureSettings,
  evaluateTrafficScope: ModuleHostServices['evaluateTrafficScope']
): Promise<LoadedLibraryReadResult> {
  const pageOrigin = pageSignals.origin;
  const sources: LatentFeatureTextSource[] = [];
  const warnings: string[] = [];
  const urls: string[] = [];
  const seenUrls = new Set<string>();
  for (const rawUrl of pageSignals.loadedScriptUrls) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(rawUrl, pageSignals.pageUrl);
    } catch {
      continue;
    }
    if (!/^https?:$/.test(parsedUrl.protocol) || seenUrls.has(parsedUrl.href)) {
      continue;
    }
    seenUrls.add(parsedUrl.href);

    const scopeDecision = evaluateTrafficScope(parsedUrl.href, 'GET');
    if (scopeDecision.disposition !== 'in-scope') {
      warnings.push(
        `Retained loaded library metadata without automatic read for ${parsedUrl.href}: ${scopeDecision.disposition} under scope policy ${scopeDecision.policyId}.`
      );
      continue;
    }
    if (!settings.includeThirdPartyLibraries && parsedUrl.origin !== pageOrigin) {
      warnings.push(
        `Retained loaded library metadata without automatic read for ${parsedUrl.href}: third-party library reads are disabled.`
      );
      continue;
    }
    if (urls.length < settings.maxLibrariesPerScan) {
      urls.push(parsedUrl.href);
    }
  }

  let cursor = 0;
  let readCount = 0;
  let failureCount = 0;
  let bytesRead = 0;
  let remainingBudget = settings.maxTotalLibraryBytes;
  let nextStartAt = 0;

  const takeJob = () => {
    if (cursor >= urls.length || remainingBudget <= 0) {
      return undefined;
    }
    const url = urls[cursor];
    if (!url) {
      return undefined;
    }
    cursor += 1;
    const byteAllowance = Math.min(settings.maxLibraryBytes, remainingBudget);
    remainingBudget -= byteAllowance;
    const scheduledAt = Math.max(Date.now(), nextStartAt);
    nextStartAt = scheduledAt + settings.libraryDelayMs;
    return {
      url,
      byteAllowance,
      waitMs: Math.max(0, scheduledAt - Date.now())
    };
  };

  const worker = async () => {
    while (true) {
      const job = takeJob();
      if (!job) {
        return;
      }
      if (job.waitMs > 0) {
        await delay(job.waitMs);
      }

      try {
        const result = await readLoadedLibrary(
          job.url,
          job.byteAllowance,
          evaluateTrafficScope
        );
        remainingBudget += Math.max(0, job.byteAllowance - result.bytesRead);
        bytesRead += result.bytesRead;
        if (!result.text) {
          failureCount += 1;
          warnings.push(result.warning ?? `No analyzable source returned for ${job.url}`);
          continue;
        }
        readCount += 1;
        const sourceUrl = result.finalUrl ?? job.url;
        sources.push({
          sourceKind: 'bundle',
          label: libraryLabel(sourceUrl),
          sourceUrl: sanitizeRecordedUrl(sourceUrl),
          contentType: result.contentType,
          truncated: result.truncated,
          text: result.text
        });
        if (result.warning) {
          warnings.push(result.warning);
        }
      } catch (error) {
        remainingBudget += job.byteAllowance;
        failureCount += 1;
        warnings.push(
          `Loaded library read failed for ${job.url}: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
    }
  };

  await Promise.all(
    Array.from({ length: Math.min(settings.libraryThreadCount, urls.length) }, () => worker())
  );

  return {
    sources,
    loadedCount: pageSignals.loadedScriptUrls.length,
    readCount,
    failureCount,
    bytesRead,
    warnings: warnings.slice(0, 30)
  };
}

async function fetchLibraryWithinScope(
  initialUrl: string,
  evaluateTrafficScope: ModuleHostServices['evaluateTrafficScope'],
  signal: AbortSignal
): Promise<ScopedLibraryFetchResult> {
  const visited = new Set<string>();
  let currentUrl = initialUrl;

  for (let redirectCount = 0; redirectCount <= MAX_SCOPED_REDIRECT_HOPS; redirectCount += 1) {
    if (visited.has(currentUrl)) {
      return {
        ok: false,
        blockedUrl: currentUrl,
        reason: `Skipped loaded library ${initialUrl}: redirect loop detected at ${currentUrl}.`
      };
    }
    visited.add(currentUrl);

    const scopeDecision = evaluateTrafficScope(currentUrl, 'GET');
    if (scopeDecision.disposition !== 'in-scope') {
      return {
        ok: false,
        blockedUrl: currentUrl,
        reason: `Skipped loaded library ${initialUrl} before ${currentUrl}: ${scopeDecision.disposition} under scope policy ${scopeDecision.policyId}.`
      };
    }

    const response = await fetch(currentUrl, {
      cache: 'force-cache',
      credentials: 'omit',
      redirect: 'manual',
      signal
    });
    if (response.type === 'opaqueredirect') {
      return {
        ok: false,
        blockedUrl: currentUrl,
        reason: `Skipped loaded library ${initialUrl}: redirect from ${currentUrl} was opaque and could not be scope-checked.`
      };
    }
    if (!REDIRECT_STATUS_CODES.has(response.status)) {
      return {
        ok: true,
        response,
        finalUrl: currentUrl
      };
    }

    const location = response.headers.get('location');
    if (response.body) {
      await response.body.cancel().catch(() => {});
    }
    if (!location) {
      return {
        ok: false,
        blockedUrl: currentUrl,
        reason: `Skipped loaded library ${initialUrl}: redirect from ${currentUrl} did not expose a destination for scope evaluation.`
      };
    }
    if (redirectCount === MAX_SCOPED_REDIRECT_HOPS) {
      return {
        ok: false,
        blockedUrl: currentUrl,
        reason: `Skipped loaded library ${initialUrl}: redirect chain exceeded ${MAX_SCOPED_REDIRECT_HOPS} hops.`
      };
    }

    currentUrl = new URL(location, currentUrl).toString();
  }

  return {
    ok: false,
    blockedUrl: currentUrl,
    reason: `Skipped loaded library ${initialUrl}: redirect chain could not be resolved.`
  };
}

async function readLoadedLibrary(
  url: string,
  byteLimit: number,
  evaluateTrafficScope: ModuleHostServices['evaluateTrafficScope']
): Promise<{
  text?: string;
  bytesRead: number;
  finalUrl?: string;
  contentType?: string;
  truncated?: boolean;
  warning?: string;
}> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const scopedFetch = await fetchLibraryWithinScope(url, evaluateTrafficScope, controller.signal);
    if (!scopedFetch.ok) {
      return {
        bytesRead: 0,
        finalUrl: scopedFetch.blockedUrl,
        warning: scopedFetch.reason
      };
    }

    const { response, finalUrl } = scopedFetch;
    if (!response.ok) {
      return {
        bytesRead: 0,
        finalUrl,
        warning: `Loaded library ${finalUrl} returned HTTP ${response.status}; no retry was attempted.`
      };
    }

    const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
    const looksLikeJavaScript =
      /javascript|ecmascript|text\/plain/.test(contentType) ||
      /\.(?:m?js)(?:$|[?#])/i.test(finalUrl);
    if (!looksLikeJavaScript) {
      return {
        bytesRead: 0,
        finalUrl,
        warning: `Skipped loaded resource ${finalUrl} because its response was not JavaScript.`
      };
    }

    const reader = response.body?.getReader();
    if (!reader) {
      return {
        bytesRead: 0,
        finalUrl,
        contentType,
        warning: `Skipped loaded library ${finalUrl} because its body was not available for bounded streaming.`
      };
    }

    const decoder = new TextDecoder();
    let text = '';
    let bytesRead = 0;
    let truncated = false;
    while (bytesRead < byteLimit) {
      const next = await reader.read();
      if (next.done) {
        break;
      }
      const chunk = next.value;
      const remaining = byteLimit - bytesRead;
      const accepted = chunk.byteLength > remaining ? chunk.slice(0, remaining) : chunk;
      bytesRead += accepted.byteLength;
      text += decoder.decode(accepted, {
        stream: true
      });
      if (accepted.byteLength < chunk.byteLength) {
        truncated = true;
        await reader.cancel();
        break;
      }
    }
    text += decoder.decode();
    if (bytesRead >= byteLimit) {
      truncated = true;
      await reader.cancel().catch(() => {});
    }

    return {
      text,
      bytesRead,
      finalUrl,
      contentType,
      truncated,
      warning: truncated
        ? `Stopped reading ${finalUrl} at the configured ${byteLimit}-byte cap.`
        : undefined
    };
  } finally {
    clearTimeout(timeout);
  }
}

function applyStorageFeatureState(input: {
  expectedOrigin: string;
  area: 'localStorage' | 'sessionStorage';
  storageKey: string;
  jsonPath: string[];
  format: 'direct' | 'json';
  expectedValue: JsonValue;
  appliedValue: JsonValue;
  maxOriginalValueCharacters: number;
}): StorageFeatureStateResult {
  try {
    if (location.origin !== input.expectedOrigin) {
      return {
        ok: false,
        code: 'ORIGIN_CHANGED',
        error: 'The page origin changed after discovery; no storage write was attempted.'
      };
    }
    const isPrimitiveJsonValue = (value: unknown): value is string | number | boolean | null =>
      value === null ||
      typeof value === 'string' ||
      typeof value === 'boolean' ||
      (typeof value === 'number' && Number.isFinite(value));
    const valuesEqual = (left: JsonValue, right: JsonValue): boolean =>
      Object.is(left, right);
    const unsafeSegment = (segment: string) =>
      segment === '__proto__' || segment === 'prototype' || segment === 'constructor';

    const storage = input.area === 'localStorage' ? window.localStorage : window.sessionStorage;
    const originalValue = storage.getItem(input.storageKey);
    if (
      originalValue !== null &&
      originalValue.length > input.maxOriginalValueCharacters
    ) {
      return {
        ok: false,
        code: 'UNAVAILABLE',
        error: `The original storage value exceeds the ${input.maxOriginalValueCharacters}-character reversible-probe cap.`
      };
    }
    let previousCandidateValue: JsonValue;
    let replacement: string;
    if (input.format === 'direct') {
      if (originalValue === null) {
        return {
          ok: false,
          code: 'STALE_VALUE',
          error: 'The direct storage value no longer exists; no write was attempted.'
        };
      }
      previousCandidateValue = originalValue;
      if (!valuesEqual(previousCandidateValue, input.expectedValue)) {
        return {
          ok: false,
          code: 'STALE_VALUE',
          error: 'The live storage value no longer matches the scan/current expected value; rescan before changing it.'
        };
      }
      if (valuesEqual(previousCandidateValue, input.appliedValue)) {
        return {
          ok: true,
          changed: false,
          hadOriginalValue: true,
          originalValue,
          previousCandidateValue
        };
      }
      replacement =
        typeof input.appliedValue === 'string'
          ? input.appliedValue
          : String(input.appliedValue);
    } else {
      if (originalValue === null) {
        return {
          ok: false,
          code: 'STALE_VALUE',
          error: 'The JSON storage container no longer exists.'
        };
      }
      const parsed = JSON.parse(originalValue) as unknown;
      if (!parsed || typeof parsed !== 'object') {
        return {
          ok: false,
          code: 'STALE_VALUE',
          error: 'The storage container is no longer a JSON object.'
        };
      }
      let target = parsed as Record<string, unknown>;
      for (const segment of input.jsonPath.slice(0, -1)) {
        if (
          unsafeSegment(segment) ||
          !Object.prototype.hasOwnProperty.call(target, segment) ||
          target[segment] === null ||
          typeof target[segment] !== 'object'
        ) {
          return {
            ok: false,
            code: 'UNSAFE_PATH',
            error: 'The stored JSON path changed or is not safe to update.'
          };
        }
        target = target[segment] as Record<string, unknown>;
      }
      const finalSegment = input.jsonPath.at(-1);
      if (
        !finalSegment ||
        unsafeSegment(finalSegment) ||
        !Object.prototype.hasOwnProperty.call(target, finalSegment)
      ) {
        return {
          ok: false,
          code: 'UNSAFE_PATH',
          error: 'The stored JSON path is empty or unsafe.'
        };
      }
      const liveValue = target[finalSegment];
      if (!isPrimitiveJsonValue(liveValue)) {
        return {
          ok: false,
          code: 'STALE_VALUE',
          error: 'The live JSON flag is no longer a primitive toggle value; no write was attempted.'
        };
      }
      previousCandidateValue = liveValue;
      if (!valuesEqual(previousCandidateValue, input.expectedValue)) {
        return {
          ok: false,
          code: 'STALE_VALUE',
          error: 'The live JSON flag no longer matches the scan/current expected value; rescan before changing it.'
        };
      }
      if (valuesEqual(previousCandidateValue, input.appliedValue)) {
        return {
          ok: true,
          changed: false,
          hadOriginalValue: true,
          originalValue,
          previousCandidateValue
        };
      }
      target[finalSegment] = input.appliedValue;
      replacement = JSON.stringify(parsed);
    }

    storage.setItem(input.storageKey, replacement);
    try {
      window.dispatchEvent(
        new CustomEvent('blanche:latent-feature-probe', {
          detail: {
            area: input.area,
            storageKey: input.storageKey,
            jsonPath: input.jsonPath
          }
        })
      );
    } catch {
      // The reversible storage write is authoritative; a page event listener is advisory only.
    }
    return {
      ok: true,
      changed: true,
      hadOriginalValue: originalValue !== null,
      originalValue: originalValue ?? undefined,
      previousCandidateValue
    };
  } catch (error) {
    return {
      ok: false,
      code: 'UNAVAILABLE',
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

function restoreStorageFeatureProbe(
  input: {
    expectedOrigin: string;
    changes: LatentFeatureProbeChange[];
  }
): StorageFeatureRestoreResult {
  try {
    if (location.origin !== input.expectedOrigin) {
      return {
        ok: false,
        error: 'The page origin changed; no recovery write was attempted.'
      };
    }
    const containers = new Map<string, LatentFeatureProbeChange>();
    for (const change of input.changes) {
      const containerId = `${change.area}\u0000${change.storageKey}`;
      const existing = containers.get(containerId);
      if (
        existing &&
        (existing.hadOriginalValue !== change.hadOriginalValue ||
          existing.originalValue !== change.originalValue)
      ) {
        return {
          ok: false,
          error: `Recovery records for ${change.area}.${change.storageKey} have conflicting exact baselines; no recovery write was attempted.`
        };
      }
      if (!existing) containers.set(containerId, change);
    }

    for (const change of containers.values()) {
      const storage =
        change.area === 'localStorage' ? window.localStorage : window.sessionStorage;
      if (change.hadOriginalValue) {
        storage.setItem(change.storageKey, change.originalValue ?? '');
      } else {
        storage.removeItem(change.storageKey);
      }
      const restoredValue = storage.getItem(change.storageKey);
      if (
        (change.hadOriginalValue && restoredValue !== (change.originalValue ?? '')) ||
        (!change.hadOriginalValue && restoredValue !== null)
      ) {
        return {
          ok: false,
          error: `The browser did not retain the exact baseline for ${change.area}.${change.storageKey}.`
        };
      }
    }
    window.dispatchEvent(
      new CustomEvent('blanche:latent-feature-restore', {
        detail: {
          restoredCount: input.changes.length,
          restoredContainerCount: containers.size
        }
      })
    );
    return {
      ok: true,
      restoredCount: input.changes.length,
      restoredContainerCount: containers.size
    };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

function resolveSettings(settings: Record<string, JsonValue>): LatentFeatureSettings {
  return {
    autoDiscoverOnNavigation: settings.autoDiscoverOnNavigation === true,
    probeLoadedLibraries: settings.probeLoadedLibraries !== false,
    includeThirdPartyLibraries: settings.includeThirdPartyLibraries === true,
    libraryThreadCount: clampNumber(settings.libraryThreadCount, 1, 1, 6),
    libraryDelayMs: clampNumber(settings.libraryDelayMs, 750, 100, 10000),
    maxLibrariesPerScan: clampNumber(settings.maxLibrariesPerScan, 8, 1, 100),
    maxLibraryBytes: clampNumber(settings.maxLibraryBytes, 524288, 16384, 4194304),
    maxTotalLibraryBytes: clampNumber(
      settings.maxTotalLibraryBytes,
      2097152,
      65536,
      16777216
    ),
    maxCandidates: clampNumber(settings.maxCandidates, 200, 10, 1000),
    javascriptObservationMs: clampNumber(settings.javascriptObservationMs, 1500, 250, 10000),
    reloadAfterProbe: settings.reloadAfterProbe !== false,
    checkDependencyAdvisories: settings.checkDependencyAdvisories !== false
  };
}

function clampNumber(
  value: JsonValue | undefined,
  fallback: number,
  minimum: number,
  maximum: number
): number {
  const numeric = typeof value === 'number' && Number.isFinite(value) ? value : fallback;
  return Math.min(maximum, Math.max(minimum, Math.floor(numeric)));
}

function emptyLibraryReadResult(loadedCount: number): LoadedLibraryReadResult {
  return {
    sources: [],
    loadedCount,
    readCount: 0,
    failureCount: 0,
    bytesRead: 0,
    warnings: []
  };
}

function errorResult(message: string): ModuleActionResult {
  return {
    status: 'error',
    message
  };
}

function libraryLabel(rawUrl: string): string {
  try {
    const url = new URL(rawUrl);
    return url.pathname.split('/').filter(Boolean).at(-1) ?? url.hostname;
  } catch {
    return rawUrl.slice(0, 160);
  }
}

function delay(delayMs: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, delayMs));
}

async function reloadAndWaitForTopLevelLoad(tabId: number, timeoutMs = 15000): Promise<void> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  let reloadRequested = false;
  let committedDocumentId: string | undefined;
  let committedUrl: string | undefined;
  let handleCommitted:
    | ((details: chrome.webNavigation.WebNavigationTransitionCallbackDetails) => void)
    | undefined;
  let handleCompleted:
    | ((details: chrome.webNavigation.WebNavigationFramedCallbackDetails) => void)
    | undefined;
  const completion = new Promise<void>((resolve, reject) => {
    handleCommitted = (details) => {
      if (!reloadRequested || details.tabId !== tabId || details.frameId !== 0) return;
      committedDocumentId = details.documentId;
      committedUrl = details.url;
    };
    handleCompleted = (details) => {
      if (
        details.tabId === tabId &&
        details.frameId === 0 &&
        committedUrl &&
        (committedDocumentId
          ? details.documentId === committedDocumentId
          : details.url === committedUrl)
      ) {
        cleanup();
        resolve();
      }
    };
    const cleanup = () => {
      if (timeout) clearTimeout(timeout);
      if (handleCommitted) chrome.webNavigation.onCommitted.removeListener(handleCommitted);
      if (handleCompleted) chrome.webNavigation.onCompleted.removeListener(handleCompleted);
    };
    timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out waiting for tab ${tabId} to finish the startup-observation reload.`));
    }, timeoutMs);
    chrome.webNavigation.onCommitted.addListener(handleCommitted);
    chrome.webNavigation.onCompleted.addListener(handleCompleted);
  });

  try {
    reloadRequested = true;
    await chrome.tabs.reload(tabId);
    await completion;
  } catch (error) {
    if (handleCommitted) chrome.webNavigation.onCommitted.removeListener(handleCommitted);
    if (handleCompleted) chrome.webNavigation.onCompleted.removeListener(handleCompleted);
    if (timeout) clearTimeout(timeout);
    throw error;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isJsonValue(value: unknown): value is JsonValue {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return true;
  }
  if (Array.isArray(value)) {
    return value.every(isJsonValue);
  }
  if (isRecord(value)) {
    return Object.values(value).every(isJsonValue);
  }
  return false;
}
