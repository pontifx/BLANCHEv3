import type {
  ArtifactDescriptor,
  CollectorResult,
  ExportError,
  ExportWarning,
  JsonObject,
  PageMetadata,
  VisibilityGap
} from '../../../../shared-schema/src';
import type {
  Logger,
  ModuleActionContext,
  ModuleActionResult,
  ModuleBackgroundController,
  ModuleDescriptor
} from '../../shared/contracts';
import {
  createId,
  isInspectableUrl,
  sanitizeJsonValue,
  toErrorDetails,
  tryGetOrigin
} from '../../shared/helpers';
import type {
  BurpBridgeSettings,
  ContentInstrumentationResponse,
  InstrumentationEventRecord,
  PageFrameCollectorPayload
} from './types';
import { collectPageFrameSnapshot } from './pageSnapshotScript';

const CONTENT_MESSAGE_CHANNEL = 'blanche-burp-bridge';
const DEFAULT_BURP_INGEST_URL = 'http://blanche.invalid/ingest';
const DEFAULT_BURP_LOOPBACK_INGEST_URL = 'http://127.0.0.1:47625/api/blanche/ingest';
const BURP_INGEST_TIMEOUT_MS = 5000;

interface FrameSnapshotResult {
  frameId: number;
  payload: PageFrameCollectorPayload;
}

interface InstrumentationFrameResult {
  frameId: number;
  response?: ContentInstrumentationResponse;
  error?: string;
}

interface FrameRecord {
  frameId: number;
  parentFrameId: number;
  url?: string;
  errorOccurred?: boolean;
  documentId?: string;
  frameType?: string;
}

interface BurpIngestAttemptResult {
  delivered: boolean;
  endpoint: string;
  warning?: ExportWarning;
  status?: number;
  responseText?: string;
}

interface EndpointAttemptResult {
  delivered: boolean;
  endpoint: string;
  errorMessage?: string;
  status?: number;
  responseText?: string;
}

export function createBurpBridgeBackgroundController(input: {
  descriptor: ModuleDescriptor;
  logger: Logger;
}): ModuleBackgroundController {
  return {
    async onHostStart() {
      input.logger.info('Burp Bridge background controller ready');
    },
    async runAction(request, context) {
      return runCollection(input.descriptor, request.actionId, request.tabId, context);
    }
  };
}

async function runCollection(
  descriptor: ModuleDescriptor,
  actionId: string,
  tabId: number | undefined,
  context: ModuleActionContext
): Promise<ModuleActionResult> {
  if (!tabId) {
    return {
      status: 'error',
      message: 'Burp Bridge requires a target tab.'
    };
  }

  const settings = resolveSettings(context.settings);
  const tab = await chrome.tabs.get(tabId);

  if (!isInspectableUrl(tab.url)) {
    return {
      status: 'error',
      message: `Unsupported tab URL for collection: ${tab.url ?? 'unknown'}`
    };
  }

  const forceInstrumented = actionId === 'collectInstrumented';
  const mode = actionId === 'collectPassive' ? 'passive' : forceInstrumented ? 'instrumented' : settings.defaultMode;
  const reloadTriggered = forceInstrumented || (actionId !== 'collectPassive' && settings.reloadBeforeCollect);
  const session = context.sessions.begin({
    moduleId: descriptor.id,
    tabId,
    mode,
    reloadTriggered,
    note: `Burp Bridge ${mode} collection`
  });

  context.logger.info('Starting Burp Bridge collection', {
    sessionId: session.sessionId,
    tabId,
    mode,
    reloadTriggered
  });

  try {
    if (reloadTriggered) {
      await chrome.tabs.reload(tabId);
      await waitForTopLevelLoad(tabId);
    }

    const finalTab = await chrome.tabs.get(tabId);
    const [frameStructure, pageSnapshots, instrumentation] = await Promise.all([
      collectFrameStructure(tabId),
      collectPageSnapshots(tabId, settings),
      collectInstrumentation(tabId, mode)
    ]);

    const page = buildPageMetadata(finalTab, frameStructure.frames, pageSnapshots.frames);
    const topLevelWarnings: ExportWarning[] = [];
    const topLevelErrors: ExportError[] = [];
    const topLevelVisibilityGaps: VisibilityGap[] = [];

    if (mode === 'passive') {
      topLevelWarnings.push({
        code: 'PASSIVE_MODE_PROVENANCE_LIMIT',
        message:
          'Passive mode can enumerate current blob and dynamic artifacts, but cannot retroactively prove creation provenance.',
        severity: 'warning'
      });
      topLevelVisibilityGaps.push({
        code: 'PASSIVE_MODE_BLOB_PROVENANCE_GAP',
        surface: 'background',
        message:
          'Blob URL provenance remains unavailable without instrumented document_start observation.',
        reason: 'timing'
      });
    }

    const permissions = await context.services.getPermissionsState();
    const artifacts = buildArtifacts(frameStructure.frames, pageSnapshots.frames, instrumentation.frames);
    const trafficLedger = await context.services.getTrafficLedgerExport({
      sourceSessionId: session.sessionId,
      tabId,
      targetOrigin: page.origin,
      since: reloadTriggered ? session.startedAt : undefined,
      limit: 1000
    });
    const exportPayload = context.services.buildExport({
      component: 'chromium-extension/background',
      hostVersion: context.services.getProductVersion(),
      module: {
        id: descriptor.id,
        name: descriptor.name,
        version: descriptor.version
      },
      page,
      collection: {
        sessionId: session.sessionId,
        mode,
        reloadTriggered,
        startedAt: session.startedAt,
        finishedAt: new Date().toISOString(),
        target: {
          tabId,
          initialUrl: tab.url,
          finalUrl: finalTab.url
        }
      },
      permissions,
      collectors: [frameStructure.collector, pageSnapshots.collector, instrumentation.collector],
      artifacts,
      trafficLedger,
      warnings: topLevelWarnings,
      errors: topLevelErrors,
      visibilityGaps: topLevelVisibilityGaps
    });

    await context.services.saveLastExport(exportPayload);
    const burpIngestResult = await maybeSendExportToBurp(exportPayload, settings, context.logger);
    context.sessions.complete(
      session.sessionId,
      `Collected ${exportPayload.summary.artifactCount} artifacts and ${trafficLedger.summary.entryCount} traffic endpoints`
    );

    const resultWarnings = burpIngestResult.warning
      ? [...exportPayload.warnings, burpIngestResult.warning]
      : exportPayload.warnings;
    const resultStatus: ModuleActionResult['status'] =
      exportPayload.errors.length > 0 || burpIngestResult.warning?.severity === 'warning'
        ? 'partial'
        : 'ok';
    const burpStatusMessage = settings.autoSendToBurp
      ? burpIngestResult.delivered
        ? ` Export sent to Burp at ${burpIngestResult.endpoint}.`
        : ` Export saved locally, but Burp auto-ingest failed at ${burpIngestResult.endpoint}.`
      : ' Auto-send to Burp is disabled.';

    return {
      status: resultStatus,
      message: `Collected ${exportPayload.summary.artifactCount} artifacts and ${trafficLedger.summary.entryCount} scored traffic endpoints from tab ${tabId}.${burpStatusMessage}`,
      sessionId: session.sessionId,
      export: exportPayload,
      warnings: resultWarnings,
      errors: exportPayload.errors,
      data: {
        artifactCount: exportPayload.summary.artifactCount,
        trafficEntryCount: trafficLedger.summary.entryCount,
        trafficHighestScore: trafficLedger.summary.highestScore,
        trafficHandoffEligibleCount: trafficLedger.summary.handoffEligibleCount,
        frameCount: exportPayload.page.frames.length,
        burpIngested: burpIngestResult.delivered,
        burpIngestUrl: burpIngestResult.endpoint,
        burpIngestStatus: burpIngestResult.status ?? null,
        burpIngestResponse: burpIngestResult.responseText
          ? burpIngestResult.responseText.slice(0, 1200)
          : null
      }
    };
  } catch (error) {
    context.sessions.fail(
      session.sessionId,
      error instanceof Error ? error.message : String(error)
    );
    context.logger.error('Burp Bridge collection failed', {
      sessionId: session.sessionId,
      error: toErrorDetails(error)
    });
    return {
      status: 'error',
      message: error instanceof Error ? error.message : String(error),
      errors: [
        {
          code: 'BURP_BRIDGE_COLLECTION_FAILED',
          message: error instanceof Error ? error.message : String(error),
          recoverable: true
        }
      ]
    };
  }
}

async function maybeSendExportToBurp(
  exportPayload: ReturnType<ModuleActionContext['services']['buildExport']>,
  settings: BurpBridgeSettings,
  logger: Logger
): Promise<BurpIngestAttemptResult> {
  const endpoint = settings.burpIngestUrl.trim();
  if (!settings.autoSendToBurp) {
    return {
      delivered: false,
      endpoint
    };
  }

  const primaryEndpoint = endpoint || DEFAULT_BURP_INGEST_URL;
  const fallbackEndpoint = DEFAULT_BURP_LOOPBACK_INGEST_URL;

  const primaryAttempt = await sendExportToEndpoint(exportPayload, primaryEndpoint, logger);
  if (primaryAttempt.delivered) {
    return {
      delivered: true,
      endpoint: primaryAttempt.endpoint,
      status: primaryAttempt.status,
      responseText: primaryAttempt.responseText
    };
  }

  if (primaryEndpoint === fallbackEndpoint) {
    return {
      delivered: false,
      endpoint: primaryEndpoint,
      warning: {
        code: 'BURP_AUTO_INGEST_FAILED',
        message: `Burp auto-ingest failed: ${primaryAttempt.errorMessage ?? 'Unknown error.'}`,
        severity: 'warning',
        context: {
          endpoint: primaryEndpoint
        }
      }
    };
  }

  const fallbackAttempt = await sendExportToEndpoint(exportPayload, fallbackEndpoint, logger);
  if (fallbackAttempt.delivered) {
    logger.info('Burp Bridge export delivered via fallback ingest endpoint', {
      primaryEndpoint,
      fallbackEndpoint
    });

    return {
      delivered: true,
      endpoint: fallbackEndpoint,
      status: fallbackAttempt.status,
      responseText: fallbackAttempt.responseText,
      warning: {
        code: 'BURP_AUTO_INGEST_FALLBACK_USED',
        message: `Primary Burp ingest endpoint ${primaryEndpoint} failed; delivered export to fallback ${fallbackEndpoint}.`,
        severity: 'info',
        context: {
          primaryEndpoint,
          fallbackEndpoint
        }
      }
    };
  }

  return {
    delivered: false,
    endpoint: primaryEndpoint,
    warning: {
      code: 'BURP_AUTO_INGEST_FAILED',
      message:
        `Burp auto-ingest failed. Primary ${primaryEndpoint}: ${primaryAttempt.errorMessage ?? 'Unknown error.'} ` +
        `Fallback ${fallbackEndpoint}: ${fallbackAttempt.errorMessage ?? 'Unknown error.'}`,
      severity: 'warning',
      context: {
        primaryEndpoint,
        fallbackEndpoint
      }
    }
  };
}

async function sendExportToEndpoint(
  exportPayload: ReturnType<ModuleActionContext['services']['buildExport']>,
  endpoint: string,
  logger: Logger
): Promise<EndpointAttemptResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), BURP_INGEST_TIMEOUT_MS);

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'text/plain;charset=UTF-8'
      },
      body: JSON.stringify(exportPayload),
      credentials: 'omit',
      mode: 'no-cors',
      signal: controller.signal
    });
    const opaque = response.type === 'opaque';
    const responseText = opaque ? undefined : await response.text();

    if (!opaque && !response.ok) {
      throw new Error(
        `Burp ingest endpoint responded with ${response.status}${
          responseText ? `: ${responseText.slice(0, 240)}` : ''
        }`
      );
    }

    logger.info('Burp Bridge export sent to Burp', {
      endpoint,
      status: response.status,
      opaque
    });

    return {
      delivered: true,
      endpoint,
      status: opaque ? undefined : response.status,
      responseText
    };
  } catch (error) {
    const errorMessage =
      error instanceof Error && error.name === 'AbortError'
        ? `Timed out waiting for the Burp ingest endpoint after ${BURP_INGEST_TIMEOUT_MS}ms.`
        : error instanceof Error
          ? error.message
          : String(error);

    logger.warn('Burp Bridge export handoff attempt failed', {
      endpoint,
      error: toErrorDetails(error)
    });

    return {
      delivered: false,
      endpoint,
      errorMessage
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function collectFrameStructure(tabId: number): Promise<{
  frames: FrameRecord[];
  collector: CollectorResult;
}> {
  const collectedAt = new Date().toISOString();
  try {
    const rawFrames = (await chrome.webNavigation.getAllFrames({ tabId })) ?? [];
    const frames = rawFrames.map((frame) => ({
      frameId: frame.frameId,
      parentFrameId: frame.parentFrameId,
      url: frame.url,
      errorOccurred: frame.errorOccurred,
      documentId: frame.documentId,
      frameType: frame.frameType
    }));

    return {
      frames,
      collector: {
        collectorId: 'frame-structure',
        name: 'Frame Structure Collector',
        surface: 'background',
        status: 'ok',
        collectedAt,
        warnings: [],
        errors: [],
        visibilityGaps: [],
        data: {
          frames
        }
      }
    };
  } catch (error) {
    return {
      frames: [],
      collector: {
        collectorId: 'frame-structure',
        name: 'Frame Structure Collector',
        surface: 'background',
        status: 'error',
        collectedAt,
        warnings: [],
        errors: [
          {
            code: 'FRAME_STRUCTURE_FAILED',
            message: error instanceof Error ? error.message : String(error),
            collectorId: 'frame-structure',
            recoverable: true
          }
        ],
        visibilityGaps: [],
        data: {
          frames: []
        }
      }
    };
  }
}

async function collectPageSnapshots(
  tabId: number,
  settings: BurpBridgeSettings
): Promise<{
  frames: FrameSnapshotResult[];
  collector: CollectorResult;
}> {
  const collectedAt = new Date().toISOString();

  try {
    const injectionResults = await chrome.scripting.executeScript({
      target: {
        tabId,
        allFrames: true
      },
      world: 'MAIN',
      func: collectPageFrameSnapshot,
      args: [
        {
          resourceEntryLimit: settings.resourceEntryLimit,
          cacheEntryLimit: settings.cacheEntryLimit,
          storageValueLimit: settings.storageValueLimit
        }
      ]
    });

    const frames = injectionResults
      .filter((result) => result.result)
      .map((result) => ({
        frameId: result.frameId,
        payload: result.result as unknown as PageFrameCollectorPayload
      }));

    const warnings = frames.flatMap((frame) =>
      frame.payload.warnings.map<ExportWarning>((warning) => ({
        code: warning.code,
        message: warning.message,
        collectorId: 'page-snapshot',
        severity: 'warning',
        context: {
          frameId: frame.frameId
        }
      }))
    );
    const visibilityGaps = frames.flatMap((frame) =>
      frame.payload.visibilityGaps.map<VisibilityGap>((gap) => ({
        code: gap.code,
        surface: 'page',
        message: gap.message,
        reason: gap.reason,
        context: {
          frameId: frame.frameId
        }
      }))
    );

    return {
      frames,
      collector: {
        collectorId: 'page-snapshot',
        name: 'Page Snapshot Collector',
        surface: 'page',
        status: warnings.length > 0 || visibilityGaps.length > 0 ? 'partial' : 'ok',
        collectedAt,
        warnings,
        errors: [],
        visibilityGaps,
        data: {
          frames: frames.map((frame) => ({
            frameId: frame.frameId,
            snapshot: sanitizeJsonValue(frame.payload.snapshot)
          }))
        }
      }
    };
  } catch (error) {
    return {
      frames: [],
      collector: {
        collectorId: 'page-snapshot',
        name: 'Page Snapshot Collector',
        surface: 'page',
        status: 'error',
        collectedAt,
        warnings: [],
        errors: [
          {
            code: 'PAGE_SNAPSHOT_EXECUTION_FAILED',
            message: error instanceof Error ? error.message : String(error),
            collectorId: 'page-snapshot',
            recoverable: true
          }
        ],
        visibilityGaps: [],
        data: {
          frames: []
        }
      }
    };
  }
}

async function collectInstrumentation(
  tabId: number,
  mode: BurpBridgeSettings['defaultMode']
): Promise<{
  frames: InstrumentationFrameResult[];
  collector: CollectorResult;
}> {
  const collectedAt = new Date().toISOString();
  if (mode === 'passive') {
    return {
      frames: [],
      collector: {
        collectorId: 'instrumentation-bridge',
        name: 'Instrumentation Bridge Collector',
        surface: 'content',
        status: 'partial',
        collectedAt,
        warnings: [
          {
            code: 'INSTRUMENTATION_SKIPPED',
            message: 'Instrumentation collector skipped because passive mode was selected.',
            collectorId: 'instrumentation-bridge',
            severity: 'info'
          }
        ],
        errors: [],
        visibilityGaps: [
          {
            code: 'INSTRUMENTATION_NOT_REQUESTED',
            surface: 'content',
            message:
              'Document_start instrumentation was not requested, so dynamic blob provenance can remain unavailable.',
            reason: 'timing'
          }
        ],
        data: {
          frames: []
        }
      }
    };
  }

  const frameResults = (await chrome.webNavigation.getAllFrames({ tabId })) ?? [];
  const frames = await Promise.all(
    frameResults.map(async (frame) => {
      try {
        const response = (await chrome.tabs.sendMessage(
          tabId,
          {
            channel: CONTENT_MESSAGE_CHANNEL,
            type: 'content/getInstrumentationSnapshot'
          },
          {
            frameId: frame.frameId
          }
        )) as ContentInstrumentationResponse;

        return {
          frameId: frame.frameId,
          response
        } satisfies InstrumentationFrameResult;
      } catch (error) {
        return {
          frameId: frame.frameId,
          error: error instanceof Error ? error.message : String(error)
        } satisfies InstrumentationFrameResult;
      }
    })
  );

  const warnings = frames.flatMap((frame) => {
    if (!frame.response) {
      return [];
    }

    return frame.response.warnings.map<ExportWarning>((message) => ({
      code: 'CONTENT_INSTRUMENTATION_WARNING',
      message,
      collectorId: 'instrumentation-bridge',
      severity: 'warning',
      context: {
        frameId: frame.frameId
      }
    }));
  });

  const errors = frames
    .filter((frame) => frame.error)
    .map<ExportError>((frame) => ({
      code: 'CONTENT_INSTRUMENTATION_FAILED',
      message: frame.error ?? 'Instrumentation request failed',
      collectorId: 'instrumentation-bridge',
      recoverable: true,
      context: {
        frameId: frame.frameId
      }
    }));

  const visibilityGaps = frames
    .filter((frame) => frame.response && !frame.response.instrumented)
    .map<VisibilityGap>((frame) => ({
      code: 'INSTRUMENTOR_NOT_READY',
      surface: 'content',
      message:
        'The content bridge did not receive a document_start instrumentation snapshot for this frame.',
      reason: 'timing',
      context: {
        frameId: frame.frameId
      }
    }));

  return {
    frames,
    collector: {
      collectorId: 'instrumentation-bridge',
      name: 'Instrumentation Bridge Collector',
      surface: 'content',
      status: errors.length > 0 || visibilityGaps.length > 0 ? 'partial' : 'ok',
      collectedAt,
      warnings,
      errors,
      visibilityGaps,
      data: {
        frames: frames.map((frame) => ({
          frameId: frame.frameId,
          response: frame.response ? sanitizeJsonValue(frame.response) : null,
          error: frame.error ?? null
        }))
      }
    }
  };
}

async function waitForTopLevelLoad(tabId: number, timeoutMs = 15000): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out waiting for tab ${tabId} to finish loading`));
    }, timeoutMs);

    const handleCompleted = (details: chrome.webNavigation.WebNavigationFramedCallbackDetails) => {
      if (details.tabId === tabId && details.frameId === 0) {
        cleanup();
        resolve();
      }
    };

    const cleanup = () => {
      clearTimeout(timeout);
      chrome.webNavigation.onCompleted.removeListener(handleCompleted);
    };

    chrome.webNavigation.onCompleted.addListener(handleCompleted);
  });
}

function resolveSettings(rawSettings: Record<string, unknown>): BurpBridgeSettings {
  return {
    defaultMode:
      rawSettings.defaultMode === 'passive' || rawSettings.defaultMode === 'instrumented'
        ? rawSettings.defaultMode
        : 'instrumented',
    reloadBeforeCollect: rawSettings.reloadBeforeCollect !== false,
    autoCaptureOnNavigation: rawSettings.autoCaptureOnNavigation !== false,
    autoSendToBurp: rawSettings.autoSendToBurp !== false,
    burpIngestUrl:
      typeof rawSettings.burpIngestUrl === 'string' && rawSettings.burpIngestUrl.trim().length > 0
        ? rawSettings.burpIngestUrl.trim()
        : DEFAULT_BURP_INGEST_URL,
    resourceEntryLimit:
      typeof rawSettings.resourceEntryLimit === 'number' ? rawSettings.resourceEntryLimit : 250,
    cacheEntryLimit:
      typeof rawSettings.cacheEntryLimit === 'number' ? rawSettings.cacheEntryLimit : 40,
    storageValueLimit:
      typeof rawSettings.storageValueLimit === 'number' ? rawSettings.storageValueLimit : 400
  };
}

function buildPageMetadata(
  tab: chrome.tabs.Tab,
  frameStructure: FrameRecord[],
  snapshots: FrameSnapshotResult[]
): PageMetadata {
  const topFrameSnapshot = snapshots.find((frame) => frame.frameId === 0)?.payload.snapshot;
  const frames =
    frameStructure.length > 0
      ? frameStructure.map((frame) => ({
          frameId: frame.frameId,
          parentFrameId: frame.parentFrameId >= 0 ? frame.parentFrameId : undefined,
          url: frame.url,
          origin: tryGetOrigin(frame.url),
          documentId: frame.documentId,
          frameType: frame.frameType,
          errorOccurred: frame.errorOccurred
        }))
      : snapshots.map((frame) => ({
          frameId: frame.frameId,
          parentFrameId: frame.frameId === 0 ? undefined : 0,
          url: frame.payload.snapshot.url,
          origin: tryGetOrigin(frame.payload.snapshot.url)
        }));

  return {
    url: tab.url,
    title:
      typeof topFrameSnapshot?.title === 'string'
        ? topFrameSnapshot.title
        : tab.title,
    origin:
      typeof topFrameSnapshot?.origin === 'string'
        ? topFrameSnapshot.origin
        : tryGetOrigin(tab.url),
    referrer:
      typeof topFrameSnapshot?.referrer === 'string'
        ? topFrameSnapshot.referrer
        : undefined,
    topLevelFrameId: 0,
    frames,
    tab: {
      tabId: tab.id ?? 0,
      windowId: tab.windowId,
      openerTabId: tab.openerTabId,
      status: tab.status,
      active: tab.active,
      discarded: tab.discarded,
      audible: tab.audible,
      favIconUrl: tab.favIconUrl
    }
  };
}

function buildArtifacts(
  frameStructure: FrameRecord[],
  snapshots: FrameSnapshotResult[],
  instrumentationFrames: InstrumentationFrameResult[]
): ArtifactDescriptor[] {
  const artifacts = new Map<string, ArtifactDescriptor>();

  const upsertArtifact = (key: string, candidate: ArtifactDescriptor) => {
    const existing = artifacts.get(key);
    if (!existing) {
      artifacts.set(key, candidate);
      return;
    }

    existing.discoveredBy = Array.from(new Set([...existing.discoveredBy, ...candidate.discoveredBy]));
    existing.provenance.sources = Array.from(
      new Set([...existing.provenance.sources, ...candidate.provenance.sources])
    );

    if (rankDisposition(candidate.provenance.disposition) > rankDisposition(existing.provenance.disposition)) {
      existing.provenance.disposition = candidate.provenance.disposition;
      existing.provenance.confidence = candidate.provenance.confidence;
      existing.provenance.note = candidate.provenance.note;
    }

    existing.attributes = {
      ...existing.attributes,
      ...candidate.attributes
    };
  };

  for (const frame of frameStructure) {
    upsertArtifact(`frame:${frame.frameId}`, {
      artifactId: createId('artifact'),
      category: 'frame',
      kind: 'frame',
      url: frame.url,
      frameId: frame.frameId,
      origin: tryGetOrigin(frame.url),
      discoveredBy: ['webNavigation'],
      attributes: {
        parentFrameId: frame.parentFrameId,
        frameType: frame.frameType ?? null,
        errorOccurred: frame.errorOccurred ?? false
      },
      provenance: {
        disposition: 'observed',
        confidence: 'high',
        sources: ['webNavigation.getAllFrames']
      }
    });
  }

  for (const frame of snapshots) {
    const snapshot = frame.payload.snapshot;
    upsertArtifact(`runtime:${frame.frameId}`, {
      artifactId: createId('artifact'),
      category: 'runtime-indicator',
      kind: 'frame-runtime-state',
      frameId: frame.frameId,
      url: typeof snapshot.url === 'string' ? snapshot.url : undefined,
      origin: tryGetOrigin(typeof snapshot.url === 'string' ? snapshot.url : undefined),
      discoveredBy: ['page-snapshot'],
      attributes: snapshot.runtimeIndicators,
      provenance: {
        disposition: 'observed',
        confidence: 'high',
        sources: ['page snapshot']
      }
    });

    addDomArtifacts(upsertArtifact, frame.frameId, snapshot.dom.scripts, 'script', 'dom-script');
    addDomArtifacts(
      upsertArtifact,
      frame.frameId,
      snapshot.dom.stylesheets,
      'stylesheet',
      'dom-stylesheet'
    );
    addDomArtifacts(upsertArtifact, frame.frameId, snapshot.dom.images, 'image', 'dom-image');
    addDomArtifacts(
      upsertArtifact,
      frame.frameId,
      snapshot.dom.manifests,
      'manifest',
      'dom-manifest'
    );
    addDomArtifacts(upsertArtifact, frame.frameId, snapshot.dom.iframes, 'iframe', 'dom-iframe');

    for (const font of snapshot.dom.fonts) {
      upsertArtifact(`font:${frame.frameId}:${font.family ?? createId('font')}`, {
        artifactId: createId('artifact'),
        category: 'font',
        kind: 'font-face',
        frameId: frame.frameId,
        discoveredBy: ['page-snapshot'],
        attributes: font,
        provenance: {
          disposition: 'observed',
          confidence: 'medium',
          sources: ['document.fonts']
        }
      });
    }

    for (const resource of snapshot.resources) {
      const name = typeof resource.name === 'string' ? resource.name : undefined;
      const category = categoryFromResource(resource);
      upsertArtifact(`resource:${frame.frameId}:${name ?? createId('resource')}`, {
        artifactId: createId('artifact'),
        category,
        kind: 'performance-resource',
        url: name,
        frameId: frame.frameId,
        origin: tryGetOrigin(name),
        discoveredBy: ['performance'],
        attributes: resource,
        provenance: {
          disposition:
            name?.startsWith('blob:') || name?.startsWith('data:') ? 'inferred' : 'observed',
          confidence:
            name?.startsWith('blob:') || name?.startsWith('data:') ? 'medium' : 'high',
          sources: ['performance resource timing'],
          note:
            name?.startsWith('blob:') || name?.startsWith('data:')
              ? 'Chromium reported this resource, but performance data alone does not establish full provenance.'
              : undefined
        }
      });
    }

    addStorageArtifacts(upsertArtifact, frame.frameId, snapshot.storage.localStorage, 'localStorage');
    addStorageArtifacts(
      upsertArtifact,
      frame.frameId,
      snapshot.storage.sessionStorage,
      'sessionStorage'
    );

    for (const database of snapshot.storage.indexedDb) {
      upsertArtifact(`idb:${frame.frameId}:${database.name ?? createId('idb')}`, {
        artifactId: createId('artifact'),
        category: 'indexeddb-database',
        kind: 'indexeddb-database',
        frameId: frame.frameId,
        discoveredBy: ['page-snapshot'],
        attributes: database,
        provenance: {
          disposition: 'observed',
          confidence: 'medium',
          sources: ['indexedDB']
        }
      });
    }

    for (const cache of snapshot.storage.cacheStorage) {
      upsertArtifact(`cache:${frame.frameId}:${cache.name ?? createId('cache')}`, {
        artifactId: createId('artifact'),
        category: 'cache',
        kind: 'cache-storage',
        frameId: frame.frameId,
        discoveredBy: ['page-snapshot'],
        attributes: cache,
        provenance: {
          disposition: 'observed',
          confidence: 'medium',
          sources: ['Cache Storage']
        }
      });
    }

    for (const serviceWorker of snapshot.workers.serviceWorkers) {
      upsertArtifact(`service-worker:${serviceWorker.scope ?? createId('sw')}`, {
        artifactId: createId('artifact'),
        category: 'service-worker',
        kind: 'service-worker-registration',
        url:
          typeof serviceWorker.activeScriptUrl === 'string'
            ? serviceWorker.activeScriptUrl
            : undefined,
        frameId: frame.frameId,
        origin: tryGetOrigin(
          typeof serviceWorker.activeScriptUrl === 'string'
            ? serviceWorker.activeScriptUrl
            : undefined
        ),
        discoveredBy: ['page-snapshot'],
        attributes: serviceWorker,
        provenance: {
          disposition: 'observed',
          confidence: 'medium',
          sources: ['navigator.serviceWorker']
        }
      });
    }
  }

  for (const instrumentationFrame of instrumentationFrames) {
    if (!instrumentationFrame.response?.snapshot) {
      continue;
    }

    for (const event of instrumentationFrame.response.snapshot.events) {
      const artifact = buildInstrumentationArtifact(instrumentationFrame.frameId, event);
      upsertArtifact(
        `${artifact.category}:${instrumentationFrame.frameId}:${artifact.url ?? artifact.kind}:${event.type}`,
        artifact
      );
    }
  }

  return [...artifacts.values()];
}

function addDomArtifacts(
  upsertArtifact: (key: string, artifact: ArtifactDescriptor) => void,
  frameId: number,
  entries: JsonObject[],
  category: ArtifactDescriptor['category'],
  kind: string
): void {
  for (const entry of entries) {
    const url = typeof entry.url === 'string' ? entry.url : undefined;
    upsertArtifact(`${category}:${frameId}:${url ?? entry.tagName ?? kind}`, {
      artifactId: createId('artifact'),
      category,
      kind,
      url,
      frameId,
      origin: tryGetOrigin(url),
      discoveredBy: ['page-snapshot'],
      attributes: entry,
      provenance: {
        disposition: url?.startsWith('blob:') ? 'unavailable' : 'observed',
        confidence: url?.startsWith('blob:') ? 'low' : 'high',
        sources: ['page snapshot dom'],
        note: url?.startsWith('blob:')
          ? 'Blob URL observed in the current DOM, but retroactive creation provenance is unavailable without prior instrumentation.'
          : undefined
      }
    });
  }
}

function addStorageArtifacts(
  upsertArtifact: (key: string, artifact: ArtifactDescriptor) => void,
  frameId: number,
  entries: JsonObject[],
  kind: 'localStorage' | 'sessionStorage'
): void {
  for (const entry of entries) {
    upsertArtifact(`${kind}:${frameId}:${entry.key}`, {
      artifactId: createId('artifact'),
      category: 'storage-key',
      kind,
      frameId,
      discoveredBy: ['page-snapshot'],
      attributes: entry,
      provenance: {
        disposition: 'observed',
        confidence: 'high',
        sources: [kind]
      }
    });
  }
}

function buildInstrumentationArtifact(
  frameId: number,
  event: InstrumentationEventRecord
): ArtifactDescriptor {
  const category =
    event.type === 'blob-created' || event.type === 'blob-revoked'
      ? 'blob'
      : event.type === 'script-added'
        ? 'script'
        : event.type === 'stylesheet-added'
          ? 'stylesheet'
          : event.type === 'image-added'
            ? 'image'
            : event.type === 'iframe-added'
              ? 'iframe'
              : event.type === 'worker-constructed' || event.type === 'shared-worker-constructed'
                ? 'worker'
                : 'runtime-indicator';

  return {
    artifactId: createId('artifact'),
    category,
    kind: `instrumented-${event.type}`,
    url: event.url,
    frameId,
    origin: tryGetOrigin(event.url),
    discoveredBy: ['instrumentation'],
    attributes: event.attributes,
    provenance: {
      disposition: 'observed',
      confidence: 'high',
      sources: ['document_start instrumentation'],
      note: 'Observed by injected page instrumentation before or during resource creation.'
    }
  };
}

function rankDisposition(value: ArtifactDescriptor['provenance']['disposition']): number {
  switch (value) {
    case 'observed':
      return 3;
    case 'inferred':
      return 2;
    case 'unavailable':
    default:
      return 1;
  }
}

function categoryFromResource(resource: JsonObject): ArtifactDescriptor['category'] {
  const initiator = String(resource.initiatorType ?? '').toLowerCase();
  if (initiator.includes('script')) {
    return 'script';
  }

  if (initiator.includes('css') || initiator.includes('link')) {
    return 'stylesheet';
  }

  if (initiator.includes('img') || initiator.includes('image')) {
    return 'image';
  }

  if (initiator.includes('font')) {
    return 'font';
  }

  if (initiator.includes('manifest')) {
    return 'manifest';
  }

  if (initiator.includes('worker')) {
    return 'worker';
  }

  return 'resource';
}
