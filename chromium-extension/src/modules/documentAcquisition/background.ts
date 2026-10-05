import type { JsonObject, JsonValue } from '../../../../shared-schema/src';
import type {
  Logger,
  ModuleActionContext,
  ModuleActionResult,
  ModuleBackgroundController,
  ModuleDescriptor,
  ModuleHostServices
} from '../../shared/contracts';
import {
  DEFAULT_DOCUMENT_KEYWORDS,
  createDefaultDocumentWorkbenchState,
  createDocumentSession,
  getActiveDocumentSession,
  normalizeDocumentWorkbenchState,
  parseInterestingKeywords,
  recalculateDocumentSessionCounts,
  sanitizePathSegment,
  type AcquiredDocument,
  type DocumentAnalysis,
  type DocumentSource,
  type DocumentWorkbenchState
} from '../../shared/documentWorkbench';
import { createId, toErrorDetails } from '../../shared/helpers';
import type { DocumentCandidate, ResolvedDocumentAcquisitionSettings } from './types';

const DOCUMENT_EXTENSIONS = new Set([
  'pdf',
  'doc',
  'docx',
  'xls',
  'xlsx',
  'ppt',
  'pptx',
  'csv',
  'txt',
  'rtf',
  'odt',
  'ods',
  'odp',
  'xml',
  'json',
  'zip',
  '7z',
  'rar',
  'gz',
  'gzip',
  'tgz',
  'tar'
]);

const DOCUMENT_MIME_PREFIXES = [
  'application/pdf',
  'application/msword',
  'application/vnd.ms-',
  'application/vnd.openxmlformats-officedocument',
  'application/rtf',
  'application/xml',
  'application/json',
  'application/zip',
  'application/x-7z-compressed',
  'application/x-rar-compressed',
  'application/gzip',
  'application/x-gzip',
  'application/x-tar',
  'text/csv',
  'text/plain',
  'text/xml'
];

const DOCUMENT_SEARCH_QUERIES = [
  'filetype:pdf',
  '(filetype:doc OR filetype:docx)',
  '(filetype:xls OR filetype:xlsx OR filetype:csv)',
  '(filetype:ppt OR filetype:pptx)',
  '(filetype:odt OR filetype:ods OR filetype:odp)',
  '(filetype:zip OR filetype:7z OR filetype:rar)',
  '(inurl:download OR inurl:files OR inurl:documents)'
];

const MAX_ANALYSIS_TEXT_BYTES = 2_000_000;
const MAX_EXTRACTED_URLS = 200;
const MAX_ZIP_ENTRIES = 32;
const MAX_SCOPED_REDIRECT_HOPS = 10;
const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);

interface HeaderMap {
  contentType?: string;
  contentDisposition?: string;
  contentEncoding?: string;
  contentLength?: number;
}

interface PageDocumentLink {
  url: string;
  text?: string;
}

type ScopedDocumentFetchResult =
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

export function createDocumentAcquisitionBackgroundController(input: {
  descriptor: ModuleDescriptor;
  logger: Logger;
  host: ModuleHostServices;
}): ModuleBackgroundController {
  let listenerRegistered = false;
  const inFlightUrls = new Set<string>();

  const handleHeadersReceived = (
    details: chrome.webRequest.OnHeadersReceivedDetails
  ): chrome.webRequest.BlockingResponse | undefined => {
    void handleDocumentResponse(details).catch((error) => {
      input.logger.warn('Document response handling failed', {
        url: details.url,
        error: toErrorDetails(error)
      });
    });
    return undefined;
  };

  const registerListener = () => {
    if (listenerRegistered || !chrome.webRequest?.onHeadersReceived) {
      return;
    }

    chrome.webRequest.onHeadersReceived.addListener(
      handleHeadersReceived,
      {
        urls: ['<all_urls>']
      },
      ['responseHeaders']
    );
    listenerRegistered = true;
  };

  const unregisterListener = () => {
    if (!listenerRegistered || !chrome.webRequest?.onHeadersReceived) {
      return;
    }

    chrome.webRequest.onHeadersReceived.removeListener(handleHeadersReceived);
    listenerRegistered = false;
  };

  const getSettings = (): ResolvedDocumentAcquisitionSettings => {
    const moduleState = input.host
      .getModuleStates()
      .find((candidate) => candidate.descriptor.id === input.descriptor.id);
    return resolveSettings(moduleState?.settings ?? {});
  };

  const handleDocumentResponse = async (
    details: chrome.webRequest.OnHeadersReceivedDetails
  ): Promise<void> => {
    const settings = getSettings();
    if (
      !settings.autoCaptureBrowsedDocuments ||
      details.method !== 'GET' ||
      details.tabId < 0 ||
      ['script', 'stylesheet', 'image', 'font', 'media'].includes(details.type)
    ) {
      return;
    }

    const candidate = detectDocumentCandidate(details.url, details.responseHeaders);
    if (!candidate) {
      return;
    }

    candidate.sourceTabId = details.tabId >= 0 ? details.tabId : undefined;
    const scopeDecision = input.host.evaluateTrafficScope(candidate.url, details.method);
    const acquire = scopeDecision.disposition === 'in-scope';
    if (!acquire) {
      let targetTabInScope = false;
      try {
        const tab = await chrome.tabs.get(details.tabId);
        if (/^https?:/i.test(tab.url ?? '')) {
          targetTabInScope =
            input.host.evaluateTrafficScope(tab.url!, 'GET').disposition === 'in-scope';
        }
      } catch {
        // A closed or replaced tab cannot establish target context for passive retention.
      }
      if (!targetTabInScope) {
        return;
      }
    }
    await recordCandidate(candidate, 'web-request', settings, acquire);
    if (!acquire) {
      input.logger.info('Retained document metadata without automatic retrieval', {
        host: getHostname(candidate.url) ?? null,
        scopeDisposition: scopeDecision.disposition,
        scopePolicyId: scopeDecision.policyId
      });
    }
  };

  const recordCandidate = async (
    candidate: DocumentCandidate,
    source: DocumentSource,
    settings: ResolvedDocumentAcquisitionSettings,
    acquire: boolean
  ): Promise<AcquiredDocument> => {
    const normalizedUrl = normalizeDocumentUrl(candidate.url);
    if (inFlightUrls.has(normalizedUrl)) {
      return (
        input.host
          .getDocumentWorkbenchState()
          .documents.find((document) => normalizeDocumentUrl(document.url) === normalizedUrl) ??
        createTransientDocument(candidate, source, input.host.getDocumentWorkbenchState())
      );
    }

    const timestamp = new Date().toISOString();
    const state = ensureDocumentWorkbench(input.host.getDocumentWorkbenchState());
    const activeSession = getActiveDocumentSession(state);
    const existing = state.documents.find(
      (document) =>
        document.sessionId === activeSession.id &&
        normalizeDocumentUrl(document.url) === normalizedUrl
    );
    const targetHost = getHostname(candidate.finalUrl ?? candidate.url);
    const blockedReason =
      candidate.contentLength !== undefined && candidate.contentLength > settings.maxDocumentBytes
        ? `Content-Length ${candidate.contentLength} exceeds maximum ${settings.maxDocumentBytes}.`
        : undefined;

    const nextDocument: AcquiredDocument = existing
      ? {
          ...existing,
          finalUrl: candidate.finalUrl ?? existing.finalUrl,
          targetHost: targetHost ?? existing.targetHost,
          sourcePageUrl: candidate.sourcePageUrl ?? existing.sourcePageUrl,
          sourceTabId: candidate.sourceTabId ?? existing.sourceTabId,
          filename: candidate.filename ?? existing.filename,
          mimeType: candidate.mimeType ?? existing.mimeType,
          contentEncoding: candidate.contentEncoding ?? existing.contentEncoding,
          byteLength: candidate.contentLength ?? existing.byteLength,
          lastSeenAt: timestamp,
          status:
            blockedReason && existing.status !== 'acquired'
              ? 'blocked'
              : existing.status === 'failed' && acquire
                ? 'queued'
                : existing.status
        }
      : {
          id: createId('doc'),
          sessionId: activeSession.id,
          url: candidate.url,
          finalUrl: candidate.finalUrl,
          targetHost,
          source,
          sourcePageUrl: candidate.sourcePageUrl,
          sourceTabId: candidate.sourceTabId,
          filename: candidate.filename ?? inferFilename(candidate.url, candidate.mimeType),
          mimeType: candidate.mimeType,
          contentEncoding: candidate.contentEncoding,
          byteLength: candidate.contentLength,
          firstSeenAt: timestamp,
          lastSeenAt: timestamp,
          status: blockedReason ? 'blocked' : acquire ? 'queued' : 'discovered',
          failureReason: blockedReason,
          queueReason: blockedReason ?? (acquire ? 'Observed while browsing; queued for in-memory inspection.' : 'Discovered and awaiting inspection.'),
          downloadDecision: 'review'
        };

    const nextDocuments = existing
      ? state.documents.map((document) => (document.id === existing.id ? nextDocument : document))
      : [nextDocument, ...state.documents].slice(0, 500);
    await saveDocumentWorkbench({
      ...state,
      documents: nextDocuments
    });

    if (
      acquire &&
      !blockedReason &&
      !['acquiring', 'acquired', 'reviewed', 'downloaded', 'duplicate'].includes(nextDocument.status)
    ) {
      void acquireDocument(nextDocument.id, settings).catch((error) => {
        input.logger.warn('Document acquisition failed', {
          url: nextDocument.url,
          error: toErrorDetails(error)
        });
      });
    }

    return nextDocument;
  };

  const acquireDocument = async (
    documentId: string,
    settings: ResolvedDocumentAcquisitionSettings
  ): Promise<void> => {
    const initialState = ensureDocumentWorkbench(input.host.getDocumentWorkbenchState());
    const document = initialState.documents.find((candidate) => candidate.id === documentId);
    if (!document) {
      return;
    }

    const normalizedUrl = normalizeDocumentUrl(document.url);
    if (inFlightUrls.has(normalizedUrl)) {
      return;
    }

    inFlightUrls.add(normalizedUrl);
    await updateDocument(documentId, {
      status: 'acquiring',
      failureReason: undefined
    });

    try {
      const scopedFetch = await fetchDocumentWithinScope(
        document.url,
        (rawUrl, method) => input.host.evaluateTrafficScope(rawUrl, method)
      );
      if (!scopedFetch.ok) {
        await updateDocument(documentId, {
          status: 'blocked',
          finalUrl: scopedFetch.blockedUrl,
          failureReason: scopedFetch.reason,
          queueReason: 'Automatic retrieval stopped at the executable scope boundary.'
        });
        return;
      }

      const { response, finalUrl } = scopedFetch;
      if (!response.ok) {
        throw new Error(`Document fetch returned HTTP ${response.status}`);
      }

      const buffer = await response.arrayBuffer();
      if (buffer.byteLength > settings.maxDocumentBytes) {
        await updateDocument(documentId, {
          status: 'blocked',
          byteLength: buffer.byteLength,
          failureReason: `Fetched document size ${buffer.byteLength} exceeds maximum ${settings.maxDocumentBytes}.`
        });
        return;
      }

      const mimeType = response.headers.get('content-type')?.split(';')[0]?.trim() || document.mimeType;
      const contentEncoding = response.headers.get('content-encoding') ?? document.contentEncoding;
      const filename =
        filenameFromContentDisposition(response.headers.get('content-disposition') ?? undefined) ??
        document.filename ??
        inferFilename(finalUrl, mimeType);
      const sha256 = await digestSha256(buffer);
      const duplicate = input.host
        .getDocumentWorkbenchState()
        .documents.find(
          (candidate) =>
            candidate.id !== documentId &&
            candidate.sha256 === sha256 &&
            ['acquired', 'reviewed', 'downloaded', 'duplicate'].includes(candidate.status)
        );
      const analysis = await analyzeDocument(buffer, {
        mimeType,
        contentEncoding,
        filename,
        keywords: parseInterestingKeywords(settings.interestingKeywords)
      });

      if (analysis.interestingKeywords.length > 0) {
        const interestScore = scoreDocumentAnalysis(analysis);
        try {
          const topHits = analysis.interestingKeywords
            .slice(0, 5)
            .map((hit) => `${hit.keyword} (${hit.count})`)
            .join(', ');
          await input.host.recordFinding({
            kind: 'document-hit',
            sourceModuleId: input.descriptor.id,
            host: getHostname(finalUrl),
            severity: 'warning',
            title: `Interesting keywords in ${filename}`,
            detail: `Matched: ${topHits}`,
            context: {
              documentId,
              url: document.url
            }
          });
          await input.host.recordIntelligenceFinding({
            kind: 'document',
            score: interestScore,
            title: `Review ${filename}`,
            summary: `BLANCHE inspected this document in memory and found ${analysis.interestingKeywords.length} interesting keyword group${analysis.interestingKeywords.length === 1 ? '' : 's'}.`,
            host: getHostname(finalUrl),
            evidence: [
              {
                label: 'Keyword evidence',
                detail: topHits,
                url: document.url
              },
              ...analysis.extractedUrls.slice(0, 5).map((url) => ({
                label: 'Extracted URL',
                detail: url,
                url: /^https?:/i.test(url) ? url : undefined
              }))
            ],
            context: { documentId },
            question: {
              prompt: `This document matched ${topHits}. Review it for the test report?`,
              reason: 'The question was raised from the document body analysis and its configured interesting terms.'
            }
          });
        } catch (error) {
          input.logger.warn('Failed to record document keyword-hit finding', {
            url: document.url,
            error: toErrorDetails(error)
          });
        }
      }

      if (duplicate) {
        await updateDocument(documentId, {
          status: 'duplicate',
          finalUrl,
          filename,
          mimeType,
          contentEncoding,
          byteLength: buffer.byteLength,
          sha256,
          acquiredAt: new Date().toISOString(),
          analysis,
          failureReason: `Duplicate of ${duplicate.filename ?? duplicate.url}`
        });
        return;
      }

      const interestScore = scoreDocumentAnalysis(analysis);
      const matchedDownloadRule = analysis.interestingKeywords.some((hit) =>
        parseInterestingKeywords(settings.downloadRuleKeywords).includes(hit.keyword.toLowerCase())
      );
      const automaticDownloadSuppressed =
        settings.autoDownloadDocuments &&
        matchedDownloadRule &&
        interestScore >= settings.autoDownloadScoreThreshold;
      if (automaticDownloadSuppressed) {
        input.logger.info('Retained rule-matched document for explicit download approval', {
          host: getHostname(finalUrl) ?? null,
          interestScore,
          reason: 'Browser download redirects cannot be evaluated before the network request.'
        });
      }
      await updateDocument(documentId, {
        status: 'reviewed',
        finalUrl,
        filename,
        mimeType,
        contentEncoding,
        byteLength: buffer.byteLength,
        sha256,
        acquiredAt: new Date().toISOString(),
        analysis,
        interestScore,
        queueReason: automaticDownloadSuppressed
          ? `Matched the automatic download rule at score ${interestScore}, but browser download redirects cannot be scope-checked; explicit tester approval is required.`
          : `Inspected in memory; score ${interestScore}. Filesystem download awaits approval.`,
        downloadDecision: 'not-downloaded',
        failureReason: undefined
      });
    } catch (error) {
      await updateDocument(documentId, {
        status: 'failed',
        failureReason: error instanceof Error ? error.message : String(error)
      });
    } finally {
      inFlightUrls.delete(normalizedUrl);
    }
  };

  const updateDocument = async (
    documentId: string,
    patch: Partial<AcquiredDocument>
  ): Promise<void> => {
    const state = ensureDocumentWorkbench(input.host.getDocumentWorkbenchState());
    await saveDocumentWorkbench({
      ...state,
      documents: state.documents.map((document) =>
        document.id === documentId
          ? {
              ...document,
              ...patch,
              lastSeenAt: new Date().toISOString()
            }
          : document
      )
    });
  };

  const saveDocumentWorkbench = async (state: DocumentWorkbenchState): Promise<void> => {
    await input.host.updateDocumentWorkbenchState(recalculateDocumentSessionCounts(state));
  };

  return {
    async onHostStart() {
      registerListener();
      input.logger.info('Document Acquisition background controller ready');
    },
    async onModuleEnabled() {
      registerListener();
    },
    async onModuleDisabled() {
      unregisterListener();
    },
    async runAction(request, context) {
      const settings = resolveSettings(context.settings);
      switch (request.actionId) {
        case 'startSession':
          return startDocumentSession(request.input, context);
        case 'launchDocumentSearches':
          return launchDocumentSearches(request.tabId, request.input, context);
        case 'scanCurrentPageLinks':
          return scanCurrentPageLinks(request.tabId, settings, recordCandidate, context);
        case 'openSessionFolder':
          return openSessionFolder(context);
        case 'downloadDocument': {
          const documentId = typeof request.input?.documentId === 'string' ? request.input.documentId : undefined;
          if (!documentId) return { status: 'error', message: 'Choose a reviewed document to download.' };
          const state = ensureDocumentWorkbench(context.services.getDocumentWorkbenchState());
          const document = state.documents.find((entry) => entry.id === documentId);
          if (!document) return { status: 'error', message: 'The selected document is no longer in the queue.' };
          const session = state.sessions.find((entry) => entry.id === document.sessionId) ?? getActiveDocumentSession(state);
          const filename = document.filename ?? inferFilename(document.url, document.mimeType);
          const downloadFilename = buildDownloadPath(session, settings, filename);
          const downloadId = await downloadDocument(document, downloadFilename);
          await updateDocument(document.id, {
            status: downloadId === undefined ? document.status : 'downloaded',
            downloadId,
            downloadFilename: downloadId === undefined ? undefined : downloadFilename,
            downloadDecision: 'manual',
            queueReason: downloadId === undefined ? 'Browser download API was unavailable.' : 'Downloaded after tester approval.'
          });
          return downloadId === undefined
            ? { status: 'error', message: 'The browser download API was unavailable.' }
            : { status: 'ok', message: `Downloading ${filename}.` };
        }
        case 'clearDocuments':
          await context.services.updateDocumentWorkbenchState(createDefaultDocumentWorkbenchState());
          return {
            status: 'ok',
            message: 'Cleared document inventory and started a clean document session.'
          };
        default:
          return {
            status: 'error',
            message: `Unsupported document acquisition action: ${request.actionId}`
          };
      }
    }
  };
}

function resolveSettings(rawSettings: Record<string, JsonValue>): ResolvedDocumentAcquisitionSettings {
  return {
    autoCaptureBrowsedDocuments: rawSettings.autoCaptureBrowsedDocuments !== false,
    autoDownloadDocuments: rawSettings.autoDownloadDocuments === true,
    autoDownloadScoreThreshold:
      typeof rawSettings.autoDownloadScoreThreshold === 'number'
        ? Math.max(0, Math.min(100, rawSettings.autoDownloadScoreThreshold))
        : 60,
    downloadRuleKeywords:
      typeof rawSettings.downloadRuleKeywords === 'string'
        ? rawSettings.downloadRuleKeywords
        : 'credential, secret, token, api_key, client_secret, private key, confidential, restricted',
    maxDocumentBytes:
      typeof rawSettings.maxDocumentBytes === 'number' && rawSettings.maxDocumentBytes > 0
        ? rawSettings.maxDocumentBytes
        : 52_428_800,
    downloadFolderRoot:
      typeof rawSettings.downloadFolderRoot === 'string' && rawSettings.downloadFolderRoot.trim()
        ? rawSettings.downloadFolderRoot.trim()
        : 'BLANCHE',
    interestingKeywords:
      typeof rawSettings.interestingKeywords === 'string' && rawSettings.interestingKeywords.trim()
        ? rawSettings.interestingKeywords
        : DEFAULT_DOCUMENT_KEYWORDS
  };
}

async function startDocumentSession(
  input: JsonObject | undefined,
  context: ModuleActionContext
): Promise<ModuleActionResult> {
  const state = ensureDocumentWorkbench(context.services.getDocumentWorkbenchState());
  const label =
    typeof input?.label === 'string' && input.label.trim()
      ? input.label.trim()
      : undefined;
  const session = createDocumentSession(label);
  await context.services.updateDocumentWorkbenchState({
    ...state,
    activeSessionId: session.id,
    sessions: [session, ...state.sessions].slice(0, 30)
  });

  return {
    status: 'ok',
    message: `Started document session ${session.label}.`,
    data: {
      sessionId: session.id,
      folderName: session.folderName
    }
  };
}

async function launchDocumentSearches(
  tabId: number | undefined,
  input: JsonObject | undefined,
  context: ModuleActionContext
): Promise<ModuleActionResult> {
  const target =
    typeof input?.target === 'string' && input.target.trim()
      ? normalizeTarget(input.target)
      : await getTabHostname(tabId);
  if (!target) {
    return {
      status: 'error',
      message: 'No target hostname is available for indexed document searches.'
    };
  }

  const tab = tabId ? await chrome.tabs.get(tabId) : undefined;
  const urls = DOCUMENT_SEARCH_QUERIES.map((query) => {
    const searchUrl = new URL('https://www.google.com/search');
    searchUrl.searchParams.set('q', `site:${target} ${query}`);
    return searchUrl.toString();
  });

  for (const [index, url] of urls.entries()) {
    await chrome.tabs.create({
      url,
      active: false,
      windowId: tab?.windowId,
      index: tab?.index !== undefined ? tab.index + index + 1 : undefined
    });
  }

  return {
    status: 'ok',
    message: `Opened ${urls.length} indexed document search tabs for ${target}.`,
    data: {
      target,
      searchCount: urls.length
    }
  };
}

async function scanCurrentPageLinks(
  tabId: number | undefined,
  settings: ResolvedDocumentAcquisitionSettings,
  recordCandidate: (
    candidate: DocumentCandidate,
    source: DocumentSource,
    settings: ResolvedDocumentAcquisitionSettings,
    acquire: boolean
  ) => Promise<AcquiredDocument>,
  context: ModuleActionContext
): Promise<ModuleActionResult> {
  if (!tabId) {
    return {
      status: 'error',
      message: 'Document link scan requires a target tab.'
    };
  }

  try {
    const [result] = await chrome.scripting.executeScript({
      target: {
        tabId,
        allFrames: false
      },
      func: collectDocumentLinksFromPage,
      args: [[...DOCUMENT_EXTENSIONS]]
    });
    const links = ((result?.result ?? []) as PageDocumentLink[]).slice(0, 200);
    const tab = await chrome.tabs.get(tabId);

    let scopeRetainedCount = 0;
    for (const link of links) {
      const scopeDecision = context.services.evaluateTrafficScope(link.url, 'GET');
      const acquire =
        settings.autoCaptureBrowsedDocuments && scopeDecision.disposition === 'in-scope';
      await recordCandidate(
        {
          url: link.url,
          sourcePageUrl: tab.url,
          sourceTabId: tabId,
          filename: inferFilename(link.url)
        },
        'current-page-link',
        settings,
        acquire
      );
      if (settings.autoCaptureBrowsedDocuments && !acquire) {
        scopeRetainedCount += 1;
        context.logger.info('Retained page document link without automatic retrieval', {
          host: getHostname(link.url) ?? null,
          scopeDisposition: scopeDecision.disposition,
          scopePolicyId: scopeDecision.policyId
        });
      }
    }

    return {
      status: 'ok',
      message: `Discovered ${links.length} document link${links.length === 1 ? '' : 's'} on the current page.`,
      data: {
        linkCount: links.length,
        scopeRetainedCount
      }
    };
  } catch (error) {
    context.logger.warn('Document link scan failed', {
      error: toErrorDetails(error)
    });
    return {
      status: 'error',
      message: error instanceof Error ? error.message : String(error)
    };
  }
}

async function fetchDocumentWithinScope(
  initialUrl: string,
  evaluateTrafficScope: ModuleHostServices['evaluateTrafficScope']
): Promise<ScopedDocumentFetchResult> {
  const visited = new Set<string>();
  let currentUrl = initialUrl;

  for (let redirectCount = 0; redirectCount <= MAX_SCOPED_REDIRECT_HOPS; redirectCount += 1) {
    if (visited.has(currentUrl)) {
      return {
        ok: false,
        blockedUrl: currentUrl,
        reason: `Automatic document retrieval stopped at ${currentUrl}: redirect loop detected.`
      };
    }
    visited.add(currentUrl);

    const scopeDecision = evaluateTrafficScope(currentUrl, 'GET');
    if (scopeDecision.disposition !== 'in-scope') {
      return {
        ok: false,
        blockedUrl: currentUrl,
        reason: `Automatic document retrieval stopped before ${currentUrl}: ${scopeDecision.disposition} under scope policy ${scopeDecision.policyId}.`
      };
    }

    const response = await fetch(currentUrl, {
      credentials: 'omit',
      redirect: 'manual'
    });
    if (response.type === 'opaqueredirect') {
      return {
        ok: false,
        blockedUrl: currentUrl,
        reason: `Automatic document retrieval stopped at ${currentUrl}: the redirect destination was opaque and could not be scope-checked.`
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
        reason: `Automatic document retrieval stopped at ${currentUrl}: the redirect destination was not exposed for scope evaluation.`
      };
    }
    if (redirectCount === MAX_SCOPED_REDIRECT_HOPS) {
      return {
        ok: false,
        blockedUrl: currentUrl,
        reason: `Automatic document retrieval stopped at ${currentUrl}: redirect chain exceeded ${MAX_SCOPED_REDIRECT_HOPS} hops.`
      };
    }

    currentUrl = new URL(location, currentUrl).toString();
  }

  return {
    ok: false,
    blockedUrl: currentUrl,
    reason: `Automatic document retrieval stopped for ${initialUrl}: redirect chain could not be resolved.`
  };
}

async function openSessionFolder(context: ModuleActionContext): Promise<ModuleActionResult> {
  const state = ensureDocumentWorkbench(context.services.getDocumentWorkbenchState());
  const session = getActiveDocumentSession(state);
  const downloadId =
    session.lastDownloadId ??
    [...state.documents]
      .reverse()
      .find((document) => document.sessionId === session.id && typeof document.downloadId === 'number')
      ?.downloadId;

  if (typeof downloadId === 'number') {
    chrome.downloads.show(downloadId);
    return {
      status: 'ok',
      message: `Opened the containing folder for ${session.label}.`
    };
  }

  chrome.downloads.showDefaultFolder();
  return {
    status: 'partial',
    message: 'No session document has been downloaded yet, so the default downloads folder was opened.'
  };
}

function detectDocumentCandidate(
  url: string,
  responseHeaders: chrome.webRequest.HttpHeader[] | undefined
): DocumentCandidate | undefined {
  if (!/^https?:/i.test(url)) {
    return undefined;
  }

  const headers = parseHeaders(responseHeaders);
  const mimeType = headers.contentType?.split(';')[0]?.trim().toLowerCase();
  const extension = getUrlExtension(url);
  const dispositionFilename = filenameFromContentDisposition(headers.contentDisposition);
  const hasAttachment = /attachment/i.test(headers.contentDisposition ?? '');
  const extensionLooksDocument = Boolean(extension && DOCUMENT_EXTENSIONS.has(extension));
  const genericTextMime = Boolean(
    mimeType && ['text/plain', 'application/json', 'application/xml', 'text/xml'].includes(mimeType)
  );
  const mimeLooksDocument = Boolean(
    mimeType &&
    DOCUMENT_MIME_PREFIXES.some((prefix) => mimeType.startsWith(prefix)) &&
    (!genericTextMime || extensionLooksDocument || hasAttachment || dispositionFilename)
  );

  if (!hasAttachment && !mimeLooksDocument && !extensionLooksDocument && !dispositionFilename) {
    return undefined;
  }

  return {
    url,
    mimeType,
    contentEncoding: headers.contentEncoding,
    contentLength: headers.contentLength,
    filename: dispositionFilename ?? inferFilename(url, mimeType)
  };
}

function collectDocumentLinksFromPage(extensions: string[]): PageDocumentLink[] {
  const extensionSet = new Set(extensions);
  const output = new Map<string, PageDocumentLink>();
  const isDocumentUrl = (rawUrl: string): boolean => {
    try {
      const parsed = new URL(rawUrl, location.href);
      const extension = parsed.pathname.split('.').at(-1)?.toLowerCase() ?? '';
      return extensionSet.has(extension);
    } catch {
      return false;
    }
  };
  const expandCandidateUrls = (rawUrl: string): string[] => {
    const candidates = new Set<string>();
    try {
      const parsed = new URL(rawUrl, location.href);
      candidates.add(parsed.toString());
      for (const key of ['q', 'url', 'u']) {
        const nested = parsed.searchParams.get(key);
        if (!nested) {
          continue;
        }

        try {
          candidates.add(new URL(nested, location.href).toString());
        } catch {
          candidates.add(nested);
        }
      }
    } catch {
      candidates.add(rawUrl);
    }

    return [...candidates];
  };

  for (const anchor of Array.from(document.querySelectorAll<HTMLAnchorElement>('a[href]'))) {
    const href = anchor.href;
    const documentUrl = expandCandidateUrls(href).find((candidate) => isDocumentUrl(candidate));
    if (!href || !documentUrl) {
      continue;
    }

    output.set(documentUrl, {
      url: documentUrl,
      text: anchor.textContent?.trim().slice(0, 160)
    });
  }

  return [...output.values()];
}

async function analyzeDocument(
  buffer: ArrayBuffer,
  input: {
    mimeType?: string;
    contentEncoding?: string;
    filename?: string;
    keywords: string[];
  }
): Promise<DocumentAnalysis> {
  const bytes = new Uint8Array(buffer);
  const compressionTypes = new Set<string>();
  const notes: string[] = [];

  if (input.contentEncoding) {
    compressionTypes.add(`http-content-encoding:${input.contentEncoding.toLowerCase()}`);
  }

  const signatureCompression = detectCompressionBySignature(bytes, input.mimeType, input.filename);
  for (const entry of signatureCompression) {
    compressionTypes.add(entry);
  }

  const textParts = [decodeBytesForAnalysis(bytes)];
  if (compressionTypes.has('zip-container')) {
    const zipText = await extractZipText(bytes, notes);
    if (zipText) {
      textParts.push(zipText);
    }
  }

  const text = textParts.join('\n').slice(0, MAX_ANALYSIS_TEXT_BYTES);
  const extractedUrls = extractUrls(text).slice(0, MAX_EXTRACTED_URLS);
  const interestingKeywords = countKeywords(text, input.keywords);

  if (input.mimeType?.includes('pdf') || input.filename?.toLowerCase().endsWith('.pdf')) {
    const pdfFilters = extractPdfFilters(text);
    for (const filter of pdfFilters) {
      compressionTypes.add(`pdf-filter:${filter}`);
    }
  }

  if (compressionTypes.size === 0) {
    compressionTypes.add('none-detected');
  }

  return {
    compressionTypes: [...compressionTypes].sort(),
    extractedUrls,
    interestingKeywords,
    scannedTextBytes: text.length,
    notes
  };
}

async function extractZipText(bytes: Uint8Array, notes: string[]): Promise<string> {
  const textParts: string[] = [];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;
  let entries = 0;

  while (offset + 30 < bytes.byteLength && entries < MAX_ZIP_ENTRIES) {
    if (view.getUint32(offset, true) !== 0x04034b50) {
      break;
    }

    const flags = view.getUint16(offset + 6, true);
    const method = view.getUint16(offset + 8, true);
    const compressedSize = view.getUint32(offset + 18, true);
    const fileNameLength = view.getUint16(offset + 26, true);
    const extraLength = view.getUint16(offset + 28, true);
    const nameStart = offset + 30;
    const dataStart = nameStart + fileNameLength + extraLength;
    const dataEnd = dataStart + compressedSize;
    const fileName = decodeBytesForAnalysis(bytes.slice(nameStart, nameStart + fileNameLength));

    if ((flags & 0x08) !== 0 || compressedSize === 0 || dataEnd > bytes.byteLength) {
      notes.push(`Skipped ZIP entry ${fileName || entries + 1}; local header did not expose a bounded payload.`);
      break;
    }

    const payload = bytes.slice(dataStart, dataEnd);
    const looksTextual =
      /\.(xml|rels|txt|csv|json|html?)$/i.test(fileName) ||
      fileName.includes('word/') ||
      fileName.includes('xl/') ||
      fileName.includes('ppt/');
    if (looksTextual) {
      if (method === 0) {
        textParts.push(decodeBytesForAnalysis(payload));
      } else if (method === 8) {
        const inflated = await inflateRaw(payload);
        if (inflated) {
          textParts.push(decodeBytesForAnalysis(inflated));
        }
      }
    }

    offset = dataEnd;
    entries += 1;
  }

  if (entries >= MAX_ZIP_ENTRIES) {
    notes.push(`ZIP analysis stopped after ${MAX_ZIP_ENTRIES} local entries.`);
  }

  return textParts.join('\n').slice(0, MAX_ANALYSIS_TEXT_BYTES);
}

async function inflateRaw(payload: Uint8Array): Promise<Uint8Array | undefined> {
  try {
    if (!('DecompressionStream' in globalThis)) {
      return undefined;
    }

    const body = copyToArrayBuffer(payload);
    const stream = new Response(body).body?.pipeThrough(
      new DecompressionStream('deflate-raw' as CompressionFormat)
    );
    if (!stream) {
      return undefined;
    }

    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch {
    return undefined;
  }
}

function extractUrls(text: string): string[] {
  const urls = new Set<string>();
  const patterns = [
    /\b[a-z][a-z0-9+.-]{1,31}:\/\/[^\s<>"'`{}|\\^()[\]]+/gi,
    /\bmailto:[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi,
    /\bwww\.[^\s<>"'`{}|\\^()[\]]+/gi,
    /\\\\[a-z0-9._$-]+\\[^\s<>"'`{}|]+/gi
  ];

  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      const value = trimUrlTail(match[0]);
      if (value.length >= 4 && isPlausibleExtractedUrl(value)) {
        urls.add(value);
      }
    }
  }

  return [...urls].sort();
}

function isPlausibleExtractedUrl(value: string): boolean {
  if (/^https?:/i.test(value)) {
    try {
      const parsed = new URL(value);
      return parsed.hostname === 'localhost' || parsed.hostname.includes('.');
    } catch {
      return false;
    }
  }
  if (/^www\./i.test(value)) {
    return value.slice(4).includes('.');
  }
  return /^mailto:/i.test(value) || /^\\\\[^\\\s]+\\[^\s]+/.test(value);
}

function countKeywords(text: string, keywords: string[]): Array<{ keyword: string; count: number }> {
  const lowerText = text.toLowerCase();
  return keywords
    .map((keyword) => ({
      keyword,
      count: countOccurrences(lowerText, keyword.toLowerCase())
    }))
    .filter((hit) => hit.count > 0)
    .sort((left, right) => right.count - left.count || left.keyword.localeCompare(right.keyword))
    .slice(0, 50);
}

function countOccurrences(text: string, needle: string): number {
  if (!needle) {
    return 0;
  }

  if (/^[a-z0-9_]+$/i.test(needle)) {
    const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return [...text.matchAll(new RegExp(`\\b${escaped}\\b`, 'gi'))].length;
  }

  let count = 0;
  let offset = 0;
  while (offset < text.length) {
    const index = text.indexOf(needle, offset);
    if (index < 0) {
      break;
    }

    count += 1;
    offset = index + needle.length;
  }

  return count;
}

function scoreDocumentAnalysis(analysis: DocumentAnalysis): number {
  const distinctKeywordScore = Math.min(60, analysis.interestingKeywords.length * 12);
  const occurrenceScore = Math.min(
    25,
    analysis.interestingKeywords.reduce((sum, hit) => sum + hit.count, 0) * 2
  );
  const extractedUrlScore = Math.min(10, analysis.extractedUrls.length * 2);
  const archiveScore = analysis.compressionTypes.some((entry) => entry !== 'none-detected') ? 5 : 0;
  return Math.min(100, distinctKeywordScore + occurrenceScore + extractedUrlScore + archiveScore);
}

function detectCompressionBySignature(
  bytes: Uint8Array,
  mimeType?: string,
  filename?: string
): string[] {
  const output = new Set<string>();
  const lowerName = filename?.toLowerCase() ?? '';
  const lowerMime = mimeType?.toLowerCase() ?? '';

  if (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) {
    output.add('zip-container');
  }
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    output.add('gzip');
  }
  if (bytes[0] === 0x52 && bytes[1] === 0x61 && bytes[2] === 0x72 && bytes[3] === 0x21) {
    output.add('rar');
  }
  if (
    bytes[0] === 0x37 &&
    bytes[1] === 0x7a &&
    bytes[2] === 0xbc &&
    bytes[3] === 0xaf &&
    bytes[4] === 0x27 &&
    bytes[5] === 0x1c
  ) {
    output.add('7z');
  }
  if (lowerName.endsWith('.docx') || lowerName.endsWith('.xlsx') || lowerName.endsWith('.pptx')) {
    output.add('office-openxml-zip-container');
  }
  if (lowerMime.includes('zip')) {
    output.add('zip-container');
  }
  if (lowerMime.includes('gzip')) {
    output.add('gzip');
  }

  return [...output];
}

function extractPdfFilters(text: string): string[] {
  const filters = new Set<string>();
  for (const match of text.matchAll(/\/([A-Za-z0-9]+Decode)\b/g)) {
    filters.add(match[1] ?? '');
  }

  return [...filters].filter(Boolean).sort();
}

function decodeBytesForAnalysis(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', {
    fatal: false
  }).decode(bytes.slice(0, MAX_ANALYSIS_TEXT_BYTES));
}

function copyToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

async function digestSha256(buffer: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function downloadDocument(
  document: AcquiredDocument,
  downloadPath: string
): Promise<number | undefined> {
  if (!chrome.downloads?.download) {
    return undefined;
  }

  return chrome.downloads.download({
    url: document.url,
    filename: downloadPath,
    conflictAction: 'uniquify',
    saveAs: false
  });
}

function buildDownloadPath(
  session: { folderName: string },
  settings: ResolvedDocumentAcquisitionSettings,
  filename: string
): string {
  return [
    sanitizePathSegment(settings.downloadFolderRoot),
    sanitizePathSegment(session.folderName),
    sanitizeFilename(filename)
  ].join('/');
}

function parseHeaders(headers: chrome.webRequest.HttpHeader[] | undefined): HeaderMap {
  const getHeader = (name: string): string | undefined =>
    headers?.find((header) => header.name.toLowerCase() === name)?.value;
  const contentLengthRaw = getHeader('content-length');
  const contentLength = contentLengthRaw ? Number(contentLengthRaw) : undefined;

  return {
    contentType: getHeader('content-type'),
    contentDisposition: getHeader('content-disposition'),
    contentEncoding: getHeader('content-encoding'),
    contentLength: Number.isFinite(contentLength) ? contentLength : undefined
  };
}

function filenameFromContentDisposition(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }

  const utfMatch = /filename\*=UTF-8''([^;]+)/i.exec(value);
  if (utfMatch?.[1]) {
    return sanitizeFilename(decodeURIComponentSafe(utfMatch[1]));
  }

  const quotedMatch = /filename="([^"]+)"/i.exec(value);
  if (quotedMatch?.[1]) {
    return sanitizeFilename(quotedMatch[1]);
  }

  const bareMatch = /filename=([^;]+)/i.exec(value);
  if (bareMatch?.[1]) {
    return sanitizeFilename(bareMatch[1].trim());
  }

  return undefined;
}

function inferFilename(rawUrl: string, mimeType?: string): string {
  try {
    const parsed = new URL(rawUrl);
    const pathName = decodeURIComponentSafe(parsed.pathname.split('/').filter(Boolean).at(-1) ?? '');
    if (pathName && pathName.includes('.')) {
      return sanitizeFilename(pathName);
    }
  } catch {
    // fall through to generated filename
  }

  const extension = extensionFromMimeType(mimeType) ?? 'bin';
  return `document-${Date.now().toString(36)}.${extension}`;
}

function extensionFromMimeType(mimeType?: string): string | undefined {
  switch (mimeType?.toLowerCase()) {
    case 'application/pdf':
      return 'pdf';
    case 'text/csv':
      return 'csv';
    case 'text/plain':
      return 'txt';
    case 'application/json':
      return 'json';
    case 'application/xml':
    case 'text/xml':
      return 'xml';
    case 'application/zip':
      return 'zip';
    default:
      return undefined;
  }
}

function sanitizeFilename(rawValue: string): string {
  const stripped = rawValue.split(/[\\/]/g).at(-1) ?? rawValue;
  const sanitized = stripped
    .trim()
    .replace(/[<>:"/\\|?*\u0000-\u001f]+/g, '-')
    .replace(/\s+/g, ' ')
    .replace(/^\.+/g, '')
    .slice(0, 160);

  return sanitized || `document-${Date.now().toString(36)}.bin`;
}

function getUrlExtension(rawUrl: string): string | undefined {
  try {
    const parsed = new URL(rawUrl);
    return parsed.pathname.split('.').at(-1)?.toLowerCase();
  } catch {
    return undefined;
  }
}

function getHostname(rawUrl: string | undefined): string | undefined {
  if (!rawUrl) {
    return undefined;
  }

  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

async function getTabHostname(tabId: number | undefined): Promise<string | undefined> {
  if (!tabId) {
    return undefined;
  }

  const tab = await chrome.tabs.get(tabId);
  return getHostname(tab.url);
}

function normalizeTarget(value: string): string | undefined {
  const trimmed = value.trim();
  try {
    return new URL(trimmed).hostname.toLowerCase();
  } catch {
    return trimmed.replace(/^https?:\/\//i, '').split('/')[0]?.toLowerCase();
  }
}

function normalizeDocumentUrl(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    parsed.hash = '';
    return parsed.toString();
  } catch {
    return rawUrl;
  }
}

function trimUrlTail(value: string): string {
  return value.replace(/[.,;:!?)}\]"']+$/g, '');
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function ensureDocumentWorkbench(state: DocumentWorkbenchState): DocumentWorkbenchState {
  return normalizeDocumentWorkbenchState(state);
}

function createTransientDocument(
  candidate: DocumentCandidate,
  source: DocumentSource,
  state: DocumentWorkbenchState
): AcquiredDocument {
  const timestamp = new Date().toISOString();
  return {
    id: createId('doc'),
    sessionId: getActiveDocumentSession(state).id,
    url: candidate.url,
    source,
    firstSeenAt: timestamp,
    lastSeenAt: timestamp,
    status: 'queued'
  };
}
