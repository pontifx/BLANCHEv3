import type { ContentInstrumentationResponse, InstrumentationSnapshot } from '../modules/burpBridge/types';

type PageBridgeMessage =
  | {
      __blanche: 'burp-bridge';
      type: 'instrumentation-event';
      payload: InstrumentationSnapshot['events'][number];
    }
  | {
      __blanche: 'burp-bridge';
      type: 'instrumentation-ready';
      payload: {
        startedAt: string;
      };
    }
  | {
      __blanche: 'burp-bridge';
      type: 'instrumentation-snapshot-response';
      payload: {
        requestId: string;
        snapshot: InstrumentationSnapshot;
      };
    };

const state = {
  instrumented: false,
  warnings: [] as string[],
  liveEvents: [] as InstrumentationSnapshot['events'],
  startedAt: undefined as string | undefined,
  droppedLiveEventCount: 0
};

const PAGE_WORLD_INTEGRITY_WARNING =
  'Page-world instrumentation is unverified: same-window postMessage evidence can be fabricated or suppressed by the inspected page.';

function sanitizeBridgeUrl(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl, location.href);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return `${parsed.protocol}${parsed.protocol === 'blob:' ? '[redacted]' : ''}`;
    }
    parsed.username = '';
    parsed.password = '';
    parsed.hash = '';
    const names = [...new Set([...parsed.searchParams.keys()])].sort();
    parsed.search = names.length > 0
      ? `?${names.map((name) => `${encodeURIComponent(name)}=`).join('&')}`
      : '';
    return parsed.toString();
  } catch {
    return '[unparseable-url]';
  }
}

function sanitizeBridgeText(value: string, maxLength = 500): string {
  return value
    .replace(/https?:\/\/[^\s"'<>]+/gi, (url) => sanitizeBridgeUrl(url))
    .replace(/(\/\/)[^/\s:@]+:[^@\s/]+@/g, '$1[redacted-credentials]@')
    .replace(/([?&][A-Za-z0-9_.~%-]{1,100})=([^&#\s]*)/g, '$1=[redacted]')
    .replace(/#[^\s"'<>]*/g, '#[redacted]')
    .replace(/\b(bearer)\s+[A-Za-z0-9._~+/=-]+/gi, '$1 [redacted]')
    .replace(
      /\b(password|passwd|secret|access[-_]?token|refresh[-_]?token|authorization|api[-_]?key|session[-_]?id|cookie)\s*[:=]\s*[^\s,;]+/gi,
      '$1=[redacted]'
    )
    .slice(0, maxLength);
}

function isBridgeUrlAttribute(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
  return (
    normalized.endsWith('url') ||
    normalized.endsWith('uri') ||
    normalized.endsWith('href') ||
    normalized.endsWith('src') ||
    normalized === 'endpoint' ||
    normalized === 'location' ||
    normalized === 'referrer' ||
    normalized === 'initiator'
  );
}

function sanitizeBridgeAttributes(
  attributes: InstrumentationSnapshot['events'][number]['attributes'],
  redactStrings: boolean
): InstrumentationSnapshot['events'][number]['attributes'] {
  const visit = (key: string, value: unknown, depth: number): unknown => {
    if (value === undefined || value === null) return value;
    if (isBridgeUrlAttribute(key) && typeof value === 'string') {
      return sanitizeBridgeUrl(value);
    }
    if (depth >= 5) return '[depth-limit]';
    if (Array.isArray(value)) {
      return value.slice(0, 100).map((entry) => visit(key, entry, depth + 1));
    }
    if (typeof value === 'object') {
      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>)
          .slice(0, 100)
          .map(([childKey, entry]) => [childKey, visit(childKey, entry, depth + 1)])
      );
    }
    if (redactStrings && typeof value === 'string') {
      return sanitizeBridgeText(value);
    }
    return value;
  };

  return Object.fromEntries(
    Object.entries(attributes)
      .slice(0, 100)
      .map(([key, value]) => [key, visit(key, value, 0)])
  ) as InstrumentationSnapshot['events'][number]['attributes'];
}

function sanitizeBridgeEvent(
  event: InstrumentationSnapshot['events'][number]
): InstrumentationSnapshot['events'][number] {
  return {
    ...event,
    pageUrl: event.pageUrl ? sanitizeBridgeUrl(event.pageUrl) : undefined,
    frameHref: event.frameHref ? sanitizeBridgeUrl(event.frameHref) : undefined,
    url: event.url ? sanitizeBridgeUrl(event.url) : undefined,
    attributes: sanitizeBridgeAttributes(
      event.attributes,
      event.type === 'runtime-error' || event.type === 'unhandled-rejection'
    )
  };
}

function sanitizeBridgeSnapshot(snapshot: InstrumentationSnapshot): InstrumentationSnapshot {
  return {
    ...snapshot,
    pageUrl: snapshot.pageUrl ? sanitizeBridgeUrl(snapshot.pageUrl) : undefined,
    events: snapshot.events.slice(0, 400).map(sanitizeBridgeEvent),
    warnings: snapshot.warnings.slice(0, 100).map((warning) => sanitizeBridgeText(warning))
  };
}

const pendingRequests = new Map<
  string,
  {
    resolve: (response: ContentInstrumentationResponse) => void;
    timeout: number;
  }
>();

window.addEventListener('message', (event: MessageEvent<PageBridgeMessage>) => {
  if (event.source !== window || !event.data || event.data.__blanche !== 'burp-bridge') {
    return;
  }

  switch (event.data.type) {
    case 'instrumentation-event':
      state.liveEvents.unshift(sanitizeBridgeEvent(event.data.payload));
      if (state.liveEvents.length > 300) {
        state.droppedLiveEventCount += state.liveEvents.length - 300;
        state.liveEvents.length = 300;
      }
      break;
    case 'instrumentation-ready':
      state.instrumented = true;
      state.startedAt = event.data.payload.startedAt;
      break;
    case 'instrumentation-snapshot-response': {
      const pending = pendingRequests.get(event.data.payload.requestId);
      if (!pending) {
        break;
      }

      window.clearTimeout(pending.timeout);
      pendingRequests.delete(event.data.payload.requestId);
      pending.resolve({
        instrumented: true,
        integrity: 'page-world-unverified',
        frameUrl: sanitizeBridgeUrl(location.href),
        topFrame: window.top === window,
        snapshot: sanitizeBridgeSnapshot(event.data.payload.snapshot),
        warnings: [...state.warnings, PAGE_WORLD_INTEGRITY_WARNING]
      });
      break;
    }
    default:
      break;
  }
});

ensureInstrumentorInjected();

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (
    !message ||
    typeof message !== 'object' ||
    message.channel !== 'blanche-burp-bridge' ||
    message.type !== 'content/getInstrumentationSnapshot'
  ) {
    return false;
  }

  void requestInstrumentationSnapshot().then(sendResponse);
  return true;
});

function ensureInstrumentorInjected(): void {
  if (document.documentElement?.hasAttribute('data-blanche-burp-bridge')) {
    return;
  }

  const inject = () => {
    if (document.documentElement?.hasAttribute('data-blanche-burp-bridge')) {
      return;
    }

    const host = document.head ?? document.documentElement;
    if (!host) {
      state.warnings.push('Unable to inject page instrumentor before document root was available.');
      return;
    }

    const instrumentorPath = resolveInstrumentorPath();
    if (!instrumentorPath) {
      state.warnings.push('Page instrumentor is not exposed in web_accessible_resources.');
      return;
    }

    const script = document.createElement('script');
    script.src = chrome.runtime.getURL(instrumentorPath);
    script.async = false;
    script.dataset.blanche = 'burp-bridge';
    host.prepend(script);
    document.documentElement?.setAttribute('data-blanche-burp-bridge', 'true');
    script.addEventListener('load', () => script.remove(), { once: true });
    script.addEventListener(
      'error',
      () => {
        state.warnings.push('Failed to load page instrumentor script.');
      },
      { once: true }
    );
  };

  if (document.documentElement) {
    inject();
    return;
  }

  document.addEventListener('readystatechange', inject, { once: true });
}

function resolveInstrumentorPath(): string | undefined {
  const manifest = chrome.runtime.getManifest();
  for (const entry of manifest.web_accessible_resources ?? []) {
    if (typeof entry === 'string') {
      if (entry.endsWith('pageInstrumentor.js')) {
        return entry;
      }
      continue;
    }

    for (const resource of entry.resources ?? []) {
      if (resource.endsWith('pageInstrumentor.js')) {
        return resource;
      }
    }
  }

  return undefined;
}

async function requestInstrumentationSnapshot(): Promise<ContentInstrumentationResponse> {
  const requestId = crypto.randomUUID();
  return new Promise<ContentInstrumentationResponse>((resolve) => {
    const timeout = window.setTimeout(() => {
      pendingRequests.delete(requestId);
      resolve({
        instrumented: state.instrumented,
        integrity: 'page-world-unverified',
        frameUrl: sanitizeBridgeUrl(location.href),
        topFrame: window.top === window,
        snapshot: state.startedAt
          ? {
              version: '0.3.0',
              startedAt: state.startedAt,
              pageUrl: sanitizeBridgeUrl(location.href),
              events: [...state.liveEvents],
              warnings: [
                ...state.warnings,
                ...(state.droppedLiveEventCount > 0
                  ? [`Fallback instrumentation buffer dropped ${state.droppedLiveEventCount} event observation${state.droppedLiveEventCount === 1 ? '' : 's'} at its 300-event limit.`]
                  : []),
                'Fallback instrumentation snapshot could not recover page-world response-observation coverage counters.'
              ],
              coverage: {
                eventBuffer: {
                  limit: 300,
                  retainedEventCount: state.liveEvents.length,
                  droppedEventCount: state.droppedLiveEventCount,
                  droppedByReason:
                    state.droppedLiveEventCount > 0
                      ? { 'fallback-event-buffer-limit': state.droppedLiveEventCount }
                      : {}
                }
              }
            }
          : undefined,
        warnings: [
          ...state.warnings,
          PAGE_WORLD_INTEGRITY_WARNING,
          'Timed out waiting for instrumented snapshot response.'
        ]
      });
    }, 700);

    pendingRequests.set(requestId, {
      resolve,
      timeout
    });
    window.postMessage(
      {
        __blanche: 'burp-bridge',
        type: 'instrumentation-snapshot-request',
        payload: {
          requestId
        }
      },
      '*'
    );
  });
}
