import {
  BLANCHE_OSINT_SCHEMA_VERSION,
  BLANCHE_OSINT_SEED_KIND,
  type BlancheOsintSeedV1,
  type ExportWarning
} from '../../../../shared-schema/src';
import type {
  Logger,
  ModuleActionContext,
  ModuleActionResult,
  ModuleBackgroundController,
  ModuleDescriptor
} from '../../shared/contracts';
import { createId, toErrorDetails } from '../../shared/helpers';
import type { OsintSeedSettings, SeedCollectionPayload } from './types';

const DEFAULT_BURP_OSINT_SEED_URL = 'http://blanche.invalid/osint/seed';
const DEFAULT_BURP_OSINT_LOOPBACK_URL = 'http://127.0.0.1:47625/api/blanche/osint/seed';
const BURP_SEED_TIMEOUT_MS = 5000;

export function createOsintSeedBackgroundController(input: {
  descriptor: ModuleDescriptor;
  logger: Logger;
}): ModuleBackgroundController {
  return {
    async onHostStart() {
      input.logger.info('OSINT Seed background controller ready');
    },
    async runAction(request, context) {
      if (request.actionId !== 'seedTarget') {
        return {
          status: 'error',
          message: `Unsupported OSINT Seed action: ${request.actionId}`
        };
      }

      return runSeedCollection(input.descriptor, request.tabId, context);
    }
  };
}

async function runSeedCollection(
  descriptor: ModuleDescriptor,
  tabId: number | undefined,
  context: ModuleActionContext
): Promise<ModuleActionResult> {
  if (!tabId) {
    return {
      status: 'error',
      message: 'OSINT Seed requires a target tab.'
    };
  }

  const tab = await chrome.tabs.get(tabId);
  if (!tab.url || !/^https?:/i.test(tab.url)) {
    return {
      status: 'error',
      message: `OSINT Seed only supports public http(s) tabs. Current URL: ${tab.url ?? 'unknown'}`
    };
  }

  const settings = resolveSettings(context.settings);
  const seedSignals = await collectSeedSignals(tabId, settings.relatedHostLimit);
  const primaryUrl = new URL(tab.url);
  const primaryHostname = normalizeHostname(primaryUrl.hostname);
  if (!primaryHostname) {
    return {
      status: 'error',
      message: `Unable to derive a hostname from ${tab.url}`
    };
  }

  const relatedHosts = buildRelatedHostObservations(seedSignals, primaryHostname, settings.relatedHostLimit);
  const seedPayload: BlancheOsintSeedV1 = {
    kind: BLANCHE_OSINT_SEED_KIND,
    schemaVersion: BLANCHE_OSINT_SCHEMA_VERSION,
    seedMetadata: {
      seedId: createId('seed'),
      createdAt: new Date().toISOString(),
      generatedBy: {
        product: 'BLANCHE',
        component: 'chromium-extension/background',
        version: context.services.getProductVersion(),
        moduleId: descriptor.id,
        moduleVersion: descriptor.version
      }
    },
    scope: buildScopeStatement(),
    seed: {
      targetUrl: tab.url,
      targetOrigin: primaryUrl.origin,
      primaryHostname,
      apparentRootDomain: deriveApparentRootDomain(primaryHostname),
      sourceType: 'tab-url'
    },
    browserContext: {
      tabId,
      pageUrl: seedSignals.pageUrl ?? tab.url,
      pageOrigin: seedSignals.pageOrigin ?? primaryUrl.origin,
      pageTitle: seedSignals.pageTitle ?? tab.title,
      referrer: seedSignals.referrer,
      apparentRootDomain: deriveApparentRootDomain(primaryHostname),
      relatedHosts,
      signals: seedSignals.signalSummary
    },
    warnings: [
      {
        code: 'OSINT_INFORMATIONAL_ONLY',
        message:
          'Generated seed is intended for public, informational OSINT only and does not validate vulnerabilities.',
        severity: 'info'
      }
    ]
  };

  const handoff = await maybeSendSeedToBurp(seedPayload, settings, context.logger);
  const status: ModuleActionResult['status'] =
    handoff.warning?.severity === 'warning' ? 'partial' : 'ok';
  return {
    status,
    message: handoff.delivered
      ? `Prepared OSINT seed for ${primaryHostname} and sent it to Burp at ${handoff.endpoint}.`
      : `Prepared OSINT seed for ${primaryHostname}, but Burp delivery failed at ${handoff.endpoint}.`,
    warnings: handoff.warning ? [handoff.warning] : [],
    data: {
      seedId: seedPayload.seedMetadata.seedId,
      primaryHostname,
      relatedHostCount: relatedHosts.length,
      burpSeedUrl: handoff.endpoint,
      delivered: handoff.delivered
    }
  };
}

async function collectSeedSignals(tabId: number, relatedHostLimit: number): Promise<SeedCollectionPayload> {
  const [result] = await chrome.scripting.executeScript({
    target: {
      tabId,
      allFrames: false
    },
    func: collectPageSeedSignals,
    args: [relatedHostLimit]
  });

  return (result?.result as SeedCollectionPayload | undefined) ?? {
    signals: {
      anchors: [],
      scripts: [],
      stylesheets: [],
      images: [],
      forms: [],
      iframes: [],
      manifests: []
    },
    signalSummary: {}
  };
}

function collectPageSeedSignals(relatedHostLimit: number): SeedCollectionPayload {
  const collectUrls = (selector: string, attributeName: string): string[] => {
    const urls = new Set<string>();
    for (const element of Array.from(document.querySelectorAll(selector))) {
      const rawValue = element.getAttribute(attributeName);
      if (!rawValue) {
        continue;
      }

      try {
        urls.add(new URL(rawValue, location.href).toString());
        if (urls.size >= relatedHostLimit) {
          break;
        }
      } catch {
        continue;
      }
    }
    return [...urls];
  };

  const anchors = collectUrls('a[href]', 'href');
  const scripts = collectUrls('script[src]', 'src');
  const stylesheets = collectUrls('link[rel~="stylesheet"][href]', 'href');
  const images = collectUrls('img[src]', 'src');
  const forms = collectUrls('form[action]', 'action');
  const iframes = collectUrls('iframe[src]', 'src');
  const manifests = collectUrls('link[rel~="manifest"][href]', 'href');

  return {
    pageUrl: location.href,
    pageOrigin: location.origin,
    pageTitle: document.title,
    referrer: document.referrer,
    signals: {
      anchors,
      scripts,
      stylesheets,
      images,
      forms,
      iframes,
      manifests
    },
    signalSummary: {
      anchorCount: anchors.length,
      scriptCount: scripts.length,
      stylesheetCount: stylesheets.length,
      imageCount: images.length,
      formCount: forms.length,
      iframeCount: iframes.length,
      manifestCount: manifests.length
    }
  };
}

function buildRelatedHostObservations(
  payload: SeedCollectionPayload,
  primaryHostname: string,
  limit: number
): BlancheOsintSeedV1['browserContext']['relatedHosts'] {
  const observed = new Map<string, BlancheOsintSeedV1['browserContext']['relatedHosts'][number]>();
  const pushEntries = (
    values: string[],
    sourceType: BlancheOsintSeedV1['browserContext']['relatedHosts'][number]['sourceType']
  ) => {
    for (const value of values) {
      try {
        const parsed = new URL(value);
        const hostname = normalizeHostname(parsed.hostname);
        if (!hostname || hostname === primaryHostname) {
          continue;
        }

        if (!observed.has(hostname)) {
          observed.set(hostname, {
            hostname,
            url: parsed.toString(),
            sourceType,
            confidence: 'medium'
          });
        }

        if (observed.size >= limit) {
          break;
        }
      } catch {
        continue;
      }
    }
  };

  pushEntries(payload.signals.anchors, 'dom-link');
  pushEntries(payload.signals.scripts, 'dom-script');
  pushEntries(payload.signals.stylesheets, 'dom-stylesheet');
  pushEntries(payload.signals.images, 'dom-image');
  pushEntries(payload.signals.forms, 'dom-form');
  pushEntries(payload.signals.iframes, 'dom-iframe');
  pushEntries(payload.signals.manifests, 'manifest');

  return [...observed.values()];
}

interface HandoffResult {
  delivered: boolean;
  endpoint: string;
  warning?: ExportWarning;
}

async function maybeSendSeedToBurp(
  seedPayload: BlancheOsintSeedV1,
  settings: OsintSeedSettings,
  logger: Logger
): Promise<HandoffResult> {
  const endpoint = settings.burpSeedUrl.trim();
  if (!settings.autoSendToBurp) {
    return {
      delivered: false,
      endpoint
    };
  }

  const primaryEndpoint = endpoint || DEFAULT_BURP_OSINT_SEED_URL;
  const fallbackEndpoint = DEFAULT_BURP_OSINT_LOOPBACK_URL;
  const primaryAttempt = await sendSeedToEndpoint(seedPayload, primaryEndpoint, logger);
  if (primaryAttempt.delivered) {
    return primaryAttempt;
  }

  if (primaryEndpoint === fallbackEndpoint) {
    return {
      delivered: false,
      endpoint: primaryEndpoint,
      warning: {
        code: 'OSINT_SEED_HANDOFF_FAILED',
        message: primaryAttempt.errorMessage ?? 'OSINT seed handoff failed.',
        severity: 'warning',
        context: {
          endpoint: primaryEndpoint
        }
      }
    };
  }

  const fallbackAttempt = await sendSeedToEndpoint(seedPayload, fallbackEndpoint, logger);
  if (fallbackAttempt.delivered) {
    return {
      delivered: true,
      endpoint: fallbackEndpoint,
      warning: {
        code: 'OSINT_SEED_FALLBACK_USED',
        message: `Primary Burp seed endpoint ${primaryEndpoint} failed; delivered seed to fallback ${fallbackEndpoint}.`,
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
      code: 'OSINT_SEED_HANDOFF_FAILED',
      message:
        `OSINT seed handoff failed. Primary ${primaryEndpoint}: ${primaryAttempt.errorMessage ?? 'Unknown error.'} ` +
        `Fallback ${fallbackEndpoint}: ${fallbackAttempt.errorMessage ?? 'Unknown error.'}`,
      severity: 'warning',
      context: {
        primaryEndpoint,
        fallbackEndpoint
      }
    }
  };
}

async function sendSeedToEndpoint(
  seedPayload: BlancheOsintSeedV1,
  endpoint: string,
  logger: Logger
): Promise<{ delivered: boolean; endpoint: string; errorMessage?: string }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), BURP_SEED_TIMEOUT_MS);
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'text/plain;charset=UTF-8'
      },
      body: JSON.stringify(seedPayload),
      credentials: 'omit',
      mode: 'no-cors',
      signal: controller.signal
    });

    if (response.type !== 'opaque' && !response.ok) {
      throw new Error(`Burp seed endpoint responded with status ${response.status}`);
    }

    logger.info('OSINT seed sent to Burp', {
      endpoint,
      status: response.status,
      opaque: response.type === 'opaque'
    });
    return {
      delivered: true,
      endpoint
    };
  } catch (error) {
    logger.warn('OSINT seed handoff attempt failed', {
      endpoint,
      error: toErrorDetails(error)
    });
    return {
      delivered: false,
      endpoint,
      errorMessage:
        error instanceof Error && error.name === 'AbortError'
          ? `Timed out waiting for Burp after ${BURP_SEED_TIMEOUT_MS}ms.`
          : error instanceof Error
            ? error.message
            : String(error)
    };
  } finally {
    clearTimeout(timeout);
  }
}

function resolveSettings(rawSettings: Record<string, unknown>): OsintSeedSettings {
  return {
    autoSendToBurp: rawSettings.autoSendToBurp !== false,
    burpSeedUrl:
      typeof rawSettings.burpSeedUrl === 'string' && rawSettings.burpSeedUrl.trim().length > 0
        ? rawSettings.burpSeedUrl.trim()
        : DEFAULT_BURP_OSINT_SEED_URL,
    relatedHostLimit:
      typeof rawSettings.relatedHostLimit === 'number' ? rawSettings.relatedHostLimit : 80
  };
}

function buildScopeStatement(): BlancheOsintSeedV1['scope'] {
  return {
    mode: 'public-passive',
    allowedActivities: [
      'Capture public hostnames and references already present in the browser-visible page context.',
      'Use the generated seed to guide passive/public OSINT orchestration only.'
    ],
    disallowedActivities: [
      'Do not treat this seed as proof of ownership, vulnerability, or exploitability.',
      'Do not use the generated seed to collect non-public information or bypass access controls.'
    ],
    operatorNotes: [
      'This seed is informational context for follow-on testing and reporting preparation.'
    ]
  };
}

function normalizeHostname(rawValue: string | undefined): string | undefined {
  if (!rawValue) {
    return undefined;
  }

  const normalized = rawValue.trim().toLowerCase().replace(/\.$/, '');
  if (!normalized || /\s/.test(normalized)) {
    return undefined;
  }

  return normalized;
}

function deriveApparentRootDomain(hostname: string): string {
  const labels = hostname.split('.');
  if (labels.length <= 2) {
    return hostname;
  }

  const tld = labels.at(-1) ?? '';
  const secondLevel = labels.at(-2) ?? '';
  const commonCountryCodeSecondLevels = new Set(['co', 'com', 'org', 'net', 'gov', 'edu']);
  if (tld.length === 2 && commonCountryCodeSecondLevels.has(secondLevel) && labels.length >= 3) {
    return labels.slice(-3).join('.');
  }

  return labels.slice(-2).join('.');
}
