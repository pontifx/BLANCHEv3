export async function collectPageFrameSnapshot(options: {
  resourceEntryLimit: number;
  cacheEntryLimit: number;
  storageValueLimit: number;
}): Promise<{
  snapshot: Record<string, unknown>;
  warnings: Array<{ code: string; message: string }>;
  visibilityGaps: Array<{
    code: string;
    message: string;
    reason:
      | 'cross-origin'
      | 'permission'
      | 'api-unavailable'
      | 'timing'
      | 'unsupported-context'
      | 'implementation-gap';
  }>;
}> {
  const warnings: Array<{ code: string; message: string }> = [];
  const visibilityGaps: Array<{
    code: string;
    message: string;
    reason:
      | 'cross-origin'
      | 'permission'
      | 'api-unavailable'
      | 'timing'
      | 'unsupported-context'
      | 'implementation-gap';
  }> = [];
  const resourceEntryLimit =
    typeof options.resourceEntryLimit === 'number' ? options.resourceEntryLimit : 250;
  const cacheEntryLimit = typeof options.cacheEntryLimit === 'number' ? options.cacheEntryLimit : 40;
  const storageValueLimit =
    typeof options.storageValueLimit === 'number' ? options.storageValueLimit : 400;

  const truncate = (value: unknown, max = 400): string => {
    const normalized = typeof value === 'string' ? value : String(value ?? '');
    return normalized.length <= max ? normalized : `${normalized.slice(0, max)}...`;
  };

  const safeUrl = (value: unknown): string | undefined => {
    if (typeof value !== 'string' || !value) {
      return undefined;
    }

    try {
      return new URL(value, location.href).href;
    } catch {
      return value;
    }
  };

  const collectNavigation = (): Record<string, unknown> => {
    const navigationEntry = performance.getEntriesByType('navigation')[0] as
      | PerformanceNavigationTiming
      | undefined;

    if (navigationEntry) {
      return {
        type: navigationEntry.type,
        redirectCount: navigationEntry.redirectCount,
        domComplete: navigationEntry.domComplete,
        domContentLoadedEventEnd: navigationEntry.domContentLoadedEventEnd,
        loadEventEnd: navigationEntry.loadEventEnd,
        responseEnd: navigationEntry.responseEnd,
        responseStart: navigationEntry.responseStart,
        transferSize: navigationEntry.transferSize,
        decodedBodySize: navigationEntry.decodedBodySize,
        encodedBodySize: navigationEntry.encodedBodySize
      };
    }

    return {
      timingFallback: {
        navigationStart: performance.timing?.navigationStart ?? null,
        domInteractive: performance.timing?.domInteractive ?? null,
        domComplete: performance.timing?.domComplete ?? null,
        loadEventEnd: performance.timing?.loadEventEnd ?? null
      }
    };
  };

  const summarizeNode = (
    node: Element,
    urlAttribute: 'src' | 'href',
    extra: Record<string, unknown> = {}
  ): Record<string, unknown> => {
    const url = node.getAttribute(urlAttribute);
    return {
      url: safeUrl(url),
      tagName: node.tagName.toLowerCase(),
      inline: !url,
      ...extra
    };
  };

  const collectDomResources = () => ({
    scripts: Array.from(document.querySelectorAll('script')).map((node) =>
      summarizeNode(node, 'src', {
        type: node.getAttribute('type') ?? null,
        async: node.hasAttribute('async'),
        defer: node.hasAttribute('defer'),
        integrity: node.getAttribute('integrity') ?? null,
        noncePresent: node.hasAttribute('nonce')
      })
    ),
    stylesheets: [
      ...Array.from(document.querySelectorAll('link[rel~="stylesheet"]')).map((node) =>
        summarizeNode(node, 'href', {
          rel: node.getAttribute('rel') ?? null,
          media: node.getAttribute('media') ?? null
        })
      ),
      ...Array.from(document.querySelectorAll('style')).map(() => ({
        tagName: 'style',
        inline: true
      }))
    ],
    images: Array.from(document.querySelectorAll('img')).map((node) =>
      summarizeNode(node, 'src', {
        loading: node.getAttribute('loading') ?? null,
        currentSrc: safeUrl((node as HTMLImageElement).currentSrc)
      })
    ),
    manifests: Array.from(document.querySelectorAll('link[rel~="manifest"]')).map((node) =>
      summarizeNode(node, 'href', {
        rel: node.getAttribute('rel') ?? null
      })
    ),
    iframes: Array.from(document.querySelectorAll('iframe, frame')).map((node) =>
      summarizeNode(node, 'src', {
        sandbox: node.getAttribute('sandbox') ?? null,
        name: node.getAttribute('name') ?? null
      })
    ),
    fonts:
      'fonts' in document
        ? Array.from((document.fonts as unknown as Iterable<FontFace>) ?? []).map((font) => ({
            family: truncate(font.family, 120),
            style: font.style,
            weight: font.weight,
            stretch: font.stretch,
            status: font.status
          }))
        : []
  });

  const collectPerformanceResources = (): Array<Record<string, unknown>> => {
    return performance
      .getEntriesByType('resource')
      .slice(0, resourceEntryLimit)
      .map((entry) => {
        const resource = entry as PerformanceResourceTiming;
        return {
          name: resource.name,
          initiatorType: resource.initiatorType,
          transferSize: resource.transferSize,
          encodedBodySize: resource.encodedBodySize,
          decodedBodySize: resource.decodedBodySize,
          nextHopProtocol: resource.nextHopProtocol,
          deliveryType: (resource as PerformanceResourceTiming & { deliveryType?: string })
            .deliveryType,
          renderBlockingStatus: (
            resource as PerformanceResourceTiming & { renderBlockingStatus?: string }
          ).renderBlockingStatus,
          responseEnd: resource.responseEnd
        };
      });
  };

  const collectStorage = (storage: Storage | undefined, label: string) => {
    const entries: Array<Record<string, unknown>> = [];

    if (!storage) {
      return entries;
    }

    try {
      for (let index = 0; index < storage.length; index += 1) {
        const key = storage.key(index);
        if (!key) {
          continue;
        }

        entries.push({
          key,
          value: truncate(storage.getItem(key), storageValueLimit),
          truncated: (storage.getItem(key)?.length ?? 0) > storageValueLimit,
          storageArea: label
        });
      }
    } catch (error) {
      warnings.push({
        code: `${label.toUpperCase()}_READ_FAILED`,
        message: `Unable to read ${label}: ${String(error)}`
      });
    }

    return entries;
  };

  const collectIndexedDb = async () => {
    const databases: Array<Record<string, unknown>> = [];
    const indexedDbFactory = indexedDB as IDBFactory & {
      databases?: () => Promise<Array<{ name?: string; version?: number }>>;
    };

    if (typeof indexedDbFactory.databases !== 'function') {
      visibilityGaps.push({
        code: 'INDEXEDDB_DATABASES_UNAVAILABLE',
        message: 'indexedDB.databases() is unavailable in this context.',
        reason: 'api-unavailable'
      });
      return databases;
    }

    try {
      const catalog = await indexedDbFactory.databases();
      for (const databaseInfo of catalog) {
        if (!databaseInfo.name) {
          continue;
        }

        try {
          const handle = await new Promise<IDBDatabase>((resolve, reject) => {
            const request = indexedDB.open(databaseInfo.name as string);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error ?? new Error('IDB open failed'));
          });

          const objectStores = Array.from(handle.objectStoreNames).map((storeName) => {
            const transaction = handle.transaction(storeName, 'readonly');
            const store = transaction.objectStore(storeName);
            return {
              name: storeName,
              keyPath:
                typeof store.keyPath === 'string'
                  ? store.keyPath
                  : Array.isArray(store.keyPath)
                    ? [...store.keyPath]
                    : null,
              autoIncrement: store.autoIncrement,
              indexes: Array.from(store.indexNames).map((indexName) => {
                const index = store.index(indexName);
                return {
                  name: index.name,
                  keyPath:
                    typeof index.keyPath === 'string'
                      ? index.keyPath
                      : Array.isArray(index.keyPath)
                        ? [...index.keyPath]
                        : null,
                  multiEntry: index.multiEntry,
                  unique: index.unique
                };
              })
            };
          });

          databases.push({
            name: handle.name,
            version: handle.version,
            objectStores
          });
          handle.close();
        } catch (error) {
          warnings.push({
            code: 'INDEXEDDB_DATABASE_OPEN_FAILED',
            message: `Unable to inspect IndexedDB database ${databaseInfo.name}: ${String(error)}`
          });
        }
      }
    } catch (error) {
      warnings.push({
        code: 'INDEXEDDB_ENUMERATION_FAILED',
        message: `Unable to enumerate IndexedDB databases: ${String(error)}`
      });
    }

    return databases;
  };

  const collectCacheStorage = async () => {
    const cachesOutput: Array<Record<string, unknown>> = [];
    if (!('caches' in window)) {
      visibilityGaps.push({
        code: 'CACHE_STORAGE_UNAVAILABLE',
        message: 'Cache Storage is unavailable in this frame.',
        reason: 'api-unavailable'
      });
      return cachesOutput;
    }

    try {
      const cacheNames = await caches.keys();
      for (const cacheName of cacheNames) {
        try {
          const cache = await caches.open(cacheName);
          const requests = await cache.keys();
          cachesOutput.push({
            name: cacheName,
            requestUrls: requests.slice(0, cacheEntryLimit).map((request) => request.url),
            truncated: requests.length > cacheEntryLimit
          });
        } catch (error) {
          warnings.push({
            code: 'CACHE_STORAGE_OPEN_FAILED',
            message: `Unable to inspect cache ${cacheName}: ${String(error)}`
          });
        }
      }
    } catch (error) {
      warnings.push({
        code: 'CACHE_STORAGE_ENUMERATION_FAILED',
        message: `Unable to enumerate Cache Storage: ${String(error)}`
      });
    }

    return cachesOutput;
  };

  const collectServiceWorkers = async () => {
    if (!('serviceWorker' in navigator)) {
      visibilityGaps.push({
        code: 'SERVICE_WORKER_API_UNAVAILABLE',
        message: 'navigator.serviceWorker is unavailable in this frame.',
        reason: 'api-unavailable'
      });
      return [];
    }

    try {
      const registrations = await navigator.serviceWorker.getRegistrations();
      return registrations.map((registration) => ({
        scope: registration.scope,
        activeScriptUrl: registration.active?.scriptURL ?? null,
        installingScriptUrl: registration.installing?.scriptURL ?? null,
        waitingScriptUrl: registration.waiting?.scriptURL ?? null,
        controllerPresent: Boolean(navigator.serviceWorker.controller)
      }));
    } catch (error) {
      warnings.push({
        code: 'SERVICE_WORKER_ENUMERATION_FAILED',
        message: `Unable to inspect service worker registrations: ${String(error)}`
      });
      return [];
    }
  };

  const resources = collectPerformanceResources();
  const dom = collectDomResources();
  const indexedDb = await collectIndexedDb();
  const cacheStorage = await collectCacheStorage();
  const serviceWorkers = await collectServiceWorkers();

  return {
    snapshot: {
      url: location.href,
      title: document.title,
      origin: location.origin,
      referrer: document.referrer || undefined,
      readyState: document.readyState,
      visibilityState: document.visibilityState,
      contentType: document.contentType || undefined,
      characterSet: document.characterSet || undefined,
      navigation: collectNavigation(),
      runtimeIndicators: {
        secureContext: window.isSecureContext,
        crossOriginIsolated: window.crossOriginIsolated,
        hasFocus: document.hasFocus(),
        hidden: document.hidden,
        language: navigator.language,
        onLine: navigator.onLine,
        cookieEnabled: navigator.cookieEnabled,
        webdriver:
          'webdriver' in navigator
            ? Boolean((navigator as Navigator & { webdriver?: boolean }).webdriver)
            : false,
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory:
          'deviceMemory' in navigator
            ? (navigator as Navigator & { deviceMemory?: number }).deviceMemory ?? null
            : null,
        contentSecurityPolicyMetas: Array.from(
          document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]')
        ).map((meta) => truncate(meta.getAttribute('content'), 300))
      },
      resources,
      dom,
      storage: {
        localStorage: collectStorage(window.localStorage, 'localStorage'),
        sessionStorage: collectStorage(window.sessionStorage, 'sessionStorage'),
        indexedDb,
        cacheStorage
      },
      workers: {
        serviceWorkers,
        workerHints: resources.filter((resource) => {
          return ['worker', 'sharedworker', 'serviceworker'].includes(
            String(resource.initiatorType ?? '').toLowerCase()
          );
        })
      }
    },
    warnings,
    visibilityGaps
  };
}
