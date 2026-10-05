import type { JsonValue } from '../../../../shared-schema/src';
import type { LatentFeatureStorageArea } from '../../shared/latentFeatureWorkbench';

export interface LatentPageStorageEntry {
  area: LatentFeatureStorageArea;
  key: string;
  value: string;
  truncated: boolean;
}

export interface LatentPageStructuredSignal {
  label: string;
  value: JsonValue;
}

export interface LatentFeaturePageSignals {
  pageUrl: string;
  origin: string;
  title: string;
  documentContentType: string;
  rawDocumentSource?: {
    label: string;
    text: string;
    truncated: boolean;
    contentType: string;
  };
  loadedScriptUrls: string[];
  inlineScripts: Array<{
    label: string;
    text: string;
    truncated: boolean;
  }>;
  storageEntries: LatentPageStorageEntry[];
  runtimeGlobals: LatentPageStructuredSignal[];
  domSignals: LatentPageStructuredSignal[];
  warnings: string[];
}

export function collectLatentFeaturePageSignals(): LatentFeaturePageSignals {
  const warnings: string[] = [];
  const maxStorageValueCharacters = 65536;
  const maxInlineScriptCharacters = 65536;
  const maxInlineScripts = 20;
  const maxRawDocumentCharacters = 524288;
  const maxInspectedScripts = 1000;
  const maxLoadedScriptUrls = 1000;
  const maxInspectedResourceEntries = 2000;
  const maxEnumeratedWindowProperties = 2000;
  const maxCandidateGlobalNames = 40;
  const maxInspectedDomElements = 500;
  const maxInspectedAttributesPerElement = 50;
  const maxDomSignals = 100;
  const maxTextNodesPerSource = 10000;
  const maxDocumentBasenameCharacters = 96;
  const maxInlineScriptIdCharacters = 64;
  const normalizeLabelText = (value: string, maximum: number): string =>
    value
      .replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/gi, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, maximum);
  const documentBasename = (() => {
    const encodedBasename = location.pathname.split('/').pop();
    if (!encodedBasename) return '';
    let decodedBasename = encodedBasename;
    try {
      decodedBasename = decodeURIComponent(encodedBasename);
    } catch {
      // A malformed escape is still safe to show after bounding and character cleanup.
    }
    const cleanedBasename = normalizeLabelText(
      decodedBasename.split(/[?#]/, 1)[0] ?? '',
      maxDocumentBasenameCharacters
    );
    if (
      !cleanedBasename ||
      /[@:=]/.test(cleanedBasename) ||
      /(?:bearer\s+|\beyJ[A-Za-z0-9_-]{8,}\.|(?:token|secret|password|cookie|credential))/i.test(
        cleanedBasename
      )
    ) {
      return '';
    }
    return cleanedBasename.replace(/[^A-Za-z0-9._ -]+/g, '-').replace(/^-+|-+$/g, '');
  })();
  const inlineScriptLabel = (scriptId: string, index: number): string => {
    const fallback = `inline script ${index + 1}`;
    const cleaned = normalizeLabelText(scriptId, maxInlineScriptIdCharacters);
    if (
      !cleaned ||
      /^[a-z][a-z0-9+.-]*:\/\//i.test(cleaned) ||
      /(?:bearer\s+|\beyJ[A-Za-z0-9_-]{8,}\.|(?:token|secret|password|cookie|credential)\s*[:=])/i.test(
        cleaned
      )
    ) {
      return fallback;
    }
    return /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/.test(cleaned)
      ? `inline script #${cleaned}`
      : fallback;
  };
  const readBoundedText = (
    root: Node,
    maximum: number
  ): { text: string; truncated: boolean } => {
    if (typeof Node === 'undefined') {
      // This branch supports the isolated unit fixture. Browsers use bounded node traversal below.
      const fallbackText = typeof root.textContent === 'string' ? root.textContent : '';
      return {
        text: fallbackText.slice(0, maximum),
        truncated: fallbackText.length > maximum
      };
    }
    let text = '';
    let textNodeCount = 0;
    let visitedNodeCount = 0;
    const maxVisitedNodes = maxTextNodesPerSource * 5;
    const appendTextNode = (node: Node): void => {
      if (node.nodeType !== Node.TEXT_NODE) return;
      const remaining = maximum + 1 - text.length;
      text += (node.nodeValue ?? '').slice(0, Math.max(0, remaining));
      textNodeCount += 1;
    };
    let node: Node | null = root;
    while (
      node &&
      text.length <= maximum &&
      textNodeCount < maxTextNodesPerSource &&
      visitedNodeCount < maxVisitedNodes
    ) {
      appendTextNode(node);
      visitedNodeCount += 1;
      if (node.firstChild) {
        node = node.firstChild;
        continue;
      }
      while (node && node !== root && !node.nextSibling) node = node.parentNode;
      if (!node || node === root) {
        node = null;
      } else {
        node = node.nextSibling;
      }
    }
    return {
      text: text.slice(0, maximum),
      truncated: text.length > maximum || node !== null
    };
  };
  const documentContentType = document.contentType ?? '';
  const javascriptContentType = /(?:java|ecma)script/i.test(documentContentType);
  const javascriptPath = /\.m?js$/i.test(location.pathname);
  const renderedSourceElement = document.querySelector('body > pre');
  const renderedSource = renderedSourceElement
    ? readBoundedText(renderedSourceElement, maxRawDocumentCharacters)
    : undefined;
  const renderedSourceText = renderedSource?.text;
  const rawDocumentCapture = javascriptContentType
    ? renderedSource ??
      (document.body ? readBoundedText(document.body, maxRawDocumentCharacters) : undefined)
    : javascriptPath && typeof renderedSourceText === 'string'
      ? renderedSource
      : undefined;
  const rawDocumentSource = rawDocumentCapture?.text
    ? {
        label: documentBasename
          ? `current JavaScript document (${documentBasename})`
          : 'current JavaScript document',
        text: rawDocumentCapture.text,
        truncated: rawDocumentCapture.truncated,
        contentType: documentContentType
      }
    : undefined;

  const loadedScriptUrls = new Set<string>();
  const inlineScripts: LatentFeaturePageSignals['inlineScripts'] = [];
  let omittedInlineScriptCount = 0;
  const inspectedScriptCount = Math.min(document.scripts.length, maxInspectedScripts);
  for (let scriptIndex = 0; scriptIndex < inspectedScriptCount; scriptIndex += 1) {
    const script = document.scripts[scriptIndex];
    if (!script) continue;
    if (script.src) {
      if (loadedScriptUrls.size < maxLoadedScriptUrls) loadedScriptUrls.add(script.src);
      continue;
    }
    if (inlineScripts.length >= maxInlineScripts) {
      omittedInlineScriptCount += 1;
      continue;
    }
    const source = readBoundedText(script, maxInlineScriptCharacters);
    if (!source.text.trim()) continue;
    inlineScripts.push({
      label: inlineScriptLabel(script.id, inlineScripts.length),
      text: source.text,
      truncated: source.truncated
    });
  }
  if (document.scripts.length > inspectedScriptCount) {
    warnings.push(
      `Script enumeration stopped at ${maxInspectedScripts} document scripts; additional script elements were not inspected.`
    );
  }
  if (omittedInlineScriptCount > 0) {
    warnings.push(
      `${omittedInlineScriptCount} inline script${omittedInlineScriptCount === 1 ? '' : 's'} exceeded the ${maxInlineScripts}-script source cap.`
    );
  }

  const resourceEntries = performance.getEntriesByType('resource');
  const inspectedResourceEntryCount = Math.min(
    resourceEntries.length,
    maxInspectedResourceEntries
  );
  for (let index = 0; index < inspectedResourceEntryCount; index += 1) {
    const resource = resourceEntries[index] as PerformanceResourceTiming | undefined;
    if (
      resource &&
      loadedScriptUrls.size < maxLoadedScriptUrls &&
      String(resource.initiatorType).toLowerCase().includes('script') &&
      resource.name
    ) {
      loadedScriptUrls.add(resource.name);
    }
  }
  if (resourceEntries.length > inspectedResourceEntryCount) {
    warnings.push(
      `Resource Timing enumeration stopped at ${maxInspectedResourceEntries} entries; later resources were not inspected for scripts.`
    );
  }
  if (loadedScriptUrls.size >= maxLoadedScriptUrls) {
    warnings.push(`Loaded script URL collection reached its ${maxLoadedScriptUrls}-URL cap.`);
  }

  const storageEntries: LatentPageStorageEntry[] = [];
  const collectStorage = (area: LatentFeatureStorageArea, storage: Storage) => {
    try {
      for (let index = 0; index < Math.min(storage.length, 300); index += 1) {
        const key = storage.key(index);
        if (!key) {
          continue;
        }
        const value = storage.getItem(key) ?? '';
        storageEntries.push({
          area,
          key,
          value: value.slice(0, maxStorageValueCharacters),
          truncated: value.length > maxStorageValueCharacters
        });
      }
    } catch (error) {
      warnings.push(`Unable to read ${area}: ${String(error)}`);
    }
  };
  collectStorage('localStorage', window.localStorage);
  collectStorage('sessionStorage', window.sessionStorage);

  const runtimeGlobals: LatentPageStructuredSignal[] = [];
  const explicitGlobalNames = [
    '__INITIAL_STATE__',
    '__PRELOADED_STATE__',
    '__NEXT_DATA__',
    '__NUXT__',
    '__APOLLO_STATE__',
    '__CONFIG__',
    '__FEATURE_FLAGS__',
    'FEATURE_FLAGS',
    'featureFlags',
    'features',
    'experiments'
  ];
  let candidateGlobalNames: string[] = [];
  try {
    let enumeratedPropertyCount = 0;
    let omittedCandidateCount = 0;
    for (const name in window) {
      if (!Object.prototype.hasOwnProperty.call(window, name)) continue;
      enumeratedPropertyCount += 1;
      if (/feature|flag|experiment|variant|rollout|preview|gate|toggle|config/i.test(name)) {
        if (candidateGlobalNames.length < maxCandidateGlobalNames) {
          candidateGlobalNames.push(name);
        } else {
          omittedCandidateCount += 1;
        }
      }
      if (enumeratedPropertyCount >= maxEnumeratedWindowProperties) break;
    }
    if (enumeratedPropertyCount >= maxEnumeratedWindowProperties) {
      warnings.push(
        `Window property enumeration stopped at ${maxEnumeratedWindowProperties} own enumerable properties.`
      );
    }
    if (omittedCandidateCount > 0) {
      warnings.push(
        `${omittedCandidateCount} flag-shaped global name${omittedCandidateCount === 1 ? '' : 's'} exceeded the ${maxCandidateGlobalNames}-name cap.`
      );
    }
  } catch (error) {
    warnings.push(`Unable to enumerate flag-shaped global names: ${String(error)}`);
  }

  const seenGlobals = new Set<string>();
  for (const name of [...explicitGlobalNames, ...candidateGlobalNames]) {
    if (seenGlobals.has(name)) {
      continue;
    }
    seenGlobals.add(name);
    try {
      const value = (window as unknown as Record<string, unknown>)[name];
      const cloned = cloneJsonLike(value, 0, { remaining: 800 });
      if (cloned !== undefined) {
        runtimeGlobals.push({
          label: name,
          value: cloned
        });
      }
    } catch {
      // Host objects and getter-backed globals can throw. Their absence is not a collection failure.
    }
  }

  const domSignals: LatentPageStructuredSignal[] = [];
  const domWalker = document.documentElement && typeof document.createTreeWalker === 'function'
    ? document.createTreeWalker(document.documentElement, 1)
    : undefined;
  let element: Element | null = document.documentElement ?? null;
  let inspectedDomElementCount = 0;
  let attributeCapReached = false;
  while (
    element &&
    inspectedDomElementCount < maxInspectedDomElements &&
    domSignals.length < maxDomSignals
  ) {
    inspectedDomElementCount += 1;
    const inspectedAttributeCount = Math.min(
      element.attributes.length,
      maxInspectedAttributesPerElement
    );
    if (element.attributes.length > inspectedAttributeCount) attributeCapReached = true;
    for (let attributeIndex = 0; attributeIndex < inspectedAttributeCount; attributeIndex += 1) {
      const attribute = element.attributes.item(attributeIndex);
      if (!attribute) continue;
      if (!/feature|flag|experiment|variant|rollout|preview|gate|toggle/i.test(attribute.name)) {
        continue;
      }
      domSignals.push({
        label: attribute.name,
        value: {
          tagName: element.tagName.toLowerCase(),
          value: attribute.value.slice(0, 500)
        }
      });
      if (domSignals.length >= maxDomSignals) break;
    }
    element = domWalker?.nextNode() as Element | null;
  }
  if (element) {
    warnings.push(
      `DOM signal enumeration stopped after ${inspectedDomElementCount} elements and ${domSignals.length} retained signals.`
    );
  }
  if (attributeCapReached) {
    warnings.push(
      `At least one inspected element exceeded the ${maxInspectedAttributesPerElement}-attribute inspection cap.`
    );
  }

  return {
    pageUrl: location.href,
    origin: location.origin,
    title: document.title,
    documentContentType,
    rawDocumentSource,
    loadedScriptUrls: [...loadedScriptUrls],
    inlineScripts,
    storageEntries,
    runtimeGlobals,
    domSignals,
    warnings
  };

  function cloneJsonLike(
    value: unknown,
    depth: number,
    budget: { remaining: number }
  ): JsonValue | undefined {
    if (budget.remaining <= 0 || depth > 5) {
      return undefined;
    }
    budget.remaining -= 1;

    if (value === null || typeof value === 'boolean' || typeof value === 'number') {
      return value;
    }
    if (typeof value === 'string') {
      return value.slice(0, 1000);
    }
    if (Array.isArray(value)) {
      return value
        .slice(0, 100)
        .map((entry) => cloneJsonLike(entry, depth + 1, budget) ?? null);
    }
    if (typeof value !== 'object' || value === null) {
      return undefined;
    }

    const output: Record<string, JsonValue> = {};
    const record = value as Record<string, unknown>;
    let inspectedEntryCount = 0;
    try {
      for (const key in record) {
        if (!Object.prototype.hasOwnProperty.call(record, key)) continue;
        const cloned = cloneJsonLike(record[key], depth + 1, budget);
        if (cloned !== undefined) {
          output[key] = cloned;
        }
        inspectedEntryCount += 1;
        if (inspectedEntryCount >= 200 || budget.remaining <= 0) break;
      }
    } catch {
      return Object.keys(output).length > 0 ? output : undefined;
    }
    return output;
  }
}
