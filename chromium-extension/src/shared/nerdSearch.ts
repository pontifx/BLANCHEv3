export type NerdSearchSurfaceMode = 'get' | 'form' | 'template';

export type NerdSearchProviderId =
  | 'google-programmable-search'
  | 'algolia'
  | 'elastic-app-search'
  | 'azure-search'
  | 'solr'
  | 'typesense'
  | 'meilisearch'
  | 'swiftype'
  | 'custom';

export interface NerdSearchProviderFingerprint {
  provider: NerdSearchProviderId;
  label: string;
  confidence: 'high' | 'medium' | 'low';
  evidence: string[];
}

export interface NerdSearchCandidate {
  id: string;
  name: string;
  mode: Exclude<NerdSearchSurfaceMode, 'template'>;
  pageUrl: string;
  actionUrl: string;
  method: 'get' | 'post' | 'dynamic';
  inputSelector: string;
  formSelector?: string;
  submitSelector?: string;
  queryParam?: string;
  fixedParams: Record<string, string>;
  providerFingerprint?: NerdSearchProviderFingerprint;
}

export interface NerdSearchSurface {
  id: string;
  name: string;
  mode: NerdSearchSurfaceMode;
  pageUrl: string;
  actionUrl: string;
  method: 'get' | 'post' | 'dynamic';
  inputSelector?: string;
  formSelector?: string;
  submitSelector?: string;
  queryParam?: string;
  fixedParams: Record<string, string>;
  providerFingerprint?: NerdSearchProviderFingerprint;
  urlTemplate?: string;
  createdAt: string;
  updatedAt: string;
}

export interface NerdFormSubmission {
  surfaceId: string;
  surfaceName: string;
  pageUrl: string;
  inputSelector: string;
  formSelector?: string;
  submitSelector?: string;
}

const MAX_SURFACE_NAME_LENGTH = 120;
const MAX_SELECTOR_LENGTH = 1024;
const MAX_FIXED_PARAMS = 30;

export function createNerdSearchSurface(candidate: NerdSearchCandidate): NerdSearchSurface {
  const normalized = normalizeCandidate(candidate);
  if (!normalized) {
    throw new Error('The selected page search control is no longer a valid Site Search surface.');
  }

  const timestamp = new Date().toISOString();
  return {
    ...normalized,
    id: createId('nerd'),
    createdAt: timestamp,
    updatedAt: timestamp
  };
}

export function createNerdSearchSurfaceFromTemplate(input: {
  name: string;
  urlTemplate: string;
}): NerdSearchSurface {
  const name = normalizeName(input.name);
  const urlTemplate = normalizeUrlTemplate(input.urlTemplate);
  if (!name) {
    throw new Error('Add a name for the Site Search surface.');
  }
  if (!urlTemplate) {
    throw new Error(
      'Use one http(s) search URL containing exactly one {query} placeholder.'
    );
  }

  const exampleUrl = urlTemplate.replace('{query}', 'blanche-query');
  const timestamp = new Date().toISOString();
  return {
    id: createId('nerd'),
    name,
    mode: 'template',
    pageUrl: exampleUrl,
    actionUrl: exampleUrl,
    method: 'get',
    fixedParams: {},
    urlTemplate,
    createdAt: timestamp,
    updatedAt: timestamp
  };
}

export function normalizeNerdSearchSurfaces(value: unknown): NerdSearchSurface[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const seen = new Set<string>();
  const surfaces: NerdSearchSurface[] = [];
  for (const entry of value) {
    const surface = normalizeNerdSearchSurface(entry);
    if (!surface || seen.has(surface.id)) {
      continue;
    }
    seen.add(surface.id);
    surfaces.push(surface);
    if (surfaces.length >= 30) {
      break;
    }
  }
  return surfaces;
}

export function normalizeNerdSearchSurface(value: unknown): NerdSearchSurface | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const id = normalizeIdentifier(value.id);
  const name = normalizeName(value.name);
  const mode = normalizeMode(value.mode);
  const queryParam = normalizeQueryParam(value.queryParam);
  const excludedUrlParams = queryParam ? [queryParam] : [];
  const pageUrl = normalizeHttpUrl(value.pageUrl, excludedUrlParams);
  const actionUrl = normalizeHttpUrl(value.actionUrl, excludedUrlParams);
  const method = normalizeMethod(value.method);
  const createdAt = normalizeTimestamp(value.createdAt);
  const updatedAt = normalizeTimestamp(value.updatedAt);
  if (!id || !name || !mode || !pageUrl || !actionUrl || !createdAt || !updatedAt) {
    return undefined;
  }

  const fixedParams = normalizeFixedParams(value.fixedParams);
  if (mode === 'template') {
    const urlTemplate = normalizeUrlTemplate(value.urlTemplate);
    if (!urlTemplate) {
      return undefined;
    }
    return {
      id,
      name,
      mode,
      pageUrl,
      actionUrl,
      method: 'get',
      fixedParams,
      providerFingerprint: normalizeProviderFingerprint(value.providerFingerprint),
      urlTemplate,
      createdAt,
      updatedAt
    };
  }

  const inputSelector = normalizeSelector(value.inputSelector);
  if (!inputSelector) {
    return undefined;
  }
  const formSelector = normalizeSelector(value.formSelector);
  const submitSelector = normalizeSelector(value.submitSelector);
  if (mode === 'get' && !queryParam) {
    return undefined;
  }

  return {
    id,
    name,
    mode,
    pageUrl,
    actionUrl,
    method,
    inputSelector,
    formSelector,
    submitSelector,
    queryParam,
    fixedParams,
    providerFingerprint: normalizeProviderFingerprint(value.providerFingerprint),
    createdAt,
    updatedAt
  };
}

export function buildNerdSearchUrl(surface: NerdSearchSurface, query: string): string {
  const normalizedQuery = query.trim().replace(/\s+/g, ' ');
  if (!normalizedQuery) {
    throw new Error('Site Search cannot launch an empty query.');
  }

  if (surface.mode === 'template') {
    const template = normalizeUrlTemplate(surface.urlTemplate);
    if (!template) {
      throw new Error(`Site Search surface ${surface.name} has an invalid URL template.`);
    }
    return template.replace('{query}', encodeURIComponent(normalizedQuery));
  }

  if (surface.mode === 'get') {
    const queryParam = normalizeQueryParam(surface.queryParam);
    if (!queryParam) {
      throw new Error(`Site Search surface ${surface.name} is missing its query parameter.`);
    }
    const url = new URL(surface.actionUrl);
    for (const [key, value] of Object.entries(surface.fixedParams)) {
      url.searchParams.set(key, value);
    }
    url.searchParams.set(queryParam, normalizedQuery);
    return url.toString();
  }

  return surface.pageUrl;
}

export function getNerdSearchSurfaceTarget(surface: NerdSearchSurface): string {
  return new URL(surface.pageUrl).hostname.toLowerCase();
}

export function buildNerdFormSubmission(
  surface: NerdSearchSurface
): NerdFormSubmission | undefined {
  if (surface.mode !== 'form' || !surface.inputSelector) {
    return undefined;
  }
  return {
    surfaceId: surface.id,
    surfaceName: surface.name,
    pageUrl: surface.pageUrl,
    inputSelector: surface.inputSelector,
    formSelector: surface.formSelector,
    submitSelector: surface.submitSelector
  };
}

/**
 * This function is passed directly to chrome.scripting.executeScript. Keep all helpers nested so
 * the serialized function has no module-scope dependencies in the inspected page.
 */
export function discoverNerdSearchSurfacesOnPage(): NerdSearchCandidate[] {
  const escapeIdentifier = (value: string): string => {
    if (globalThis.CSS?.escape) {
      return globalThis.CSS.escape(value);
    }
    return value.replace(/[^a-zA-Z0-9_-]/g, (character) => `\\${character}`);
  };
  const escapeAttribute = (value: string): string =>
    value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const selectorFor = (element: Element | null): string | undefined => {
    if (!element) {
      return undefined;
    }
    if (element.id) {
      return `#${escapeIdentifier(element.id)}`;
    }
    const tagName = element.tagName.toLowerCase();
    const name = element.getAttribute('name');
    if (name) {
      const candidate = `${tagName}[name="${escapeAttribute(name)}"]`;
      try {
        if (document.querySelectorAll(candidate).length === 1) {
          return candidate;
        }
      } catch {
        // Fall through to a structural selector.
      }
    }

    const parts: string[] = [];
    let current: Element | null = element;
    while (current && current !== document.documentElement && parts.length < 6) {
      const currentTag = current.tagName.toLowerCase();
      const parentElement: HTMLElement | null = current.parentElement;
      if (!parentElement) {
        break;
      }
      const currentTagName = current.tagName;
      const sameTagSiblings: Element[] = Array.from(parentElement.children).filter(
        (sibling: Element) => sibling.tagName === currentTagName
      );
      const index = sameTagSiblings.indexOf(current);
      parts.unshift(
        sameTagSiblings.length > 1 ? `${currentTag}:nth-of-type(${index + 1})` : currentTag
      );
      const candidate = parts.join(' > ');
      try {
        if (document.querySelectorAll(candidate).length === 1) {
          return candidate;
        }
      } catch {
        // Continue building a more specific path.
      }
      current = parentElement;
    }
    return parts.length ? parts.join(' > ') : undefined;
  };
  const readableLabel = (input: HTMLInputElement): string => {
    const explicitLabel = input.id
      ? document.querySelector<HTMLLabelElement>(`label[for="${escapeAttribute(input.id)}"]`)
      : undefined;
    const wrappedLabel = input.closest('label');
    return (
      input.getAttribute('aria-label') ||
      explicitLabel?.innerText ||
      wrappedLabel?.innerText ||
      input.placeholder ||
      input.name ||
      'Search'
    )
      .trim()
      .replace(/\s+/g, ' ')
      .slice(0, 120);
  };
  const scoreInput = (input: HTMLInputElement): number => {
    const descriptor = [
      input.type,
      input.name,
      input.id,
      input.placeholder,
      input.getAttribute('aria-label'),
      input.autocomplete,
      input.closest('[role="search"]') ? 'role-search' : '',
      input.form?.getAttribute('role') ?? ''
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    let score = input.type === 'search' ? 8 : 0;
    if (/\b(search|query|keyword|lookup|find)\b/.test(descriptor)) score += 5;
    if (/\b(q|s|term)\b/.test(descriptor)) score += 2;
    if (input.closest('[role="search"]') || input.form?.getAttribute('role') === 'search') score += 4;
    if (input.type === 'email' || input.type === 'password' || input.type === 'hidden') score -= 20;
    if (input.disabled || input.hidden) score -= 20;
    return score;
  };
  const fixedFormParams = (
    form: HTMLFormElement,
    queryInput: HTMLInputElement
  ): Record<string, string> => {
    const output: Record<string, string> = {};
    for (const control of Array.from(form.elements).slice(0, 80)) {
      if (control === queryInput || !(control instanceof HTMLElement)) {
        continue;
      }
      const named = control as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
      const name = named.getAttribute('name')?.trim();
      if (!name || name in output || Object.keys(output).length >= 30) {
        continue;
      }
      if (/(?:csrf|xsrf|token|secret|password|passwd|session|auth|api[-_]?key)/i.test(name)) {
        continue;
      }
      if (named instanceof HTMLInputElement) {
        if (named.type !== 'checkbox' && named.type !== 'radio') continue;
        if (!named.checked) continue;
      } else if (!(named instanceof HTMLSelectElement)) {
        continue;
      }
      output[name] = named.value;
    }
    return output;
  };
  const providerFingerprint = (): NerdSearchProviderFingerprint => {
    const evidence: string[] = [];
    const resources = Array.from(document.scripts)
      .map((script) => script.src)
      .concat(
        Array.from(document.querySelectorAll<HTMLLinkElement>('link[href]')).map(
          (link) => link.href
        ),
        Array.from(document.forms).map((form) => form.action),
        globalThis.performance
          ?.getEntriesByType('resource')
          .map((entry) => entry.name)
          .slice(0, 250) ?? []
      )
      .filter(Boolean)
      .slice(0, 400);
    const record = (label: string): void => {
      if (!evidence.includes(label) && evidence.length < 6) evidence.push(label);
    };
    const resourceMatches = (pattern: RegExp, label: string): boolean => {
      const matched = resources.some((url) => pattern.test(url));
      if (matched) record(label);
      return matched;
    };
    const selectorMatches = (selector: string, label: string): boolean => {
      let matched = false;
      try {
        matched = Boolean(document.querySelector(selector));
      } catch {
        matched = false;
      }
      if (matched) record(label);
      return matched;
    };
    const result = (
      provider: NerdSearchProviderFingerprint['provider'],
      label: string,
      confidence: NerdSearchProviderFingerprint['confidence']
    ): NerdSearchProviderFingerprint => ({ provider, label, confidence, evidence: evidence.slice(0, 6) });

    if (
      resourceMatches(/\/\/cse\.google\.com\/cse\.js/i, 'cse.google.com script') ||
      selectorMatches('.gcse-search, .gsc-control-cse, [data-gname]', 'Google CSE DOM marker')
    ) return result('google-programmable-search', 'Google Programmable Search', 'medium');
    if (
      resourceMatches(/(?:algolia|algoliasearch|instantsearch)/i, 'Algolia client resource') ||
      selectorMatches('[class*="ais-"]', 'Algolia InstantSearch DOM marker')
    ) return result('algolia', 'Algolia', 'medium');
    if (
      resourceMatches(/(?:elastic(?:%2f|\/)search-ui|elastic[-_.]search-ui|search-ui[^/]*elastic|app-search-(?:javascript|reference-ui)|elastic-enterprise-search)/i, 'Elastic Search UI resource') ||
      selectorMatches('[data-elastic-search-ui], [class*="sui-search"]', 'Elastic Search UI DOM marker')
    ) return result('elastic-app-search', 'Elastic / App Search', 'medium');
    if (
      resourceMatches(/(?:search\.windows\.net|azure[-_.]?search)/i, 'Azure AI Search resource') ||
      selectorMatches('[data-azure-search]', 'Azure Search DOM marker')
    ) return result('azure-search', 'Azure AI Search', 'medium');
    if (
      resourceMatches(/(?:\/solr\/|solr[-_.])/i, 'Solr resource') ||
      selectorMatches('[data-solr], [class*="solr-search"]', 'Solr DOM marker')
    ) return result('solr', 'Apache Solr', 'medium');
    if (
      resourceMatches(/typesense/i, 'Typesense resource') ||
      selectorMatches('[data-typesense], [class*="typesense"]', 'Typesense DOM marker')
    ) return result('typesense', 'Typesense', 'medium');
    if (
      resourceMatches(/meilisearch|meili[-_.]?search/i, 'Meilisearch resource') ||
      selectorMatches('[data-meilisearch], [class*="meilisearch"]', 'Meilisearch DOM marker')
    ) return result('meilisearch', 'Meilisearch', 'medium');
    if (
      resourceMatches(/swiftype/i, 'Swiftype resource') ||
      selectorMatches('.st-default-search-input, [data-swiftype]', 'Swiftype DOM marker')
    ) return result('swiftype', 'Swiftype', 'medium');
    return {
      provider: 'custom',
      label: 'Unknown / custom',
      confidence: 'low',
      evidence: ['No recognized provider marker in top-frame DOM or loaded resources']
    };
  };

  const fingerprint = providerFingerprint();

  const candidates: NerdSearchCandidate[] = [];
  const seen = new Set<string>();
  const inputs = Array.from(
    document.querySelectorAll<HTMLInputElement>(
      'input[type="search"], [role="search"] input, form input[name], input[placeholder]'
    )
  )
    .map((input) => ({ input, score: scoreInput(input) }))
    .filter((entry) => entry.score >= 5)
    .sort((left, right) => right.score - left.score)
    .slice(0, 20);

  for (const { input } of inputs) {
    const inputSelector = selectorFor(input);
    if (!inputSelector || seen.has(inputSelector)) {
      continue;
    }
    seen.add(inputSelector);
    const form = input.form;
    const formSelector = selectorFor(form);
    const submit =
      form?.querySelector<HTMLElement>(
        'button[type="submit"], input[type="submit"], button:not([type])'
      ) ?? input.closest('[role="search"]')?.querySelector<HTMLElement>('button');
    const submitSelector = selectorFor(submit ?? null);
    const method = form?.method?.toLowerCase() === 'post' ? 'post' : form ? 'get' : 'dynamic';
    let actionUrl = location.href;
    try {
      actionUrl = new URL(form?.action || location.href, location.href).toString();
    } catch {
      actionUrl = location.href;
    }
    const queryParam = input.name?.trim() || undefined;
    const useGet = method === 'get' && Boolean(queryParam);
    const label = readableLabel(input);
    const host = location.hostname || 'current site';
    candidates.push({
      id: `candidate-${candidates.length + 1}`,
      name: `${host}: ${label}`,
      mode: useGet ? 'get' : 'form',
      pageUrl: location.href,
      actionUrl,
      method,
      inputSelector,
      formSelector,
      submitSelector,
      queryParam,
      fixedParams: form ? fixedFormParams(form, input) : {},
      providerFingerprint: fingerprint
    });
  }

  return candidates;
}

/** Runs in the inspected page. It must remain independent of module-scope bindings. */
export function highlightNerdSearchSurfaceOnPage(
  selector: string
): { highlighted: boolean; reason?: string } {
  const marker = 'data-blanche-search-highlight';
  const styleId = 'blanche-search-highlight-style';
  const token = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const clean = (): void => {
    document.querySelectorAll(`[${marker}]`).forEach((element) => element.removeAttribute(marker));
    document.getElementById(styleId)?.remove();
  };
  clean();
  if (typeof selector !== 'string' || !selector.trim() || selector.length > 1024) {
    return { highlighted: false, reason: 'The top-frame search selector is invalid.' };
  }
  let element: Element | null = null;
  try {
    element = document.querySelector(selector);
  } catch {
    return { highlighted: false, reason: 'The top-frame search selector is not valid CSS.' };
  }
  if (!(element instanceof HTMLElement)) {
    return { highlighted: false, reason: 'The search control is no longer in the top frame.' };
  }
  const style = document.createElement('style');
  style.id = styleId;
  style.dataset.blancheSearchHighlightToken = token;
  style.textContent = `
    @keyframes blanche-search-pulse { 50% { outline-color: #ffffff; box-shadow: 0 0 0 8px rgba(255, 63, 129, .18); } }
    [${marker}] { outline: 4px solid #ff3f81 !important; outline-offset: 4px !important; box-shadow: 0 0 0 3px rgba(20, 15, 34, .9) !important; animation: blanche-search-pulse .75s ease-in-out infinite !important; }
  `;
  (document.head || document.documentElement).appendChild(style);
  element.setAttribute(marker, token);
  element.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' });
  globalThis.setTimeout(() => {
    if (element?.getAttribute(marker) === token) element.removeAttribute(marker);
    const currentStyle = document.getElementById(styleId);
    if (currentStyle?.dataset.blancheSearchHighlightToken === token) currentStyle.remove();
  }, 4000);
  return { highlighted: true };
}

/** Runs in the inspected page. It must remain independent of module-scope bindings. */
export async function pickNerdSearchSurfaceOnPage(): Promise<{
  selector?: string;
  reason?: string;
}> {
  const marker = 'data-blanche-search-picker';
  const styleId = 'blanche-search-picker-style';
  const pickerKey = '__blancheCancelTopFrameSearchPicker';
  const pickerGlobal = globalThis as typeof globalThis & Record<string, (() => void) | undefined>;
  pickerGlobal[pickerKey]?.();
  const escapeIdentifier = (value: string): string => {
    if (globalThis.CSS?.escape) return globalThis.CSS.escape(value);
    return value.replace(/[^a-zA-Z0-9_-]/g, (character) => `\\${character}`);
  };
  const escapeAttribute = (value: string): string =>
    value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const selectorFor = (element: Element): string | undefined => {
    if (element.id) return `#${escapeIdentifier(element.id)}`;
    const tagName = element.tagName.toLowerCase();
    const name = element.getAttribute('name');
    if (name) {
      const candidate = `${tagName}[name="${escapeAttribute(name)}"]`;
      try {
        if (document.querySelectorAll(candidate).length === 1) return candidate;
      } catch {
        // Continue with a structural selector.
      }
    }
    const parts: string[] = [];
    let current: Element | null = element;
    while (current && current !== document.documentElement && parts.length < 6) {
      const parentElement: HTMLElement | null = current.parentElement;
      if (!parentElement) break;
      const currentTagName = current.tagName;
      const sameTag: Element[] = Array.from(parentElement.children).filter(
        (sibling: Element) => sibling.tagName === currentTagName
      );
      const index = sameTag.indexOf(current);
      parts.unshift(
        sameTag.length > 1
          ? `${current.tagName.toLowerCase()}:nth-of-type(${index + 1})`
          : current.tagName.toLowerCase()
      );
      const candidate = parts.join(' > ');
      try {
        if (document.querySelectorAll(candidate).length === 1) return candidate;
      } catch {
        // Continue building the path.
      }
      current = parentElement;
    }
    return parts.length ? parts.join(' > ').slice(0, 1024) : undefined;
  };
  const scoreInput = (input: HTMLInputElement): number => {
    const descriptor = [
      input.type,
      input.name,
      input.id,
      input.placeholder,
      input.getAttribute('aria-label'),
      input.autocomplete,
      input.closest('[role="search"]') ? 'role-search' : '',
      input.form?.getAttribute('role') ?? ''
    ].filter(Boolean).join(' ').toLowerCase();
    let score = input.type === 'search' ? 8 : 0;
    if (/\b(search|query|keyword|lookup|find)\b/.test(descriptor)) score += 5;
    if (/\b(q|s|term)\b/.test(descriptor)) score += 2;
    if (input.closest('[role="search"]') || input.form?.getAttribute('role') === 'search') score += 4;
    if (input.type === 'email' || input.type === 'password' || input.type === 'hidden') score -= 20;
    if (input.disabled || input.hidden) score -= 20;
    return score;
  };

  document.querySelectorAll(`[${marker}]`).forEach((element) => element.removeAttribute(marker));
  document.getElementById(styleId)?.remove();
  const eligible = Array.from(document.querySelectorAll<HTMLInputElement>(
    'input[type="search"], [role="search"] input, form input[name], input[placeholder]'
  ))
    .map((input) => ({ input, score: scoreInput(input) }))
    .filter((entry) => entry.score >= 5)
    .sort((left, right) => right.score - left.score)
    .slice(0, 20)
    .map((entry) => entry.input);
  if (!eligible.length) {
    return { reason: 'No eligible search controls were found in the top frame.' };
  }
  const eligibleSet = new Set<Element>(eligible);
  const style = document.createElement('style');
  style.id = styleId;
  style.textContent = `
    [${marker}="eligible"] { outline: 2px dashed rgba(255, 63, 129, .65) !important; outline-offset: 3px !important; cursor: crosshair !important; }
    [${marker}="active"] { outline: 4px solid #ff3f81 !important; outline-offset: 4px !important; box-shadow: 0 0 0 4px rgba(20, 15, 34, .9) !important; cursor: crosshair !important; }
  `;
  (document.head || document.documentElement).appendChild(style);
  eligible.forEach((input) => input.setAttribute(marker, 'eligible'));

  return await new Promise((resolve) => {
    let settled = false;
    let timeoutId: ReturnType<typeof globalThis.setTimeout> | undefined;
    let cancelCurrent: (() => void) | undefined;
    const setActive = (target: EventTarget | null): void => {
      const active = target instanceof Element ? target.closest('input') : null;
      eligible.forEach((input) =>
        input.setAttribute(marker, input === active && eligibleSet.has(input) ? 'active' : 'eligible')
      );
    };
    const cleanup = (): void => {
      if (timeoutId !== undefined) globalThis.clearTimeout(timeoutId);
      document.removeEventListener('pointerover', onPointerOver, true);
      document.removeEventListener('focusin', onFocusIn, true);
      document.removeEventListener('click', onClick, true);
      document.removeEventListener('keydown', onKeyDown, true);
      eligible.forEach((input) => input.removeAttribute(marker));
      document.getElementById(styleId)?.remove();
      if (cancelCurrent && pickerGlobal[pickerKey] === cancelCurrent) {
        delete pickerGlobal[pickerKey];
      }
    };
    const finish = (result: { selector?: string; reason?: string }): void => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(result);
    };
    const onPointerOver = (event: Event): void => setActive(event.target);
    const onFocusIn = (event: Event): void => setActive(event.target);
    const onClick = (event: MouseEvent): void => {
      const input = event.target instanceof Element ? event.target.closest('input') : null;
      if (!input || !eligibleSet.has(input)) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      const selector = selectorFor(input);
      finish(
        selector && selector.length <= 1024
          ? { selector }
          : { reason: 'The selected top-frame control did not have a stable bounded selector.' }
      );
    };
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      event.stopImmediatePropagation();
      finish({ reason: 'Top-frame search selection was cancelled with Escape.' });
    };
    document.addEventListener('pointerover', onPointerOver, true);
    document.addEventListener('focusin', onFocusIn, true);
    document.addEventListener('click', onClick, true);
    document.addEventListener('keydown', onKeyDown, true);
    timeoutId = globalThis.setTimeout(
      () => finish({ reason: 'Top-frame search selection timed out after 30 seconds.' }),
      30000
    );
    cancelCurrent = () => finish({ reason: 'Top-frame search selection was replaced by a newer picker.' });
    pickerGlobal[pickerKey] = cancelCurrent;
  });
}

export function submitNerdSearchForm(
  submission: NerdFormSubmission,
  query: string
): { submitted: boolean; reason?: string } {
  const input = document.querySelector<HTMLInputElement | HTMLTextAreaElement>(
    submission.inputSelector
  );
  if (!input) {
    return { submitted: false, reason: 'The captured search input is no longer present.' };
  }

  const prototype = input instanceof HTMLTextAreaElement
    ? HTMLTextAreaElement.prototype
    : HTMLInputElement.prototype;
  const valueSetter = Object.getOwnPropertyDescriptor(prototype, 'value')?.set;
  if (valueSetter) {
    valueSetter.call(input, query);
  } else {
    input.value = query;
  }
  input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
  input.dispatchEvent(new Event('change', { bubbles: true, composed: true }));

  const submitter = submission.submitSelector
    ? document.querySelector<HTMLElement>(submission.submitSelector)
    : undefined;
  if (submitter) {
    submitter.click();
    return { submitted: true };
  }

  const form = submission.formSelector
    ? document.querySelector<HTMLFormElement>(submission.formSelector)
    : input.closest('form');
  if (form) {
    form.requestSubmit();
    return { submitted: true };
  }

  input.dispatchEvent(
    new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', bubbles: true, composed: true })
  );
  input.dispatchEvent(
    new KeyboardEvent('keyup', { key: 'Enter', code: 'Enter', bubbles: true, composed: true })
  );
  return { submitted: true };
}

function normalizeCandidate(value: NerdSearchCandidate): Omit<NerdSearchSurface, 'createdAt' | 'updatedAt'> | undefined {
  const name = normalizeName(value.name);
  const mode = value.mode === 'get' ? 'get' : value.mode === 'form' ? 'form' : undefined;
  const queryParam = normalizeQueryParam(value.queryParam);
  const excludedUrlParams = queryParam ? [queryParam] : [];
  const pageUrl = normalizeHttpUrl(value.pageUrl, excludedUrlParams);
  const actionUrl = normalizeHttpUrl(value.actionUrl, excludedUrlParams);
  const method = normalizeMethod(value.method);
  const inputSelector = normalizeSelector(value.inputSelector);
  if (!name || !mode || !pageUrl || !actionUrl || !inputSelector || (mode === 'get' && !queryParam)) {
    return undefined;
  }
  return {
    id: normalizeIdentifier(value.id) ?? 'candidate',
    name,
    mode,
    pageUrl,
    actionUrl,
    method,
    inputSelector,
    formSelector: normalizeSelector(value.formSelector),
    submitSelector: normalizeSelector(value.submitSelector),
    queryParam,
    fixedParams: normalizeFixedParams(value.fixedParams),
    providerFingerprint: normalizeProviderFingerprint(value.providerFingerprint)
  };
}

function normalizeProviderFingerprint(value: unknown): NerdSearchProviderFingerprint | undefined {
  if (!isRecord(value)) return undefined;
  const providers: NerdSearchProviderId[] = [
    'google-programmable-search', 'algolia', 'elastic-app-search', 'azure-search', 'solr',
    'typesense', 'meilisearch', 'swiftype', 'custom'
  ];
  const provider = providers.includes(value.provider as NerdSearchProviderId)
    ? value.provider as NerdSearchProviderId
    : undefined;
  const label = normalizeName(value.label);
  const confidence = value.confidence === 'high' || value.confidence === 'medium' || value.confidence === 'low'
    ? value.confidence
    : undefined;
  if (!provider || !label || !confidence) return undefined;
  const evidence = Array.isArray(value.evidence)
    ? value.evidence
      .filter((entry): entry is string => typeof entry === 'string')
      .map((entry) => entry.trim().replace(/\s+/g, ' ').slice(0, 180))
      .filter(Boolean)
      .slice(0, 6)
    : [];
  return { provider, label, confidence, evidence };
}

function normalizeMode(value: unknown): NerdSearchSurfaceMode | undefined {
  return value === 'get' || value === 'form' || value === 'template' ? value : undefined;
}

function normalizeMethod(value: unknown): NerdSearchSurface['method'] {
  return value === 'post' || value === 'dynamic' ? value : 'get';
}

function normalizeName(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().replace(/\s+/g, ' ').slice(0, MAX_SURFACE_NAME_LENGTH);
  return normalized || undefined;
}

function normalizeIdentifier(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().slice(0, 180);
  return normalized || undefined;
}

function normalizeSelector(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().slice(0, MAX_SELECTOR_LENGTH);
  return normalized || undefined;
}

function normalizeQueryParam(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().slice(0, 160);
  return normalized || undefined;
}

function normalizeTimestamp(value: unknown): string | undefined {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) return undefined;
  return value;
}

function normalizeHttpUrl(value: unknown, excludedParams: readonly string[] = []): string | undefined {
  if (typeof value !== 'string') return undefined;
  try {
    const url = new URL(value.trim());
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return undefined;
    if (url.username || url.password) return undefined;
    url.hash = '';
    const excluded = new Set(excludedParams.map((entry) => entry.toLowerCase()));
    for (const key of [...url.searchParams.keys()]) {
      if (excluded.has(key.toLowerCase()) || isSensitiveParamName(key)) {
        url.searchParams.delete(key);
      }
    }
    return url.toString();
  } catch {
    return undefined;
  }
}

function normalizeUrlTemplate(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().replace(/%7Bquery%7D/gi, '{query}');
  if ((normalized.match(/\{query\}/g) ?? []).length !== 1) return undefined;
  const placeholder = 'BLANCHE_QUERY_PLACEHOLDER';
  const sanitized = normalizeHttpUrl(normalized.replace('{query}', placeholder));
  if (!sanitized || !sanitized.includes(placeholder)) return undefined;
  return sanitized.replace(placeholder, '{query}');
}

function normalizeFixedParams(value: unknown): Record<string, string> {
  if (!isRecord(value)) return {};
  const output: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value).slice(0, MAX_FIXED_PARAMS)) {
    const normalizedKey = key.trim().slice(0, 160);
    if (
      !normalizedKey ||
      typeof entry !== 'string' ||
      isSensitiveParamName(normalizedKey)
    ) continue;
    output[normalizedKey] = entry.slice(0, 1000);
  }
  return output;
}

function isSensitiveParamName(value: string): boolean {
  return /(?:csrf|xsrf|token|secret|password|passwd|session|auth|api[-_]?key)/i.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function createId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}
