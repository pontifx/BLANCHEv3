import {
  normalizeNerdSearchSurfaces,
  type NerdSearchSurface
} from './nerdSearch';

export type SearchEngineId =
  | 'google'
  | 'bing'
  | 'duckduckgo'
  | 'yahoo'
  | 'shodan'
  | 'crtsh';

export type SearchLaunchMode = 'combined' | 'per-target';

export interface SearchEngineDefinition {
  id: SearchEngineId;
  name: string;
  iconLabel: string;
  accentColor: string;
  defaultSelected: boolean;
  targetTemplate: string;
  queryParam: string;
  searchBaseUrl: string;
  description: string;
}

export interface SearchOperatorDefinition {
  id: string;
  label: string;
  template: string;
  description: string;
  category: 'scope' | 'content' | 'exclude' | 'intel' | 'certificate';
  engineIds: SearchEngineId[];
  isCustom?: boolean;
}

export interface SearchQueryDraft {
  name: string;
  targetsText: string;
  queryText: string;
  selectedEngineIds: SearchEngineId[];
  launchMode: SearchLaunchMode;
  openInBackground: boolean;
}

export type DorkSuiteCategoryId =
  | 'auth-surfaces'
  | 'indexed-documents'
  | 'api-surface'
  | 'client-artifacts'
  | 'directory-listings'
  | 'recent-changes';

export interface DorkSuiteDraft {
  categoryIds: DorkSuiteCategoryId[];
  keywordsText: string;
  maxQueries: number;
}

export interface SavedSearchProfile extends SearchQueryDraft {
  id: string;
  createdAt: string;
  updatedAt: string;
}

export interface CustomSearchOperatorDefinition extends SearchOperatorDefinition {
  isCustom: true;
  createdAt: string;
  updatedAt: string;
}

export interface SearchWorkbenchState {
  draft: SearchQueryDraft;
  dorkSuiteDraft: DorkSuiteDraft;
  savedProfiles: SavedSearchProfile[];
  customOperators: CustomSearchOperatorDefinition[];
  nerdSurfaces: NerdSearchSurface[];
  selectedNerdSurfaceId?: string;
}

export interface SearchLaunchPlan {
  id: string;
  engine: SearchEngineDefinition;
  target?: string;
  query: string;
  url: string;
}

const WEB_ENGINE_IDS: SearchEngineId[] = ['google', 'bing', 'duckduckgo', 'yahoo'];
const DEFAULT_DORK_SUITE_CATEGORY_IDS: DorkSuiteCategoryId[] = [
  'auth-surfaces',
  'indexed-documents',
  'api-surface',
  'client-artifacts',
  'directory-listings',
  'recent-changes'
];
const DEFAULT_PROFILE_TIMESTAMP = '2026-01-01T00:00:00.000Z';

export const SEARCH_ENGINES: SearchEngineDefinition[] = [
  {
    id: 'google',
    name: 'Google',
    iconLabel: 'G',
    accentColor: '#5ea3ff',
    defaultSelected: true,
    targetTemplate: 'site:{target}',
    queryParam: 'q',
    searchBaseUrl: 'https://www.google.com/search',
    description: 'General web indexing with familiar dorking operators.'
  },
  {
    id: 'bing',
    name: 'Bing',
    iconLabel: 'B',
    accentColor: '#6de1d2',
    defaultSelected: false,
    targetTemplate: 'site:{target}',
    queryParam: 'q',
    searchBaseUrl: 'https://www.bing.com/search',
    description: 'Alternative web index with broad overlap and different ranking.'
  },
  {
    id: 'duckduckgo',
    name: 'DuckDuckGo',
    iconLabel: 'D',
    accentColor: '#de5833',
    defaultSelected: false,
    targetTemplate: 'site:{target}',
    queryParam: 'q',
    searchBaseUrl: 'https://duckduckgo.com/',
    description: 'Privacy-focused metasearch with distinct, relevance-weighted operator semantics.'
  },
  {
    id: 'yahoo',
    name: 'Yahoo',
    iconLabel: 'Y!',
    accentColor: '#bf8cff',
    defaultSelected: false,
    targetTemplate: 'site:{target}',
    queryParam: 'p',
    searchBaseUrl: 'https://search.yahoo.com/search',
    description: 'Additional SERP coverage and query variations.'
  },
  {
    id: 'shodan',
    name: 'Shodan',
    iconLabel: 'S',
    accentColor: '#ff8f70',
    defaultSelected: false,
    targetTemplate: 'hostname:"{target}"',
    queryParam: 'query',
    searchBaseUrl: 'https://www.shodan.io/search',
    description: 'Internet-exposed service search with host and banner filters.'
  },
  {
    id: 'crtsh',
    name: 'crt.sh',
    iconLabel: 'C',
    accentColor: '#ffd36e',
    defaultSelected: false,
    targetTemplate: '%.{target}',
    queryParam: 'q',
    searchBaseUrl: 'https://crt.sh/',
    description: 'Certificate transparency lookups for domain and subdomain identities.'
  }
];

export const DEFAULT_SEARCH_OPERATORS: SearchOperatorDefinition[] = [
  {
    id: 'scope-site',
    label: 'site:{target}',
    template: 'site:{target}',
    description: 'Restrict a web-engine query to the target site or host.',
    category: 'scope',
    engineIds: WEB_ENGINE_IDS
  },
  {
    id: 'scope-hostname',
    label: 'hostname:"{target}"',
    template: 'hostname:"{target}"',
    description: 'Restrict a Shodan query to the resolved hostname.',
    category: 'scope',
    engineIds: ['shodan']
  },
  {
    id: 'scope-crt-wildcard',
    label: '%.{target}',
    template: '%.{target}',
    description: 'Search crt.sh for wildcard subdomain certificate identities.',
    category: 'scope',
    engineIds: ['crtsh']
  },
  {
    id: 'content-intitle',
    label: 'intitle:"{value}"',
    template: 'intitle:"{value}"',
    description: 'Match pages with the given text in the title.',
    category: 'content',
    engineIds: WEB_ENGINE_IDS
  },
  {
    id: 'content-inurl',
    label: 'inurl:{value}',
    template: 'inurl:{value}',
    description: 'Match pages with the term in the path or URL.',
    category: 'content',
    engineIds: WEB_ENGINE_IDS
  },
  {
    id: 'content-filetype',
    label: 'filetype:pdf',
    template: 'filetype:pdf',
    description: 'Focus on a specific indexed document type.',
    category: 'content',
    engineIds: WEB_ENGINE_IDS
  },
  {
    id: 'content-exact',
    label: '"{value}"',
    template: '"{value}"',
    description: 'Search for an exact phrase.',
    category: 'content',
    engineIds: [...WEB_ENGINE_IDS, 'shodan']
  },
  {
    id: 'exclude-term',
    label: '-{value}',
    template: '-{value}',
    description: 'Exclude unwanted terms from the result set.',
    category: 'exclude',
    engineIds: [...WEB_ENGINE_IDS, 'shodan']
  },
  {
    id: 'intel-org',
    label: 'org:"{value}"',
    template: 'org:"{value}"',
    description: 'Filter Shodan results by organization owner.',
    category: 'intel',
    engineIds: ['shodan']
  },
  {
    id: 'intel-http-title',
    label: 'http.title:"{value}"',
    template: 'http.title:"{value}"',
    description: 'Filter Shodan banners by returned HTML title.',
    category: 'intel',
    engineIds: ['shodan']
  },
  {
    id: 'intel-product',
    label: 'product:"{value}"',
    template: 'product:"{value}"',
    description: 'Filter Shodan by banner-detected product name.',
    category: 'intel',
    engineIds: ['shodan']
  },
  {
    id: 'intel-ssl',
    label: 'ssl:"{value}"',
    template: 'ssl:"{value}"',
    description: 'Search certificate contents indexed by Shodan.',
    category: 'intel',
    engineIds: ['shodan']
  },
  {
    id: 'intel-port',
    label: 'port:443',
    template: 'port:443',
    description: 'Restrict Shodan results to a specific port.',
    category: 'intel',
    engineIds: ['shodan']
  },
  {
    id: 'certificate-exact',
    label: '{target}',
    template: '{target}',
    description: 'Query crt.sh for an exact certificate identity.',
    category: 'certificate',
    engineIds: ['crtsh']
  }
];

const SEARCH_ENGINE_BY_ID = new Map(SEARCH_ENGINES.map((engine) => [engine.id, engine]));

export const DEFAULT_OSINT_SEARCH_PROFILES: SavedSearchProfile[] = [
  {
    id: 'builtin-osint-public-footprint',
    name: 'Public Footprint Sweep',
    targetsText: '',
    queryText: '("login" OR "admin" OR "portal" OR "vpn" OR "sso" OR "remote access")',
    selectedEngineIds: ['google', 'bing', 'duckduckgo'],
    launchMode: 'combined',
    openInBackground: true,
    createdAt: DEFAULT_PROFILE_TIMESTAMP,
    updatedAt: DEFAULT_PROFILE_TIMESTAMP
  },
  {
    id: 'builtin-osint-documents-secrets',
    name: 'Documents and Secrets Sweep',
    targetsText: '',
    queryText:
      '(filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:csv) (confidential OR internal OR password OR credential OR token OR "api key")',
    selectedEngineIds: ['google', 'bing', 'duckduckgo'],
    launchMode: 'combined',
    openInBackground: true,
    createdAt: DEFAULT_PROFILE_TIMESTAMP,
    updatedAt: DEFAULT_PROFILE_TIMESTAMP
  },
  {
    id: 'builtin-osint-infra-certificates',
    name: 'Infrastructure and Certificates',
    targetsText: '',
    queryText: '',
    selectedEngineIds: ['shodan', 'crtsh'],
    launchMode: 'per-target',
    openInBackground: true,
    createdAt: DEFAULT_PROFILE_TIMESTAMP,
    updatedAt: DEFAULT_PROFILE_TIMESTAMP
  }
];

export function createDefaultSearchWorkbenchState(): SearchWorkbenchState {
  return {
    draft: createDefaultSearchDraft(),
    dorkSuiteDraft: createDefaultDorkSuiteDraft(),
    savedProfiles: [...DEFAULT_OSINT_SEARCH_PROFILES],
    customOperators: [],
    nerdSurfaces: []
  };
}

export function createDefaultDorkSuiteDraft(): DorkSuiteDraft {
  return {
    categoryIds: [...DEFAULT_DORK_SUITE_CATEGORY_IDS],
    keywordsText: '',
    maxQueries: 24
  };
}

export function createDefaultSearchDraft(): SearchQueryDraft {
  return {
    name: '',
    targetsText: '',
    queryText: '',
    selectedEngineIds: SEARCH_ENGINES.filter((engine) => engine.defaultSelected).map((engine) => engine.id),
    launchMode: 'combined',
    openInBackground: true
  };
}

export function normalizeSearchWorkbenchState(rawValue: unknown): SearchWorkbenchState {
  const fallback = createDefaultSearchWorkbenchState();
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return fallback;
  }

  const source = rawValue as Partial<SearchWorkbenchState>;
  const savedProfiles = Array.isArray(source.savedProfiles)
    ? source.savedProfiles
        .map((entry) => normalizeSavedSearchProfile(entry))
        .filter((entry): entry is SavedSearchProfile => Boolean(entry))
    : [];

  const nerdSurfaces = normalizeNerdSearchSurfaces(source.nerdSurfaces);
  const selectedNerdSurfaceId =
    typeof source.selectedNerdSurfaceId === 'string' &&
    nerdSurfaces.some((surface) => surface.id === source.selectedNerdSurfaceId)
      ? source.selectedNerdSurfaceId
      : nerdSurfaces[0]?.id;

  return {
    draft: normalizeSearchDraft(source.draft),
    dorkSuiteDraft: normalizeDorkSuiteDraft(source.dorkSuiteDraft),
    savedProfiles: mergeDefaultSearchProfiles(savedProfiles),
    customOperators: Array.isArray(source.customOperators)
      ? source.customOperators
          .map((entry) => normalizeCustomSearchOperator(entry))
          .filter((entry): entry is CustomSearchOperatorDefinition => Boolean(entry))
      : [],
    nerdSurfaces,
    selectedNerdSurfaceId
  };
}

export function normalizeDorkSuiteDraft(rawValue: unknown): DorkSuiteDraft {
  const fallback = createDefaultDorkSuiteDraft();
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return fallback;
  }

  const source = rawValue as Partial<DorkSuiteDraft>;
  const categories = new Set<DorkSuiteCategoryId>();
  if (Array.isArray(source.categoryIds)) {
    for (const entry of source.categoryIds) {
      if (isDorkSuiteCategoryId(entry)) {
        categories.add(entry);
      }
    }
  }
  const maxQueries =
    typeof source.maxQueries === 'number' && Number.isFinite(source.maxQueries)
      ? Math.min(60, Math.max(1, Math.floor(source.maxQueries)))
      : fallback.maxQueries;
  return {
    categoryIds: categories.size ? [...categories] : fallback.categoryIds,
    keywordsText: typeof source.keywordsText === 'string' ? source.keywordsText.slice(0, 1000) : '',
    maxQueries
  };
}

export function normalizeSearchDraft(rawValue: unknown): SearchQueryDraft {
  const fallback = createDefaultSearchDraft();
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return fallback;
  }

  const source = rawValue as Partial<SearchQueryDraft>;
  const selectedEngineIds = normalizeEngineIds(source.selectedEngineIds);
  return {
    name: typeof source.name === 'string' ? source.name : fallback.name,
    targetsText: typeof source.targetsText === 'string' ? source.targetsText : fallback.targetsText,
    queryText: typeof source.queryText === 'string' ? source.queryText : fallback.queryText,
    selectedEngineIds: selectedEngineIds.length > 0 ? selectedEngineIds : fallback.selectedEngineIds,
    launchMode: source.launchMode === 'per-target' ? 'per-target' : fallback.launchMode,
    openInBackground:
      typeof source.openInBackground === 'boolean' ? source.openInBackground : fallback.openInBackground
  };
}

export function getSearchOperators(
  customOperators: CustomSearchOperatorDefinition[] = []
): SearchOperatorDefinition[] {
  return [...DEFAULT_SEARCH_OPERATORS, ...customOperators].sort((left, right) =>
    left.label.localeCompare(right.label)
  );
}

export function buildSearchLaunchPlans(draft: SearchQueryDraft): SearchLaunchPlan[] {
  const targets = parseTargets(draft.targetsText);
  const queryText = normalizeQueryWhitespace(draft.queryText);
  const containsTargetPlaceholder = queryText.includes('{target}');
  const selectedEngines = normalizeEngineIds(draft.selectedEngineIds)
    .map((engineId) => SEARCH_ENGINE_BY_ID.get(engineId))
    .filter((engine): engine is SearchEngineDefinition => Boolean(engine));

  if (!selectedEngines.length) {
    return [];
  }

  if (!queryText && targets.length === 0) {
    return [];
  }

  if (draft.launchMode === 'per-target' && targets.length > 0) {
    return selectedEngines.flatMap((engine) =>
      targets.map((target) => buildLaunchPlan(engine, queryText, [target], target, containsTargetPlaceholder))
    );
  }

  return selectedEngines.map((engine) =>
    buildLaunchPlan(engine, queryText, targets, undefined, containsTargetPlaceholder)
  );
}

export function validateSearchDraft(draft: SearchQueryDraft): string | undefined {
  const targets = parseTargets(draft.targetsText);
  const queryText = normalizeQueryWhitespace(draft.queryText);

  if (normalizeEngineIds(draft.selectedEngineIds).length === 0) {
    return 'Select at least one search engine.';
  }

  if (!queryText && targets.length === 0) {
    return 'Add a target site, a query string, or both before launching searches.';
  }

  if (queryText.includes('{target}') && targets.length === 0) {
    return 'Add at least one target site before launching a target-aware query.';
  }

  if (queryText.includes('{value}')) {
    return 'Replace every {value} placeholder before launching the search.';
  }

  return undefined;
}

export function parseTargets(rawValue: string): string[] {
  const normalized = new Set<string>();
  for (const part of rawValue.split(/[\n,;]+/g)) {
    const target = normalizeTarget(part);
    if (target) {
      normalized.add(target);
    }
  }

  return [...normalized];
}

export function normalizeTarget(rawValue: string): string | undefined {
  const trimmed = rawValue.trim();
  if (!trimmed) {
    return undefined;
  }

  const wildcardStripped = trimmed.replace(/^%\./, '').replace(/^\*\./, '');

  const parsedUrl = tryParseUrl(wildcardStripped);
  const candidate = parsedUrl?.hostname ?? wildcardStripped.split('/')[0] ?? wildcardStripped;
  const normalized = candidate.trim().toLowerCase().replace(/\.$/, '');

  if (!normalized || /\s/.test(normalized)) {
    return undefined;
  }

  return normalized;
}

export function tryGetHostname(rawUrl?: string): string | undefined {
  if (!rawUrl) {
    return undefined;
  }

  return normalizeTarget(rawUrl);
}

export function createSavedSearchProfile(draft: SearchQueryDraft): SavedSearchProfile {
  const timestamp = new Date().toISOString();
  return {
    ...normalizeSearchDraft(draft),
    id: createSearchWorkbenchId('profile'),
    name: draft.name.trim(),
    createdAt: timestamp,
    updatedAt: timestamp
  };
}

export function createCustomSearchOperator(input: {
  label: string;
  template: string;
  description?: string;
  category?: SearchOperatorDefinition['category'];
  engineIds: SearchEngineId[];
}): CustomSearchOperatorDefinition {
  const timestamp = new Date().toISOString();
  return {
    id: createSearchWorkbenchId('operator'),
    label: input.label.trim(),
    template: input.template.trim(),
    description: input.description?.trim() || 'Custom search operator.',
    category: input.category ?? 'content',
    engineIds: normalizeEngineIds(input.engineIds),
    isCustom: true,
    createdAt: timestamp,
    updatedAt: timestamp
  };
}

function buildLaunchPlan(
  engine: SearchEngineDefinition,
  queryText: string,
  targets: string[],
  target: string | undefined,
  containsTargetPlaceholder: boolean
): SearchLaunchPlan {
  const expandedQuery = containsTargetPlaceholder
    ? expandTargetPlaceholders(queryText, targets, target)
    : joinSearchParts(buildScopeClause(engine, targets), queryText);

  return {
    id: createSearchWorkbenchId('launch'),
    engine,
    target,
    query: expandedQuery,
    url: buildSearchUrl(engine, expandedQuery)
  };
}

function buildSearchUrl(engine: SearchEngineDefinition, query: string): string {
  const url = new URL(engine.searchBaseUrl);
  url.searchParams.set(engine.queryParam, query);
  return url.toString();
}

function buildScopeClause(engine: SearchEngineDefinition, targets: string[]): string {
  if (targets.length === 0) {
    return '';
  }

  if (targets.length === 1) {
    const firstTarget = targets[0];
    return firstTarget ? engine.targetTemplate.replaceAll('{target}', firstTarget) : '';
  }

  return `(${targets
    .map((target) => engine.targetTemplate.replaceAll('{target}', target))
    .join(' OR ')})`;
}

function expandTargetPlaceholders(
  queryText: string,
  targets: string[],
  target: string | undefined
): string {
  if (targets.length === 0) {
    return queryText.replaceAll('{target}', '{target}');
  }

  if (target) {
    return queryText.replaceAll('{target}', target);
  }

  if (targets.length === 1) {
    const firstTarget = targets[0];
    return firstTarget ? queryText.replaceAll('{target}', firstTarget) : queryText;
  }

  return `(${targets.map((entry) => queryText.replaceAll('{target}', entry)).join(' OR ')})`;
}

function joinSearchParts(...parts: Array<string | undefined>): string {
  return normalizeQueryWhitespace(parts.filter(Boolean).join(' '));
}

function normalizeQueryWhitespace(value: string): string {
  return value.trim().replace(/\s+/g, ' ');
}

function normalizeEngineIds(rawEngineIds: unknown): SearchEngineId[] {
  if (!Array.isArray(rawEngineIds)) {
    return [];
  }

  const engineIds = new Set<SearchEngineId>();
  for (const entry of rawEngineIds) {
    if (typeof entry !== 'string') {
      continue;
    }

    const normalized = entry as SearchEngineId;
    if (SEARCH_ENGINE_BY_ID.has(normalized)) {
      engineIds.add(normalized);
    }
  }

  return [...engineIds];
}

function normalizeSavedSearchProfile(rawValue: unknown): SavedSearchProfile | undefined {
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return undefined;
  }

  const source = rawValue as Partial<SavedSearchProfile>;
  const draft = normalizeSearchDraft(source);
  const name = typeof source.name === 'string' ? source.name.trim() : '';
  if (!name) {
    return undefined;
  }

  return {
    ...draft,
    id: typeof source.id === 'string' && source.id.trim().length > 0 ? source.id : createSearchWorkbenchId('profile'),
    name,
    createdAt:
      typeof source.createdAt === 'string' && source.createdAt.trim().length > 0
        ? source.createdAt
        : new Date().toISOString(),
    updatedAt:
      typeof source.updatedAt === 'string' && source.updatedAt.trim().length > 0
        ? source.updatedAt
        : new Date().toISOString()
  };
}

function normalizeCustomSearchOperator(
  rawValue: unknown
): CustomSearchOperatorDefinition | undefined {
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return undefined;
  }

  const source = rawValue as Partial<CustomSearchOperatorDefinition>;
  const label = typeof source.label === 'string' ? source.label.trim() : '';
  const template = typeof source.template === 'string' ? source.template.trim() : '';
  const engineIds = normalizeEngineIds(source.engineIds);
  if (!label || !template || engineIds.length === 0) {
    return undefined;
  }

  return {
    id:
      typeof source.id === 'string' && source.id.trim().length > 0
        ? source.id
        : createSearchWorkbenchId('operator'),
    label,
    template,
    description:
      typeof source.description === 'string' && source.description.trim().length > 0
        ? source.description
        : 'Custom search operator.',
    category: normalizeOperatorCategory(source.category),
    engineIds,
    isCustom: true,
    createdAt:
      typeof source.createdAt === 'string' && source.createdAt.trim().length > 0
        ? source.createdAt
        : new Date().toISOString(),
    updatedAt:
      typeof source.updatedAt === 'string' && source.updatedAt.trim().length > 0
        ? source.updatedAt
        : new Date().toISOString()
  };
}

function mergeDefaultSearchProfiles(savedProfiles: SavedSearchProfile[]): SavedSearchProfile[] {
  const merged = new Map<string, SavedSearchProfile>();
  for (const profile of DEFAULT_OSINT_SEARCH_PROFILES) {
    merged.set(profile.id, profile);
  }

  for (const profile of savedProfiles) {
    // Built-ins are versioned application content. Keep the current definition authoritative so
    // persisted copies from an older release cannot silently restore retired engines or queries.
    if (!profile.id.startsWith('builtin-')) {
      merged.set(profile.id, profile);
    }
  }

  return [...merged.values()];
}

function normalizeOperatorCategory(
  value: unknown
): SearchOperatorDefinition['category'] {
  switch (value) {
    case 'scope':
    case 'content':
    case 'exclude':
    case 'intel':
    case 'certificate':
      return value;
    default:
      return 'content';
  }
}

function createSearchWorkbenchId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}

function isDorkSuiteCategoryId(value: unknown): value is DorkSuiteCategoryId {
  return (
    value === 'auth-surfaces' ||
    value === 'indexed-documents' ||
    value === 'api-surface' ||
    value === 'client-artifacts' ||
    value === 'directory-listings' ||
    value === 'recent-changes'
  );
}

function tryParseUrl(rawValue: string): URL | undefined {
  try {
    return new URL(rawValue);
  } catch {
    try {
      return new URL(`https://${rawValue}`);
    } catch {
      return undefined;
    }
  }
}
