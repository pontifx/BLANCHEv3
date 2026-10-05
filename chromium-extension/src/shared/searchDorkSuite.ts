import {
  SEARCH_ENGINES,
  parseTargets,
  type DorkSuiteCategoryId,
  type DorkSuiteDraft,
  type SearchQueryDraft
} from './searchWorkbench';
import type { CoreWebSearchEngineId } from './searchOperatorCatalog';
import type { SearchCategory } from './searchExecution';

export const DORK_SUITE_KIND = 'blanche.dork-suite' as const;
export const DORK_SUITE_SCHEMA_VERSION = '1.0.0' as const;
export const DORK_SUITE_CATALOG_REVIEWED_AT = '2026-09-09' as const;

export interface DorkSuiteCategoryDefinition {
  id: DorkSuiteCategoryId;
  label: string;
  description: string;
  searchCategory: SearchCategory;
}

export interface DorkSuiteEntry {
  id: string;
  title: string;
  categoryId: DorkSuiteCategoryId;
  searchCategory: SearchCategory;
  dialect: CoreWebSearchEngineId | 'portable';
  engineId?: CoreWebSearchEngineId;
  target: string;
  targets: string[];
  query: string;
  searchUrl?: string;
  operatorIds: string[];
  warnings: string[];
}

export interface DorkSuitePlan {
  kind: typeof DORK_SUITE_KIND;
  schemaVersion: typeof DORK_SUITE_SCHEMA_VERSION;
  catalogReviewedAt: typeof DORK_SUITE_CATALOG_REVIEWED_AT;
  targets: string[];
  entries: DorkSuiteEntry[];
  warnings: string[];
}

interface QueryRecipe {
  suffix: string;
  operatorIds: string[];
  warnings?: string[];
  variantLabel?: string;
}

interface FocusTerm {
  label: string;
  query: string;
}

interface FocusTermSet {
  terms: FocusTerm[];
  warnings: string[];
}

const MAX_FOCUS_TERMS = 20;
const MAX_FOCUS_WORDS = 6;
const MAX_FOCUS_CHARACTERS = 80;

const CORE_WEB_ENGINE_IDS = new Set<CoreWebSearchEngineId>([
  'google',
  'bing',
  'duckduckgo'
]);

export const DORK_SUITE_CATEGORIES: DorkSuiteCategoryDefinition[] = [
  {
    id: 'auth-surfaces',
    label: 'Authentication surfaces',
    description: 'Indexed login, sign-in, SSO, VPN, and administrative entry points.',
    searchCategory: 'public-footprint'
  },
  {
    id: 'indexed-documents',
    label: 'Indexed documents',
    description: 'Publicly indexed documents that merit authorized exposure review.',
    searchCategory: 'indexed-files'
  },
  {
    id: 'api-surface',
    label: 'API surface',
    description: 'Public API documentation, GraphQL, OpenAPI, and callback surfaces.',
    searchCategory: 'extracted-urls'
  },
  {
    id: 'client-artifacts',
    label: 'Client artifacts',
    description: 'Indexed JavaScript, source-map references, bundles, and configuration clues.',
    searchCategory: 'javascript'
  },
  {
    id: 'directory-listings',
    label: 'Directory listings',
    description: 'Index-style pages and public backup, log, or configuration directories.',
    searchCategory: 'public-footprint'
  },
  {
    id: 'recent-changes',
    label: 'Recent changes',
    description: 'Recent or engine-preferred security, release, and change material.',
    searchCategory: 'archives'
  }
];

const CATEGORY_BY_ID = new Map(DORK_SUITE_CATEGORIES.map((category) => [category.id, category]));
const ENGINE_BY_ID = new Map(SEARCH_ENGINES.map((engine) => [engine.id, engine]));

export function buildDorkSuitePlan(
  searchDraft: SearchQueryDraft,
  suiteDraft: DorkSuiteDraft,
  referenceDate = new Date()
): DorkSuitePlan {
  const targets = parseTargets(searchDraft.targetsText);
  const engines = [...new Set(searchDraft.selectedEngineIds)].filter(
    (engineId): engineId is CoreWebSearchEngineId =>
      CORE_WEB_ENGINE_IDS.has(engineId as CoreWebSearchEngineId)
  );
  const categoryIds = [...new Set(suiteDraft.categoryIds)];
  const focusTermSet = parseFocusTerms(suiteDraft.keywordsText);
  const maxQueries = normalizeMaxQueries(suiteDraft.maxQueries);
  const warnings: string[] = [];
  if (targets.length === 0) {
    warnings.push('Add at least one authorized target before generating a dork suite.');
  }
  if (engines.length === 0) {
    warnings.push('Select Google, Bing, or DuckDuckGo before generating an engine suite.');
  }
  warnings.push(...focusTermSet.warnings);

  const entryBuckets: DorkSuiteEntry[][] = focusTermSet.terms.map(() => []);
  let generatedEntryCount = 0;
  for (let focusIndex = 0; focusIndex < focusTermSet.terms.length; focusIndex += 1) {
    const focusTerm = focusTermSet.terms[focusIndex];
    const focusEntries = entryBuckets[focusIndex];
    if (!focusTerm || !focusEntries) continue;
    for (const target of targets) {
      for (const engineId of engines) {
        for (const categoryId of categoryIds) {
          const category = CATEGORY_BY_ID.get(categoryId);
          if (!category) continue;
          const recipes = recipesFor(engineId, categoryId, referenceDate);
          for (let recipeIndex = 0; recipeIndex < recipes.length; recipeIndex += 1) {
            const recipe = recipes[recipeIndex];
            if (!recipe) continue;
            generatedEntryCount += 1;

            const query = joinQueryParts(`site:${target}`, recipe.suffix, focusTerm.query);
            const engine = ENGINE_BY_ID.get(engineId);
            if (!engine) continue;
            const searchUrl = new URL(engine.searchBaseUrl);
            searchUrl.searchParams.set(engine.queryParam, query);
            focusEntries.push({
              id: buildEntryId(
                engineId,
                target,
                categoryId,
                recipeIndex,
                focusIndex,
                generatedEntryCount
              ),
              title: buildEntryTitle(
                category.label,
                recipeIndex,
                focusTerm,
                recipe.variantLabel
              ),
              categoryId,
              searchCategory: category.searchCategory,
              dialect: engineId,
              engineId,
              target,
              targets: [target],
              query,
              searchUrl: searchUrl.toString(),
              operatorIds: ['site', ...recipe.operatorIds],
              warnings: [...(recipe.warnings ?? []), ...engineWarnings(engineId)]
            });
          }
        }
      }
    }
  }
  const entries = takeRoundRobin(entryBuckets, maxQueries);

  if (generatedEntryCount > maxQueries) {
    warnings.push(
      `The generated suite was capped at ${maxQueries} of ${generatedEntryCount} queries to prevent a tab storm.`
    );
    const coverageWarning = buildFocusCoverageWarning(focusTermSet.terms, entryBuckets, entries);
    if (coverageWarning) warnings.push(coverageWarning);
  }
  return {
    kind: DORK_SUITE_KIND,
    schemaVersion: DORK_SUITE_SCHEMA_VERSION,
    catalogReviewedAt: DORK_SUITE_CATALOG_REVIEWED_AT,
    targets,
    entries,
    warnings
  };
}

export function buildPortableDorkSuitePlan(
  searchDraft: SearchQueryDraft,
  suiteDraft: DorkSuiteDraft,
  siteSearchTarget?: string
): DorkSuitePlan {
  const targets = parseTargets(siteSearchTarget ?? searchDraft.targetsText);
  const categoryIds = [...new Set(suiteDraft.categoryIds)];
  const focusTermSet = parseFocusTerms(suiteDraft.keywordsText);
  const maxQueries = normalizeMaxQueries(suiteDraft.maxQueries);
  const warnings: string[] = [];
  if (targets.length === 0) {
    warnings.push('Add at least one authorized target before generating a Site Search suite.');
  }
  warnings.push(...focusTermSet.warnings);
  const entryBuckets: DorkSuiteEntry[][] = focusTermSet.terms.map(() => []);
  let generatedEntryCount = 0;
  for (let focusIndex = 0; focusIndex < focusTermSet.terms.length; focusIndex += 1) {
    const focusTerm = focusTermSet.terms[focusIndex];
    const focusEntries = entryBuckets[focusIndex];
    if (!focusTerm || !focusEntries) continue;
    for (const target of targets) {
      for (const categoryId of categoryIds) {
        const category = CATEGORY_BY_ID.get(categoryId);
        if (!category) continue;
        const recipes = portableRecipes(categoryId);
        for (let recipeIndex = 0; recipeIndex < recipes.length; recipeIndex += 1) {
          const recipe = recipes[recipeIndex];
          if (!recipe) continue;
          generatedEntryCount += 1;

          focusEntries.push({
            id: buildEntryId(
              'portable',
              target,
              categoryId,
              recipeIndex,
              focusIndex,
              generatedEntryCount
            ),
            title: buildEntryTitle(
              category.label,
              recipeIndex,
              focusTerm,
              recipe.variantLabel
            ),
            categoryId,
            searchCategory: category.searchCategory,
            dialect: 'portable',
            target,
            targets: [target],
            query: joinQueryParts(recipe.suffix, focusTerm.query),
            operatorIds: [...recipe.operatorIds],
            warnings: [
              'Site Search queries omit site: because the selected destination already defines target scope and may treat portable operator syntax literally.',
              ...(recipe.warnings ?? [])
            ]
          });
        }
      }
    }
  }
  const entries = takeRoundRobin(entryBuckets, maxQueries);
  if (generatedEntryCount > maxQueries) {
    warnings.push(
      `The generated Site Search suite was capped at ${maxQueries} of ${generatedEntryCount} queries to prevent a tab storm.`
    );
    const coverageWarning = buildFocusCoverageWarning(focusTermSet.terms, entryBuckets, entries);
    if (coverageWarning) warnings.push(coverageWarning);
  }
  return {
    kind: DORK_SUITE_KIND,
    schemaVersion: DORK_SUITE_SCHEMA_VERSION,
    catalogReviewedAt: DORK_SUITE_CATALOG_REVIEWED_AT,
    targets,
    entries,
    warnings
  };
}

export function validateDorkSuitePlan(plan: DorkSuitePlan): string | undefined {
  if (plan.targets.length === 0) {
    return 'Add at least one authorized target before generating a dork suite.';
  }
  if (plan.entries.length === 0) {
    return plan.warnings[0] ?? 'Select at least one suite category and destination.';
  }
  return undefined;
}

function recipesFor(
  engineId: CoreWebSearchEngineId,
  categoryId: DorkSuiteCategoryId,
  referenceDate: Date
): QueryRecipe[] {
  if (engineId === 'google') {
    return googleRecipes(categoryId, referenceDate);
  }
  if (engineId === 'bing') {
    return bingRecipes(categoryId);
  }
  return duckDuckGoRecipes(categoryId);
}

function googleRecipes(categoryId: DorkSuiteCategoryId, referenceDate: Date): QueryRecipe[] {
  switch (categoryId) {
    case 'auth-surfaces':
      return [
        { suffix: 'intitle:"login"', operatorIds: ['intitle', 'exact-phrase'] },
        {
          suffix: 'inurl:signin',
          operatorIds: ['inurl'],
          warnings: ['Google inurl: is useful but currently classified as a relaxed/fragile constraint.']
        }
      ];
    case 'indexed-documents':
      return [
        { suffix: 'filetype:pdf "internal use"', operatorIds: ['filetype', 'exact-phrase'] },
        { suffix: 'filetype:xlsx confidential', operatorIds: ['filetype'] }
      ];
    case 'api-surface':
      return [
        { suffix: 'inurl:openapi', operatorIds: ['inurl'] },
        { suffix: 'inurl:graphql', operatorIds: ['inurl'] }
      ];
    case 'client-artifacts':
      return [
        { suffix: 'filetype:js "sourceMappingURL"', operatorIds: ['filetype', 'exact-phrase'] },
        { suffix: 'filetype:js "feature flag"', operatorIds: ['filetype', 'exact-phrase'] }
      ];
    case 'directory-listings':
      return [
        { suffix: 'intitle:"index of" backup', operatorIds: ['intitle', 'exact-phrase'] },
        { suffix: 'intitle:"index of" config', operatorIds: ['intitle', 'exact-phrase'] }
      ];
    case 'recent-changes': {
      const afterDate = oneYearBefore(referenceDate);
      return [
        { suffix: `after:${afterDate} security`, operatorIds: ['after'] },
        { suffix: `after:${afterDate} changelog`, operatorIds: ['after'] }
      ];
    }
  }
}

function bingRecipes(categoryId: DorkSuiteCategoryId): QueryRecipe[] {
  const termLimitWarning = 'Bing evaluates only the first ten query terms; BLANCHE keeps this recipe bounded.';
  switch (categoryId) {
    case 'auth-surfaces':
      return [
        { suffix: 'intitle:login', operatorIds: ['intitle'], warnings: [termLimitWarning] },
        { suffix: 'intitle:signin', operatorIds: ['intitle'], warnings: [termLimitWarning] }
      ];
    case 'indexed-documents':
      return [
        { suffix: 'filetype:pdf "internal use"', operatorIds: ['filetype', 'exact-phrase'], warnings: [termLimitWarning] },
        { suffix: 'ext:xlsx confidential', operatorIds: ['ext'], warnings: [termLimitWarning] }
      ];
    case 'api-surface':
      return [
        { suffix: 'inbody:openapi', operatorIds: ['inbody'], warnings: [termLimitWarning] },
        { suffix: 'inbody:graphql', operatorIds: ['inbody'], warnings: [termLimitWarning] }
      ];
    case 'client-artifacts':
      return [
        { suffix: 'ext:js inbody:sourceMappingURL', operatorIds: ['ext', 'inbody'], warnings: [termLimitWarning] },
        { suffix: 'filetype:js prefer:webpack', operatorIds: ['filetype', 'prefer'], warnings: [termLimitWarning] }
      ];
    case 'directory-listings':
      return [
        { suffix: 'intitle:index intitle:of backup', operatorIds: ['intitle'], warnings: [termLimitWarning] },
        { suffix: 'intitle:index intitle:of config', operatorIds: ['intitle'], warnings: [termLimitWarning] }
      ];
    case 'recent-changes':
      return [
        { suffix: 'prefer:security release', operatorIds: ['prefer'], warnings: ['Bing prefer: boosts ranking; it is not a date filter.', termLimitWarning] },
        { suffix: 'prefer:changelog', operatorIds: ['prefer'], warnings: ['Bing prefer: boosts ranking; it is not a date filter.', termLimitWarning] }
      ];
  }
}

function duckDuckGoRecipes(categoryId: DorkSuiteCategoryId): QueryRecipe[] {
  const reliabilityWarning =
    'DuckDuckGo documents this syntax as best-effort and may return related results.';
  switch (categoryId) {
    case 'auth-surfaces':
      return [
        { suffix: 'intitle:"login"', operatorIds: ['intitle', 'exact-phrase'], warnings: [reliabilityWarning] },
        { suffix: 'inurl:signin', operatorIds: ['inurl'], warnings: [reliabilityWarning] }
      ];
    case 'indexed-documents':
      return [
        { suffix: 'filetype:pdf "internal use"', operatorIds: ['filetype', 'exact-phrase'], warnings: [reliabilityWarning] },
        { suffix: 'filetype:xlsx confidential', operatorIds: ['filetype'], warnings: [reliabilityWarning] }
      ];
    case 'api-surface':
      return [
        { suffix: 'inurl:openapi', operatorIds: ['inurl'], warnings: [reliabilityWarning] },
        { suffix: 'inurl:graphql', operatorIds: ['inurl'], warnings: [reliabilityWarning] }
      ];
    case 'client-artifacts':
      return [
        { suffix: 'filetype:html "sourceMappingURL"', operatorIds: ['filetype', 'exact-phrase'], warnings: [reliabilityWarning] },
        { suffix: '~"feature flag"', operatorIds: ['ddg-semantic'], warnings: ['DuckDuckGo semantic phrase search is experimental.'] }
      ];
    case 'directory-listings':
      return [
        { suffix: 'intitle:"index of" backup', operatorIds: ['intitle', 'exact-phrase'], warnings: [reliabilityWarning] },
        { suffix: 'intitle:"index of" config', operatorIds: ['intitle', 'exact-phrase'], warnings: [reliabilityWarning] }
      ];
    case 'recent-changes':
      return [
        { suffix: '~"security release"', operatorIds: ['ddg-semantic'], warnings: ['DuckDuckGo semantic phrase search is experimental; use its date UI for strict date windows.'] },
        { suffix: '~"product changelog"', operatorIds: ['ddg-semantic'], warnings: ['DuckDuckGo semantic phrase search is experimental; use its date UI for strict date windows.'] }
      ];
  }
}

function portableRecipes(categoryId: DorkSuiteCategoryId): QueryRecipe[] {
  switch (categoryId) {
    case 'auth-surfaces':
      return [
        {
          suffix: '"login"',
          operatorIds: ['exact-phrase'],
          variantLabel: 'baseline'
        },
        {
          suffix: 'intitle:"login"',
          operatorIds: ['intitle', 'exact-phrase'],
          variantLabel: 'operator probe'
        }
      ];
    case 'indexed-documents':
      return [
        {
          suffix: '"internal use" pdf',
          operatorIds: ['exact-phrase'],
          variantLabel: 'baseline'
        },
        {
          suffix: 'filetype:pdf "internal use"',
          operatorIds: ['filetype', 'exact-phrase'],
          variantLabel: 'operator probe'
        }
      ];
    case 'api-surface':
      return [
        { suffix: 'openapi', operatorIds: [], variantLabel: 'baseline' },
        { suffix: 'inurl:openapi', operatorIds: ['inurl'], variantLabel: 'operator probe' }
      ];
    case 'client-artifacts':
      return [
        {
          suffix: '"sourceMappingURL"',
          operatorIds: ['exact-phrase'],
          variantLabel: 'baseline'
        },
        {
          suffix: 'filetype:js "sourceMappingURL"',
          operatorIds: ['filetype', 'exact-phrase'],
          variantLabel: 'operator probe'
        }
      ];
    case 'directory-listings':
      return [
        {
          suffix: '"index of" backup',
          operatorIds: ['exact-phrase'],
          variantLabel: 'baseline'
        },
        {
          suffix: 'intitle:"index of" backup',
          operatorIds: ['intitle', 'exact-phrase'],
          variantLabel: 'operator probe'
        }
      ];
    case 'recent-changes':
      return [
        {
          suffix: 'security release',
          operatorIds: [],
          variantLabel: 'baseline'
        },
        {
          suffix: 'security OR changelog',
          operatorIds: ['or'],
          variantLabel: 'operator probe'
        }
      ];
  }
}

function engineWarnings(engineId: CoreWebSearchEngineId): string[] {
  if (engineId === 'google') {
    return ['Search operators are constrained by indexing and retrieval limits; no result is not proof of absence.'];
  }
  if (engineId === 'bing') {
    return ['Bing browser URL search is used because the legacy Bing Search APIs were retired in 2025.'];
  }
  return ['DuckDuckGo combines multiple result sources, so documented syntax is not guaranteed for every query.'];
}

function parseFocusTerms(rawValue: string): FocusTermSet {
  const uniqueTerms = new Map<string, FocusTerm>();
  let shortenedTermCount = 0;

  for (const part of rawValue.split(/[\n,;]+/g)) {
    const withoutQuotes = part.replaceAll('"', '').trim().replace(/\s+/g, ' ');
    if (!withoutQuotes) continue;

    const wordBounded = withoutQuotes.split(' ').slice(0, MAX_FOCUS_WORDS).join(' ');
    const characterBounded = wordBounded.slice(0, MAX_FOCUS_CHARACTERS).trim();
    if (!characterBounded) continue;
    if (characterBounded !== withoutQuotes) shortenedTermCount += 1;

    const dedupeKey = characterBounded.toLowerCase();
    if (!uniqueTerms.has(dedupeKey)) {
      uniqueTerms.set(dedupeKey, {
        label: characterBounded,
        query: characterBounded.includes(' ') ? `"${characterBounded}"` : characterBounded
      });
    }
  }

  const allTerms = [...uniqueTerms.values()];
  const warnings: string[] = [];
  if (shortenedTermCount > 0) {
    warnings.push(
      `${shortenedTermCount} focus ${shortenedTermCount === 1 ? 'term was' : 'terms were'} shortened to at most ${MAX_FOCUS_WORDS} words and ${MAX_FOCUS_CHARACTERS} characters.`
    );
  }
  if (allTerms.length > MAX_FOCUS_TERMS) {
    warnings.push(
      `The keyword list was capped at ${MAX_FOCUS_TERMS} of ${allTerms.length} unique focus terms.`
    );
  }

  return {
    terms: allTerms.length
      ? allTerms.slice(0, MAX_FOCUS_TERMS)
      : [{ label: '', query: '' }],
    warnings
  };
}

function joinQueryParts(...parts: string[]): string {
  return parts.filter(Boolean).join(' ').trim().replace(/\s+/g, ' ');
}

function takeRoundRobin<T>(buckets: readonly (readonly T[])[], limit: number): T[] {
  const output: T[] = [];
  for (let index = 0; output.length < limit; index += 1) {
    let added = false;
    for (const bucket of buckets) {
      const entry = bucket[index];
      if (entry === undefined) continue;
      output.push(entry);
      added = true;
      if (output.length >= limit) break;
    }
    if (!added) break;
  }
  return output;
}

function buildFocusCoverageWarning(
  terms: readonly FocusTerm[],
  buckets: readonly (readonly DorkSuiteEntry[])[],
  selectedEntries: readonly DorkSuiteEntry[]
): string | undefined {
  if (terms.length <= 1 || terms.every((term) => !term.label)) return undefined;
  const selectedIds = new Set(selectedEntries.map((entry) => entry.id));
  let complete = 0;
  let partial = 0;
  let omitted = 0;
  for (const bucket of buckets) {
    const selectedCount = bucket.filter((entry) => selectedIds.has(entry.id)).length;
    if (selectedCount === 0) omitted += 1;
    else if (selectedCount === bucket.length) complete += 1;
    else partial += 1;
  }
  return `The submission cap was distributed across ${terms.length} focus terms: ${complete} complete, ${partial} partial, and ${omitted} omitted. Raise Maximum submissions for fuller per-term coverage.`;
}

function oneYearBefore(referenceDate: Date): string {
  const date = Number.isFinite(referenceDate.getTime()) ? new Date(referenceDate) : new Date();
  date.setUTCFullYear(date.getUTCFullYear() - 1);
  return date.toISOString().slice(0, 10);
}

function normalizeMaxQueries(rawValue: number): number {
  if (!Number.isFinite(rawValue)) return 24;
  return Math.min(60, Math.max(1, Math.floor(rawValue)));
}

function buildEntryTitle(
  categoryLabel: string,
  recipeIndex: number,
  focusTerm: FocusTerm,
  variantLabel?: string
): string {
  const baseTitle = variantLabel
    ? `${categoryLabel} — ${variantLabel}`
    : `${categoryLabel} ${recipeIndex + 1}`;
  return focusTerm.label ? `${baseTitle} — ${focusTerm.label}` : baseTitle;
}

function buildEntryId(
  dialect: CoreWebSearchEngineId | 'portable',
  target: string,
  categoryId: DorkSuiteCategoryId,
  recipeIndex: number,
  focusIndex: number,
  ordinal: number
): string {
  const safeTarget = target.replace(/[^a-z0-9.-]+/gi, '-').slice(0, 80);
  return `dork_${dialect}_${safeTarget}_${categoryId}_${recipeIndex + 1}_${focusIndex + 1}_${ordinal}`;
}
