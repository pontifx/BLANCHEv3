export type CoreWebSearchEngineId = 'google' | 'bing' | 'duckduckgo';

export type SearchOperatorSupportStatus =
  | 'documented'
  | 'observed'
  | 'fragile'
  | 'deprecated'
  | 'unsupported';

export type SearchOperatorCategory =
  | 'boolean'
  | 'exact'
  | 'scope'
  | 'content'
  | 'file'
  | 'date'
  | 'proximity'
  | 'locale'
  | 'feed'
  | 'routing'
  | 'image'
  | 'utility'
  | 'legacy';

export type SearchOperatorSurface =
  | 'web'
  | 'images'
  | 'news'
  | 'routing'
  | 'settings'
  | 'legacy';

export interface SearchOperatorEngineSupport {
  status: SearchOperatorSupportStatus;
  syntax: readonly string[];
  semantics: string;
  notes: readonly string[];
  sourceUrls: readonly string[];
  surfaces: readonly SearchOperatorSurface[];
  safeForGeneration: boolean;
  replacement?: string;
}

export interface SearchOperatorCatalogEntry {
  id: string;
  label: string;
  category: SearchOperatorCategory;
  description: string;
  aliases: readonly string[];
  engines: Readonly<Record<CoreWebSearchEngineId, SearchOperatorEngineSupport>>;
}

export interface SearchOperatorCatalogDocument {
  lastReviewed: string;
  operators: readonly SearchOperatorCatalogEntry[];
}

export interface SearchOperatorFilterOptions {
  categories?: readonly SearchOperatorCategory[];
  statuses?: readonly SearchOperatorSupportStatus[];
  surfaces?: readonly SearchOperatorSurface[];
  safeForGenerationOnly?: boolean;
}

export interface SearchOperatorSyntaxMatch {
  operator: SearchOperatorCatalogEntry;
  support: SearchOperatorEngineSupport;
  syntax: string;
}

export const SEARCH_OPERATOR_CATALOG_LAST_REVIEWED = '2026-09-09';

export const CORE_WEB_SEARCH_ENGINE_IDS: readonly CoreWebSearchEngineId[] = [
  'google',
  'bing',
  'duckduckgo'
];

const GOOGLE_HELP =
  'https://support.google.com/websearch/answer/2466433?hl=en';
const GOOGLE_ADVANCED = 'https://www.google.com/advanced_search';
const GOOGLE_SEARCH_OPERATORS =
  'https://developers.google.com/search/docs/monitor-debug/search-operators';
const GOOGLE_SITE =
  'https://developers.google.com/search/docs/monitor-debug/search-operators/all-search-site';
const GOOGLE_IMAGE =
  'https://developers.google.com/search/docs/monitor-debug/search-operators/image-search';
const GOOGLE_FILE_TYPES =
  'https://developers.google.com/search/docs/crawling-indexing/indexable-file-types';
const GOOGLE_CHANGELOG = 'https://developers.google.com/search/updates';
const GOOGLE_INFO_RETIREMENT =
  'https://developers.google.com/search/blog/2019/03/how-to-discover-suggest-google-selected';
const GOOGLE_PLUS_RETIREMENT =
  'https://search.googleblog.com/2011/11/search-using-your-terms-verbatim.html?hl=en';
const GOOGLE_FIELD_GUIDE =
  'https://gwern.net/doc/technology/google/2024-02-08-danielmrussell-googleadvancedsearchoperators-alltheoperators.pdf';
const GOOGLE_2026_OBSERVATION =
  'https://seomator.com/blog/google-search-operators-cheat-sheet';
const GOOGLE_LINK_RETIREMENT =
  'https://searchengineland.com/google-officially-killed-off-link-command-267454';
const GOOGLE_NEWS_HELP =
  'https://support.google.com/googlenews/answer/9005601?hl=en';

const BING_OPTIONS =
  'https://support.microsoft.com/en-us/bing/advanced-search-options';
const BING_KEYWORDS =
  'https://support.microsoft.com/en-us/bing/advanced-search-keywords';
const BING_INURL_RETIREMENT =
  'https://blogs.bing.com/search/March-2007/We-are-flattered%2C-but';
const BING_LINK_RETIREMENT =
  'https://blogs.bing.com/webmaster/September-2015/Link-Explorer-Being-Retired-in-Webmaster-Tools';

const DDG_SYNTAX =
  'https://duckduckgo.com/duckduckgo-help-pages/results/syntax';
const DDG_DATES =
  'https://duckduckgo.com/duckduckgo-help-pages/features/dates';
const DDG_SOURCES =
  'https://duckduckgo.com/duckduckgo-help-pages/results/sources';
const DDG_BANGS = 'https://duckduckgo.com/bangs';

function unsupported(
  semantics: string,
  replacement: string,
  sourceUrls: readonly string[],
  notes: readonly string[] = []
): SearchOperatorEngineSupport {
  return {
    status: 'unsupported',
    syntax: [],
    semantics,
    notes,
    sourceUrls,
    surfaces: ['web'],
    safeForGeneration: false,
    replacement
  };
}

function deprecated(
  syntax: readonly string[],
  semantics: string,
  replacement: string,
  sourceUrls: readonly string[],
  notes: readonly string[] = []
): SearchOperatorEngineSupport {
  return {
    status: 'deprecated',
    syntax,
    semantics,
    notes,
    sourceUrls,
    surfaces: ['legacy'],
    safeForGeneration: false,
    replacement
  };
}

export const SEARCH_OPERATOR_ROWS = [
  {
    id: 'exact-phrase',
    label: 'Exact phrase',
    category: 'exact',
    description: 'Request an exact ordered phrase instead of ordinary relevance matching.',
    aliases: ['quotes', 'phrase'],
    engines: {
      google: {
        status: 'documented',
        syntax: ['"{phrase}"'],
        semantics: 'Returns organic results containing the quoted word or phrase.',
        notes: [
          'Quoted matching does not constrain every special result module, and Google says local results may ignore it.'
        ],
        sourceUrls: [GOOGLE_HELP],
        surfaces: ['web', 'images', 'news'],
        safeForGeneration: true
      },
      bing: {
        status: 'documented',
        syntax: ['"{phrase}"'],
        semantics: 'Finds the exact words in a phrase.',
        notes: ['Quotes have higher precedence than Boolean operators other than grouping.'],
        sourceUrls: [BING_OPTIONS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: {
        status: 'fragile',
        syntax: ['"{phrase}"'],
        semantics: 'Requests the exact term, but may fall back to related results when exact hits are sparse.',
        notes: ['DuckDuckGo warns that advanced syntax is not correct for every query.'],
        sourceUrls: [DDG_SYNTAX],
        surfaces: ['web'],
        safeForGeneration: true
      }
    }
  },
  {
    id: 'and',
    label: 'Conjunction',
    category: 'boolean',
    description: 'Require all query branches or terms.',
    aliases: ['AND', '&', 'implicit-and'],
    engines: {
      google: {
        status: 'fragile',
        syntax: ['{term} {term}'],
        semantics: 'Whitespace supplies ordinary multi-term relevance matching; there is no necessary explicit AND token.',
        notes: ['Google may broaden ordinary unquoted queries, so this is not a database-style hard conjunction.'],
        sourceUrls: [GOOGLE_ADVANCED, GOOGLE_FIELD_GUIDE],
        surfaces: ['web'],
        safeForGeneration: true,
        replacement: 'Use quoted terms or field operators when every literal term must be present.'
      },
      bing: {
        status: 'documented',
        syntax: ['{term} {term}', '{term} AND {term}', '{term} & {term}'],
        semantics: 'Finds pages containing all terms or phrases; AND is the default.',
        notes: ['Only the first ten terms are used.'],
        sourceUrls: [BING_OPTIONS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: unsupported(
        'DuckDuckGo does not document a strict AND operator; adjacent terms are described as results about either term.',
        'Run separate constrained queries or use an exact phrase.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'or',
    label: 'Alternative',
    category: 'boolean',
    description: 'Match either of two terms or phrases.',
    aliases: ['OR', '|'],
    engines: {
      google: {
        status: 'documented',
        syntax: ['{term} OR {term}'],
        semantics: 'Requests either alternative.',
        notes: ['OR must be uppercase. The pipe alias circulates but is not in current Google help.'],
        sourceUrls: [GOOGLE_ADVANCED, GOOGLE_FIELD_GUIDE],
        surfaces: ['web'],
        safeForGeneration: true
      },
      bing: {
        status: 'documented',
        syntax: ['{term} OR {term}', '{term} | {term}'],
        semantics: 'Finds pages containing either term or phrase.',
        notes: ['OR must be uppercase and has the lowest precedence. Group it when combined with other logic.'],
        sourceUrls: [BING_OPTIONS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: unsupported(
        'DuckDuckGo does not document explicit OR or pipe syntax as a Boolean contract.',
        'Expand alternatives into separate queries.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'not',
    label: 'Term exclusion',
    category: 'boolean',
    description: 'Remove or de-emphasize results containing an unwanted term or phrase.',
    aliases: ['NOT', 'minus', '-'],
    engines: {
      google: {
        status: 'documented',
        syntax: ['-{term}', '-"{phrase}"'],
        semantics: 'Excludes an immediately following term or quoted phrase from organic results.',
        notes: ['There must be no space after the minus sign.'],
        sourceUrls: [GOOGLE_HELP],
        surfaces: ['web'],
        safeForGeneration: true
      },
      bing: {
        status: 'documented',
        syntax: ['NOT {term}', '-{term}'],
        semantics: 'Excludes pages containing the specified term or phrase.',
        notes: ['NOT must be uppercase.'],
        sourceUrls: [BING_OPTIONS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: {
        status: 'fragile',
        syntax: ['-{term}'],
        semantics: 'Requests fewer results containing the term rather than guaranteeing hard exclusion.',
        notes: ['Use negative-site for DuckDuckGo domain exclusion, which has explicit documentation.'],
        sourceUrls: [DDG_SYNTAX],
        surfaces: ['web'],
        safeForGeneration: true
      }
    }
  },
  {
    id: 'plus',
    label: 'Required or boosted term',
    category: 'boolean',
    description: 'Historically required a term; current semantics differ materially by engine.',
    aliases: ['+'],
    engines: {
      google: deprecated(
        ['+{term}'],
        'The former exact-term requirement was removed in 2011.',
        'Use "{term}" for an exact literal.',
        [GOOGLE_PLUS_RETIREMENT]
      ),
      bing: {
        status: 'documented',
        syntax: ['+{term}'],
        semantics: 'Requires a term and can include a stop word Bing would otherwise ignore.',
        notes: ['The plus operator binds before AND and OR.'],
        sourceUrls: [BING_OPTIONS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: {
        status: 'fragile',
        syntax: ['+{term}'],
        semantics: 'Boosts the term so more matching results appear; it is not a hard requirement.',
        notes: ['Do not translate Bing plus semantics directly to DuckDuckGo.'],
        sourceUrls: [DDG_SYNTAX],
        surfaces: ['web'],
        safeForGeneration: true
      }
    }
  },
  {
    id: 'grouping',
    label: 'Boolean grouping',
    category: 'boolean',
    description: 'Control precedence across compound Boolean clauses.',
    aliases: ['parentheses'],
    engines: {
      google: unsupported(
        'Google ignores parentheses as Boolean grouping.',
        'Expand each grouped branch into a separate search.',
        [GOOGLE_FIELD_GUIDE]
      ),
      bing: {
        status: 'documented',
        syntax: ['({clause})'],
        semantics: 'Groups terms and Boolean expressions and has the highest precedence.',
        notes: ['Microsoft recommends grouping OR clauses when mixed with other operators.'],
        sourceUrls: [BING_OPTIONS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: unsupported(
        'DuckDuckGo does not document Boolean grouping.',
        'Expand grouped branches into separate searches.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'wildcard',
    label: 'Whole-token wildcard',
    category: 'exact',
    description: 'Stand in for one or more unknown words.',
    aliases: ['asterisk', '*'],
    engines: {
      google: {
        status: 'fragile',
        syntax: ['"{term} * {term}"'],
        semantics: 'Historically fills whole-word gaps, with the clearest use inside a quoted phrase.',
        notes: ['A July 2026 control test could not isolate its effect from normal fuzzy matching; it is not substring globbing.'],
        sourceUrls: [GOOGLE_FIELD_GUIDE, GOOGLE_2026_OBSERVATION],
        surfaces: ['web'],
        safeForGeneration: false,
        replacement: 'Use explicit OR alternatives when the possible words are known.'
      },
      bing: unsupported(
        'Current Bing documentation says punctuation other than listed symbols is ignored.',
        'Use explicit OR alternatives.',
        [BING_OPTIONS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo does not document a wildcard operator.',
        'Use separate searches or the experimental semantic phrase operator.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'site',
    label: 'Site or domain scope',
    category: 'scope',
    description: 'Restrict results to a domain, host, or supported URL prefix.',
    aliases: ['domain-scope'],
    engines: {
      google: {
        status: 'documented',
        syntax: ['site:{domain}', 'site:{urlPrefix}'],
        semantics: 'Restricts results to a domain, URL, or URL prefix.',
        notes: ['Domain scope includes subdomains. Results and reported counts are not exhaustive.'],
        sourceUrls: [GOOGLE_SITE],
        surfaces: ['web', 'images', 'news'],
        safeForGeneration: true
      },
      bing: {
        status: 'documented',
        syntax: ['site:{domain}', 'site:{tld}', 'site:{directory}'],
        semantics: 'Restricts results to a site, top-level domain, or directory no more than two levels deep.',
        notes: ['Use grouped OR clauses for multiple sites.'],
        sourceUrls: [BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: {
        status: 'fragile',
        syntax: ['site:{domain}'],
        semantics: 'Requests pages from the specified domain.',
        notes: ['Documented, but DuckDuckGo warns that advanced syntax may relax when results are sparse.'],
        sourceUrls: [DDG_SYNTAX],
        surfaces: ['web'],
        safeForGeneration: true
      }
    }
  },
  {
    id: 'negative-site',
    label: 'Site exclusion',
    category: 'scope',
    description: 'Exclude a domain or scoped site from results.',
    aliases: ['-site'],
    engines: {
      google: {
        status: 'documented',
        syntax: ['-site:{domain}'],
        semantics: 'Composes minus with site scope to exclude a domain from organic results.',
        notes: ['Useful for duplicate-content and source-diversity searches.'],
        sourceUrls: [GOOGLE_HELP, GOOGLE_SITE],
        surfaces: ['web'],
        safeForGeneration: true
      },
      bing: {
        status: 'documented',
        syntax: ['-site:{domain}', 'NOT site:{domain}'],
        semantics: 'Composes documented exclusion and site primitives.',
        notes: ['Use uppercase NOT when using the word form.'],
        sourceUrls: [BING_OPTIONS, BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: {
        status: 'fragile',
        syntax: ['-site:{domain}'],
        semantics: 'Excludes the specified domain.',
        notes: ['This is explicitly documented and is stronger than ordinary DuckDuckGo minus-term matching.'],
        sourceUrls: [DDG_SYNTAX],
        surfaces: ['web'],
        safeForGeneration: true
      }
    }
  },
  {
    id: 'url',
    label: 'URL index-presence check',
    category: 'scope',
    description: 'Check whether a domain or full address is represented in the engine index.',
    aliases: ['index-check'],
    engines: {
      google: unsupported(
        'Google has no current url: index-presence operator.',
        'Use an exact site: URL-prefix query; site results are still not authoritative.',
        [GOOGLE_SITE]
      ),
      bing: {
        status: 'documented',
        syntax: ['url:{domainOrUrl}'],
        semantics: 'Checks whether the supplied domain or address is in the Bing index.',
        notes: ['This is not a URL-substring search.'],
        sourceUrls: [BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: unsupported(
        'DuckDuckGo has no documented index-presence operator.',
        'Use site: as a best-effort discovery query.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'intitle',
    label: 'Title term',
    category: 'content',
    description: 'Require a term or phrase in the result page title.',
    aliases: ['title'],
    engines: {
      google: {
        status: 'observed',
        syntax: ['intitle:{term}', 'intitle:"{phrase}"'],
        semantics: 'Targets the next term or quoted phrase in the page title.',
        notes: ['Verified against live Google results in July 2026 but absent from current Google operator help.'],
        sourceUrls: [GOOGLE_FIELD_GUIDE, GOOGLE_2026_OBSERVATION],
        surfaces: ['web'],
        safeForGeneration: true
      },
      bing: {
        status: 'documented',
        syntax: ['intitle:{term}'],
        semantics: 'Requires one term in title metadata.',
        notes: ['Specify one term per keyword and chain multiple intitle entries when needed.'],
        sourceUrls: [BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: {
        status: 'fragile',
        syntax: ['intitle:{term}'],
        semantics: 'Requests pages whose title includes the word.',
        notes: ['Documented, subject to DuckDuckGo related-result fallback and source variability.'],
        sourceUrls: [DDG_SYNTAX],
        surfaces: ['web'],
        safeForGeneration: true
      }
    }
  },
  {
    id: 'allintitle',
    label: 'All title terms',
    category: 'content',
    description: 'Require every following term in the title.',
    aliases: ['title-all'],
    engines: {
      google: {
        status: 'fragile',
        syntax: ['allintitle:{terms}'],
        semantics: 'Historically applies title matching to all following terms.',
        notes: ['July 2026 testing found heavy relaxation; repeated intitle clauses were more dependable.'],
        sourceUrls: [GOOGLE_FIELD_GUIDE, GOOGLE_2026_OBSERVATION],
        surfaces: ['web'],
        safeForGeneration: false,
        replacement: 'Chain intitle:{term} once per term.'
      },
      bing: unsupported(
        'Bing documents only one-term intitle.',
        'Chain intitle:{term} once per term.',
        [BING_KEYWORDS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo documents intitle but not allintitle.',
        'Chain intitle terms cautiously or issue separate queries.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'inurl',
    label: 'URL term',
    category: 'content',
    description: 'Require a term in the page URL.',
    aliases: ['url-contains'],
    engines: {
      google: {
        status: 'fragile',
        syntax: ['inurl:{term}', 'inurl:"{phrase}"'],
        semantics: 'Biases or filters toward URLs containing the next term.',
        notes: ['A July 2026 control found a real effect but also results that violated the apparent constraint.'],
        sourceUrls: [GOOGLE_FIELD_GUIDE, GOOGLE_2026_OBSERVATION],
        surfaces: ['web'],
        safeForGeneration: true
      },
      bing: deprecated(
        ['inurl:{term}'],
        'Bing publicly disabled the Google-style inurl operator and does not list it in current keywords.',
        'Use site: for domain or shallow-directory scope; Bing has no direct URL-substring replacement.',
        [BING_INURL_RETIREMENT, BING_KEYWORDS]
      ),
      duckduckgo: {
        status: 'fragile',
        syntax: ['inurl:{term}'],
        semantics: 'Requests pages whose URL includes the word.',
        notes: ['Documented, subject to DuckDuckGo advanced-syntax reliability limits.'],
        sourceUrls: [DDG_SYNTAX],
        surfaces: ['web'],
        safeForGeneration: true
      }
    }
  },
  {
    id: 'allinurl',
    label: 'All URL terms',
    category: 'content',
    description: 'Require every following term in the page URL.',
    aliases: ['url-all'],
    engines: {
      google: {
        status: 'fragile',
        syntax: ['allinurl:{terms}'],
        semantics: 'Historically applies URL matching to all following terms.',
        notes: ['Current control testing found relaxed constraint behavior.'],
        sourceUrls: [GOOGLE_FIELD_GUIDE, GOOGLE_2026_OBSERVATION],
        surfaces: ['web'],
        safeForGeneration: false,
        replacement: 'Chain inurl:{term} clauses and validate the returned URLs.'
      },
      bing: unsupported(
        'Bing does not document allinurl.',
        'Use site: for supported directory scope.',
        [BING_KEYWORDS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo does not document allinurl.',
        'Chain inurl terms cautiously or issue separate queries.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'intext',
    label: 'Body-text term',
    category: 'content',
    description: 'Require a term or phrase in indexed page text.',
    aliases: ['text'],
    engines: {
      google: {
        status: 'observed',
        syntax: ['intext:{term}', 'intext:"{phrase}"'],
        semantics: 'Targets the next term or quoted phrase in page text.',
        notes: ['Verified in July 2026; absent from the current short Google help list.'],
        sourceUrls: [GOOGLE_FIELD_GUIDE, GOOGLE_2026_OBSERVATION],
        surfaces: ['web'],
        safeForGeneration: true
      },
      bing: unsupported(
        'Bing does not document intext.',
        'Use inbody:{term}.',
        [BING_KEYWORDS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo does not document a body-text operator.',
        'Use an exact phrase or site-scoped ordinary query.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'allintext',
    label: 'All body-text terms',
    category: 'content',
    description: 'Require all following terms in indexed page text.',
    aliases: ['text-all'],
    engines: {
      google: {
        status: 'observed',
        syntax: ['allintext:{terms}'],
        semantics: 'Targets all following terms in page text.',
        notes: ['Verified in July 2026; do not mix allin operators with unrelated trailing operators.'],
        sourceUrls: [GOOGLE_FIELD_GUIDE, GOOGLE_2026_OBSERVATION],
        surfaces: ['web'],
        safeForGeneration: true
      },
      bing: {
        status: 'documented',
        syntax: ['inbody:{term} inbody:{term}'],
        semantics: 'Bing has no allinbody token, but chaining documented one-term inbody clauses supplies the capability.',
        notes: ['Each inbody occurrence accepts one term.'],
        sourceUrls: [BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: unsupported(
        'DuckDuckGo has no documented all-body-text syntax.',
        'Use exact phrases or separate searches.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'inbody',
    label: 'Bing body term',
    category: 'content',
    description: 'Require one term in body metadata using Bing-native syntax.',
    aliases: ['body'],
    engines: {
      google: unsupported(
        'Google does not use Bing inbody syntax.',
        'Use intext:{term}.',
        [GOOGLE_HELP, GOOGLE_FIELD_GUIDE]
      ),
      bing: {
        status: 'documented',
        syntax: ['inbody:{term}'],
        semantics: 'Requires one term in the page body.',
        notes: ['Chain one inbody clause per required term.'],
        sourceUrls: [BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: unsupported(
        'DuckDuckGo does not document inbody.',
        'Use an exact phrase or ordinary scoped query.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'inanchor',
    label: 'Inbound-anchor term',
    category: 'content',
    description: 'Match text used by links pointing to the result page.',
    aliases: ['anchor'],
    engines: {
      google: {
        status: 'observed',
        syntax: ['inanchor:{term}', 'inanchor:"{phrase}"'],
        semantics: 'Targets the next term in inbound anchor text.',
        notes: ['Verified in July 2026 but is sampled and must not be treated as a backlink inventory.'],
        sourceUrls: [GOOGLE_FIELD_GUIDE, GOOGLE_2026_OBSERVATION],
        surfaces: ['web'],
        safeForGeneration: true
      },
      bing: {
        status: 'documented',
        syntax: ['inanchor:{term}'],
        semantics: 'Requires one term in anchor metadata.',
        notes: ['Chain one clause per term.'],
        sourceUrls: [BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: unsupported(
        'DuckDuckGo does not document anchor-text matching.',
        'Use ordinary keyword searches or a dedicated backlink index.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'allinanchor',
    label: 'All inbound-anchor terms',
    category: 'content',
    description: 'Require every following term in inbound anchor text.',
    aliases: ['anchor-all'],
    engines: {
      google: {
        status: 'fragile',
        syntax: ['allinanchor:{terms}'],
        semantics: 'Historically applies inbound-anchor matching to all following terms.',
        notes: ['Present in the 2024 field guide but absent from current vendor help and the July 2026 control set.'],
        sourceUrls: [GOOGLE_FIELD_GUIDE],
        surfaces: ['web'],
        safeForGeneration: false,
        replacement: 'Chain inanchor:{term} clauses.'
      },
      bing: {
        status: 'documented',
        syntax: ['inanchor:{term} inanchor:{term}'],
        semantics: 'Chained one-term inanchor clauses provide all-term matching.',
        notes: ['Bing does not document an allinanchor token.'],
        sourceUrls: [BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: unsupported(
        'DuckDuckGo has no documented anchor-text syntax.',
        'Use a dedicated backlink index.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'filetype',
    label: 'File type',
    category: 'file',
    description: 'Restrict results to an indexed file or document type.',
    aliases: ['mime-type'],
    engines: {
      google: {
        status: 'documented',
        syntax: ['filetype:{extension}'],
        semantics: 'Filters by content type or file extension.',
        notes: ['Only indexed file formats can appear; current official documentation includes CSV.'],
        sourceUrls: [GOOGLE_SEARCH_OPERATORS, GOOGLE_FILE_TYPES],
        surfaces: ['web'],
        safeForGeneration: true
      },
      bing: {
        status: 'documented',
        syntax: ['filetype:{type}'],
        semantics: 'Returns pages created in the specified file type.',
        notes: ['Microsoft distinguishes filetype from filename extension matching.'],
        sourceUrls: [BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: {
        status: 'fragile',
        syntax: ['filetype:{type}'],
        semantics: 'Filters to supported document types.',
        notes: ['Supported set is pdf, doc/docx, xls/xlsx, ppt/pptx, and html; related-result fallback may relax it.'],
        sourceUrls: [DDG_SYNTAX],
        surfaces: ['web'],
        safeForGeneration: true
      }
    }
  },
  {
    id: 'ext',
    label: 'Filename extension',
    category: 'file',
    description: 'Restrict results by filename extension.',
    aliases: ['extension'],
    engines: {
      google: {
        status: 'fragile',
        syntax: ['ext:{extension}'],
        semantics: 'Historical alias for filetype with less consistent current behavior.',
        notes: ['July 2026 testing found fewer conforming results than filetype.'],
        sourceUrls: [GOOGLE_2026_OBSERVATION],
        surfaces: ['web'],
        safeForGeneration: false,
        replacement: 'Use filetype:{extension}.'
      },
      bing: {
        status: 'documented',
        syntax: ['ext:{extension}'],
        semantics: 'Returns pages with the specified filename extension.',
        notes: ['This is distinct from Bing filetype semantics.'],
        sourceUrls: [BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: unsupported(
        'DuckDuckGo does not document ext.',
        'Use filetype for one of DuckDuckGo supported document types.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'contains',
    label: 'Links to file type',
    category: 'file',
    description: 'Find pages that link to a specified file extension.',
    aliases: ['linked-extension'],
    engines: {
      google: unsupported(
        'Google has no documented contains-file operator.',
        'Search for the extension in text or use a dedicated crawler.',
        [GOOGLE_SEARCH_OPERATORS]
      ),
      bing: {
        status: 'documented',
        syntax: ['contains:{extension}'],
        semantics: 'Finds pages containing links to files with the specified extension.',
        notes: ['It finds linking pages, not necessarily files of that type.'],
        sourceUrls: [BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: unsupported(
        'DuckDuckGo has no documented equivalent.',
        'Use a site-scoped extension phrase or a crawler.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'before',
    label: 'Before date',
    category: 'date',
    description: 'Restrict results to documents dated before a boundary.',
    aliases: ['date-before'],
    engines: {
      google: {
        status: 'documented',
        syntax: ['before:YYYY-MM-DD', 'before:YYYY'],
        semantics: 'Finds documents last updated before the supplied date.',
        notes: ['Prefer ISO dates; Google dates can be inferred and need not equal original publication time.'],
        sourceUrls: [GOOGLE_HELP],
        surfaces: ['web'],
        safeForGeneration: true
      },
      bing: unsupported(
        'Bing has no current documented before text operator.',
        'Use the Bing result-page date filter.',
        [BING_OPTIONS, BING_KEYWORDS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo has no documented before text operator.',
        'Use the date dropdown or custom date range.',
        [DDG_DATES]
      )
    }
  },
  {
    id: 'after',
    label: 'After date',
    category: 'date',
    description: 'Restrict results to documents dated after a boundary.',
    aliases: ['date-after'],
    engines: {
      google: {
        status: 'documented',
        syntax: ['after:YYYY-MM-DD', 'after:YYYY'],
        semantics: 'Finds documents last updated after the supplied date.',
        notes: ['Combine with before for a range. Prefer ISO dates.'],
        sourceUrls: [GOOGLE_HELP],
        surfaces: ['web'],
        safeForGeneration: true
      },
      bing: unsupported(
        'Bing has no current documented after text operator.',
        'Use the Bing result-page date filter.',
        [BING_OPTIONS, BING_KEYWORDS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo has no documented after text operator.',
        'Use the date dropdown or custom date range.',
        [DDG_DATES]
      )
    }
  },
  {
    id: 'numeric-range',
    label: 'Numeric range',
    category: 'date',
    description: 'Match numbers between inclusive-looking endpoints.',
    aliases: ['double-dot', '..'],
    engines: {
      google: {
        status: 'documented',
        syntax: ['{minimum}..{maximum}'],
        semantics: 'Requests results containing numbers in the given range.',
        notes: ['This is numeric matching, not a reliable publication-date filter.'],
        sourceUrls: [GOOGLE_ADVANCED],
        surfaces: ['web'],
        safeForGeneration: true
      },
      bing: unsupported(
        'Current Bing documentation does not define the double-dot range.',
        'Use explicit values, grouped OR, or UI filters.',
        [BING_OPTIONS, BING_KEYWORDS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo does not document numeric ranges.',
        'Use explicit alternatives or separate queries.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'proximity',
    label: 'Term proximity',
    category: 'proximity',
    description: 'Require two terms or phrases within a word-distance window.',
    aliases: ['AROUND', 'NEAR'],
    engines: {
      google: {
        status: 'observed',
        syntax: ['{term} AROUND({distance}) {term}'],
        semantics: 'Finds documents where the two operands occur within the requested distance.',
        notes: ['Uppercase AROUND; order is not preserved. Verified by a July 2026 control.'],
        sourceUrls: [GOOGLE_FIELD_GUIDE, GOOGLE_2026_OBSERVATION],
        surfaces: ['web'],
        safeForGeneration: true
      },
      bing: {
        status: 'fragile',
        syntax: ['{term} NEAR:{distance} {term}'],
        semantics: 'NEAR syntax circulates but is absent from the current Microsoft operator contract.',
        notes: ['Treat as a laboratory candidate, not production generation syntax.'],
        sourceUrls: [BING_OPTIONS, BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: false,
        replacement: 'Use a quoted phrase or separate ordered queries.'
      },
      duckduckgo: unsupported(
        'DuckDuckGo has no documented proximity operator.',
        'Use an exact phrase or the experimental semantic phrase syntax.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'language',
    label: 'Result language',
    category: 'locale',
    description: 'Restrict or configure the language of returned documents.',
    aliases: ['lang'],
    engines: {
      google: unsupported(
        'Google exposes language as an Advanced Search or result setting, not a current text operator.',
        'Use Google Advanced Search or its result-language UI.',
        [GOOGLE_ADVANCED, GOOGLE_HELP]
      ),
      bing: {
        status: 'documented',
        syntax: ['language:{code}'],
        semantics: 'Returns pages in the specified language code.',
        notes: ['Place the code immediately after the colon.'],
        sourceUrls: [BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: unsupported(
        'DuckDuckGo has no language query operator; region and language preferences are settings.',
        'Use DuckDuckGo region/language settings or an explicit language keyword.',
        [DDG_SYNTAX],
        ['URL settings are not treated as query operators in this catalog.']
      )
    }
  },
  {
    id: 'location',
    label: 'Country or region',
    category: 'locale',
    description: 'Restrict or configure results for a country or region.',
    aliases: ['loc'],
    engines: {
      google: unsupported(
        'Google has no current loc: or location: web-query operator.',
        'Use Advanced Search region controls or explicit place terms.',
        [GOOGLE_ADVANCED]
      ),
      bing: {
        status: 'documented',
        syntax: ['loc:{countryCode}', 'location:{countryCode}'],
        semantics: 'Returns pages from the specified country or region.',
        notes: ['Group multiple alternatives with Bing OR. Availability can vary by region.'],
        sourceUrls: [BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: unsupported(
        'DuckDuckGo has no location query operator.',
        'Use region settings or add an explicit location term.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'ip',
    label: 'Hosting IP',
    category: 'scope',
    description: 'Find sites hosted at a specific IPv4 address.',
    aliases: ['host-ip'],
    engines: {
      google: unsupported(
        'Google has no documented hosting-IP operator.',
        'Use an authorized passive-DNS or infrastructure search source.',
        [GOOGLE_SEARCH_OPERATORS]
      ),
      bing: {
        status: 'documented',
        syntax: ['ip:{dottedQuad}'],
        semantics: 'Finds sites hosted by the supplied dotted-quad IPv4 address.',
        notes: ['The operand must be a dotted quad. Shared hosting can produce unrelated sites.'],
        sourceUrls: [BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: unsupported(
        'DuckDuckGo has no documented IP operator.',
        'Use an authorized passive-DNS or infrastructure search source.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'prefer',
    label: 'Preference boost',
    category: 'content',
    description: 'Boost a term or another operator without making it a hard filter.',
    aliases: ['boost'],
    engines: {
      google: unsupported(
        'Google has no documented prefer query operator.',
        'Use a quoted phrase or a more specific field constraint.',
        [GOOGLE_HELP]
      ),
      bing: {
        status: 'documented',
        syntax: ['prefer:{termOrOperator}'],
        semantics: 'Adds emphasis to a term or operator.',
        notes: ['This is a ranking preference, not a hard filter.'],
        sourceUrls: [BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: unsupported(
        'DuckDuckGo has no prefer token.',
        'Use +{term} for DuckDuckGo soft boosting.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'feed',
    label: 'RSS or Atom feed',
    category: 'feed',
    description: 'Find feeds matching a topic.',
    aliases: ['rss', 'atom'],
    engines: {
      google: unsupported(
        'Google has no current documented feed operator.',
        'Search for RSS or Atom file patterns or inspect the authorized site.',
        [GOOGLE_SEARCH_OPERATORS]
      ),
      bing: {
        status: 'documented',
        syntax: ['feed:{term}'],
        semantics: 'Finds RSS or Atom feeds for the search term.',
        notes: ['No space after the colon.'],
        sourceUrls: [BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: unsupported(
        'DuckDuckGo has no documented feed operator.',
        'Search for RSS or Atom terms within a site scope.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'hasfeed',
    label: 'Page exposes a feed',
    category: 'feed',
    description: 'Find pages that contain or expose an RSS or Atom feed.',
    aliases: ['has-rss'],
    engines: {
      google: unsupported(
        'Google has no current documented hasfeed operator.',
        'Inspect link metadata on the authorized site.',
        [GOOGLE_SEARCH_OPERATORS]
      ),
      bing: {
        status: 'documented',
        syntax: ['hasfeed:{term}'],
        semantics: 'Finds pages that contain a feed related to the term.',
        notes: ['Microsoft examples combine this with site scope.'],
        sourceUrls: [BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: true
      },
      duckduckgo: unsupported(
        'DuckDuckGo has no documented hasfeed operator.',
        'Inspect the authorized site or search for feed terms.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'source',
    label: 'News source',
    category: 'feed',
    description: 'Restrict a news search to a publisher source.',
    aliases: ['publisher'],
    engines: {
      google: {
        status: 'fragile',
        syntax: ['source:{publisher}'],
        semantics: 'Legacy Google News syntax for a publisher source.',
        notes: ['Google News still exposes a publisher-site filter, but current help does not contract this text syntax.'],
        sourceUrls: [GOOGLE_NEWS_HELP, GOOGLE_FIELD_GUIDE],
        surfaces: ['news'],
        safeForGeneration: false,
        replacement: 'Use the Google News publisher-site filter.'
      },
      bing: unsupported(
        'Bing does not list source as a current web operator.',
        'Use site: with the publisher domain or Bing News filters.',
        [BING_KEYWORDS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo does not document a publisher-source operator.',
        'Use site: with the publisher domain.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'imagesize',
    label: 'Exact image dimensions',
    category: 'image',
    description: 'Find images with exact pixel dimensions.',
    aliases: ['image-size'],
    engines: {
      google: {
        status: 'documented',
        syntax: ['imagesize:{width}x{height}'],
        semantics: 'Returns images with the exact dimensions on Google Images.',
        notes: ['Has no effect on other Google Search surfaces and is subject to retrieval limits.'],
        sourceUrls: [GOOGLE_IMAGE],
        surfaces: ['images'],
        safeForGeneration: true
      },
      bing: unsupported(
        'Bing exposes image sizing through image-search controls, not this query token.',
        'Use Bing Images filters.',
        [BING_OPTIONS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo does not document an image-dimension query operator.',
        'Use DuckDuckGo image filters.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'src',
    label: 'Image source URL',
    category: 'image',
    description: 'Find pages that reference an exact image URL.',
    aliases: ['image-src', 'hotlink'],
    engines: {
      google: {
        status: 'documented',
        syntax: ['src:{imageUrl}'],
        semantics: 'Returns pages referencing the exact image URL in an image src attribute.',
        notes: ['Google Images only; it may reveal cross-domain hotlinks but remains retrieval-limited.'],
        sourceUrls: [GOOGLE_IMAGE],
        surfaces: ['images'],
        safeForGeneration: true
      },
      bing: unsupported(
        'Bing has no documented src query operator.',
        'Use a reverse-image workflow or exact URL phrase.',
        [BING_KEYWORDS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo has no documented src query operator.',
        'Use an image-search or exact URL workflow.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'ddg-semantic',
    label: 'Semantic phrase expansion',
    category: 'exact',
    description: 'Expand a quoted phrase to semantically similar orderings and forms.',
    aliases: ['semantic-similar'],
    engines: {
      google: unsupported(
        'Google has no equivalent query token; synonym expansion occurs automatically in ordinary searches.',
        'Use ordinary terms or explicit OR alternatives.',
        [GOOGLE_HELP]
      ),
      bing: unsupported(
        'Bing has no documented semantic-phrase token.',
        'Use OR alternatives.',
        [BING_OPTIONS]
      ),
      duckduckgo: {
        status: 'fragile',
        syntax: ['~"{phrase}"'],
        semantics: 'Experimental syntax that adds semantically similar versions of the phrase.',
        notes: ['Vendor-labeled experimental and therefore not a stable contract.'],
        sourceUrls: [DDG_SYNTAX],
        surfaces: ['web'],
        safeForGeneration: true
      }
    }
  },
  {
    id: 'ddg-first-result',
    label: 'Open first result',
    category: 'routing',
    description: 'Route directly to the first result rather than displaying a result set.',
    aliases: ['backslash'],
    engines: {
      google: unsupported(
        'Google has no documented first-result routing prefix.',
        'Display the result page and let the user choose.',
        [GOOGLE_HELP]
      ),
      bing: unsupported(
        'Bing has no documented first-result routing prefix.',
        'Display the result page and let the user choose.',
        [BING_OPTIONS]
      ),
      duckduckgo: {
        status: 'documented',
        syntax: ['\\{query}'],
        semantics: 'Navigates directly to the first DuckDuckGo result.',
        notes: ['This changes destination and skips review of the result set.'],
        sourceUrls: [DDG_SYNTAX],
        surfaces: ['routing'],
        safeForGeneration: false,
        replacement: 'Open a normal DuckDuckGo result page for review.'
      }
    }
  },
  {
    id: 'ddg-bang',
    label: 'External-site bang',
    category: 'routing',
    description: 'Route a query to another site search.',
    aliases: ['bang', '!'],
    engines: {
      google: unsupported(
        'Google has no bang-routing contract.',
        'Use a configured site-search template.',
        [GOOGLE_HELP]
      ),
      bing: unsupported(
        'Bing has no bang-routing contract.',
        'Use a configured site-search template.',
        [BING_OPTIONS]
      ),
      duckduckgo: {
        status: 'documented',
        syntax: ['!{bang} {query}'],
        semantics: 'Sends the query to the selected external site search.',
        notes: ['The destination site policies and data collection apply; DuckDuckGo result privacy does not carry over.'],
        sourceUrls: [DDG_SYNTAX, DDG_BANGS],
        surfaces: ['routing'],
        safeForGeneration: false,
        replacement: 'Use an explicitly reviewed NERD-mode site-search template.'
      }
    }
  },
  {
    id: 'safe-search',
    label: 'Per-query Safe Search toggle',
    category: 'utility',
    description: 'Change explicit-content filtering for a single query.',
    aliases: ['safeon', 'safeoff'],
    engines: {
      google: unsupported(
        'Google SafeSearch is a setting rather than a supported query token.',
        'Use the Google SafeSearch setting.',
        [GOOGLE_HELP]
      ),
      bing: unsupported(
        'Bing does not document a SafeSearch query token in advanced options.',
        'Use Bing SafeSearch controls.',
        [BING_OPTIONS]
      ),
      duckduckgo: {
        status: 'documented',
        syntax: ['{query} !safeon', '{query} !safeoff'],
        semantics: 'Enables or disables Safe Search for that query.',
        notes: ['This changes filtering rather than document matching.'],
        sourceUrls: [DDG_SYNTAX],
        surfaces: ['settings'],
        safeForGeneration: false,
        replacement: 'Respect the user existing Safe Search setting unless explicitly selected.'
      }
    }
  },
  {
    id: 'cache',
    label: 'Cached page',
    category: 'legacy',
    description: 'Retrieve a search-engine-stored copy of a page.',
    aliases: ['cached'],
    engines: {
      google: deprecated(
        ['cache:{url}'],
        'Google states that the cache operator no longer works.',
        'Use a lawful web archive or a current authorized capture.',
        [GOOGLE_CHANGELOG]
      ),
      bing: unsupported(
        'Bing has no current documented cached-page operator.',
        'Use a lawful web archive or a current authorized capture.',
        [BING_OPTIONS, BING_KEYWORDS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo has no documented cached-page operator.',
        'Use a lawful web archive or a current authorized capture.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'related',
    label: 'Related sites',
    category: 'legacy',
    description: 'Find sites categorized as similar to a supplied URL.',
    aliases: ['similar-sites'],
    engines: {
      google: deprecated(
        ['related:{url}'],
        'Google removed related from its operator documentation because it is no longer supported.',
        'Compare domains ranking for the same neutral topic.',
        [GOOGLE_CHANGELOG]
      ),
      bing: {
        status: 'fragile',
        syntax: ['related:{url}'],
        semantics: 'The syntax is circulated externally but absent from current Microsoft documentation.',
        notes: ['Do not treat returned ordinary results as proof that the operator worked.'],
        sourceUrls: [BING_OPTIONS, BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: false,
        replacement: 'Compare domains ranking for the same neutral topic.'
      },
      duckduckgo: unsupported(
        'DuckDuckGo does not document related-site syntax.',
        'Compare domains ranking for the same neutral topic.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'info',
    label: 'Page information',
    category: 'legacy',
    description: 'Display search-engine metadata about a URL.',
    aliases: ['id'],
    engines: {
      google: deprecated(
        ['info:{url}', 'id:{url}'],
        'Google retired info in 2019; the undocumented id alias has no remaining function.',
        'Use Search Console URL Inspection for properties you control.',
        [GOOGLE_INFO_RETIREMENT]
      ),
      bing: {
        status: 'fragile',
        syntax: ['info:{url}'],
        semantics: 'The syntax is externally circulated but absent from current Microsoft documentation.',
        notes: ['Treat as unsupported in generation.'],
        sourceUrls: [BING_OPTIONS, BING_KEYWORDS],
        surfaces: ['web'],
        safeForGeneration: false,
        replacement: 'Use url:{url} for Bing index presence only.'
      },
      duckduckgo: unsupported(
        'DuckDuckGo has no documented page-information operator.',
        'Use site scope or the site own published metadata.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'link',
    label: 'Backlinks',
    category: 'legacy',
    description: 'Find pages linking to a supplied URL.',
    aliases: ['backlink'],
    engines: {
      google: deprecated(
        ['link:{url}'],
        'Google confirmed that link no longer functions as a backlink command.',
        'Use an authorized backlink index; inanchor can explore anchor topics but is not an inventory.',
        [GOOGLE_LINK_RETIREMENT]
      ),
      bing: deprecated(
        ['link:{url}', 'linkfromdomain:{domain}'],
        'Legacy Bing link exploration is absent from current query documentation and Bing retired Link Explorer.',
        'Use an authorized backlink index.',
        [BING_LINK_RETIREMENT, BING_KEYWORDS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo has no documented backlink operator.',
        'Use an authorized backlink index.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'synonym',
    label: 'Legacy synonym expansion',
    category: 'legacy',
    description: 'Explicitly request synonyms with a tilde prefix.',
    aliases: ['tilde', '~term'],
    engines: {
      google: deprecated(
        ['~{term}'],
        'The legacy synonym operator was removed after synonym expansion became automatic.',
        'Use explicit OR alternatives when exact control matters.',
        [GOOGLE_FIELD_GUIDE]
      ),
      bing: unsupported(
        'Bing does not document tilde synonym expansion.',
        'Use grouped OR alternatives.',
        [BING_OPTIONS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo does not document tilde on a bare term.',
        'Use ~"{phrase}" only for the experimental semantic phrase feature.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'daterange',
    label: 'Legacy Julian date range',
    category: 'legacy',
    description: 'Filter by a Julian-number date interval.',
    aliases: ['julian-range'],
    engines: {
      google: deprecated(
        ['daterange:{julianStart}-{julianEnd}'],
        'Current testing finds the legacy Julian date syntax ignored.',
        'Use after:YYYY-MM-DD and before:YYYY-MM-DD.',
        [GOOGLE_2026_OBSERVATION]
      ),
      bing: unsupported(
        'Bing does not document daterange.',
        'Use result-page date filters.',
        [BING_OPTIONS, BING_KEYWORDS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo does not document daterange.',
        'Use the date dropdown or custom range.',
        [DDG_DATES]
      )
    }
  },
  {
    id: 'phonebook',
    label: 'Legacy phonebook',
    category: 'legacy',
    description: 'Look up phone numbers associated with a person or organization.',
    aliases: ['rphonebook', 'bphonebook'],
    engines: {
      google: deprecated(
        ['phonebook:{name}', 'rphonebook:{name}', 'bphonebook:{name}'],
        'The phonebook operators are retired and silently ignored.',
        'Use consent-respecting official directories and public organization contact pages.',
        [GOOGLE_FIELD_GUIDE, GOOGLE_2026_OBSERVATION]
      ),
      bing: unsupported(
        'Bing has no documented phonebook query operator.',
        'Use official public directories.',
        [BING_OPTIONS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo has no documented phonebook query operator.',
        'Use official public directories.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'legacy-groups',
    label: 'Legacy Google Groups fields',
    category: 'legacy',
    description: 'Search old Groups or Usenet author, group, or subject fields.',
    aliases: ['author', 'group', 'insubject'],
    engines: {
      google: deprecated(
        ['author:{name}', 'group:{name}', 'insubject:{term}'],
        'These were service-specific Google Groups fields, not current Google Web operators.',
        'Use the current Google Groups interface or a site-scoped web query.',
        [GOOGLE_FIELD_GUIDE, GOOGLE_2026_OBSERVATION]
      ),
      bing: unsupported(
        'Bing does not document Google Groups field syntax.',
        'Use a site-scoped query.',
        [BING_KEYWORDS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo does not document Groups field syntax.',
        'Use a site-scoped query.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'legacy-blog-search',
    label: 'Legacy Google Blog Search fields',
    category: 'legacy',
    description: 'Search discontinued blog-specific metadata.',
    aliases: ['blogurl', 'inpostauthor', 'allinpostauthor', 'inposttitle'],
    engines: {
      google: deprecated(
        ['blogurl:{url}', 'inpostauthor:{name}', 'allinpostauthor:{name}', 'inposttitle:{term}'],
        'These tokens belonged to discontinued Google Blog Search.',
        'Use site, intitle, inurl, and exact phrases on the web index.',
        [GOOGLE_FIELD_GUIDE]
      ),
      bing: unsupported(
        'Bing has no documented Google Blog Search metadata syntax.',
        'Use site and intitle.',
        [BING_KEYWORDS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo has no documented blog metadata syntax.',
        'Use site and intitle.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'patent',
    label: 'Legacy patent prefix',
    category: 'legacy',
    description: 'Search for a patent number from the general web search box.',
    aliases: ['patent-number'],
    engines: {
      google: deprecated(
        ['patent:{number}'],
        'Current live testing returned no operator-specific results.',
        'Search Google Patents directly at https://patents.google.com/.',
        [GOOGLE_2026_OBSERVATION]
      ),
      bing: unsupported(
        'Bing does not document a patent prefix.',
        'Use an official patent database.',
        [BING_OPTIONS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo does not document a patent prefix.',
        'Use an official patent database.',
        [DDG_SYNTAX]
      )
    }
  },
  {
    id: 'utility-answer',
    label: 'Instant-answer prefixes',
    category: 'utility',
    description: 'Trigger an answer card rather than filter the web index.',
    aliases: ['define', 'weather', 'stocks', 'movie', 'map', 'time', 'currency', 'music', 'book'],
    engines: {
      google: {
        status: 'fragile',
        syntax: [
          'define {term}',
          'weather:{location}',
          'stocks:{ticker}',
          'movie:{title}'
        ],
        semantics: 'Some forms may trigger a dictionary, weather, finance, or movie answer card.',
        notes: ['These are not dependable index filters and several historical prefixes no longer trigger panels.'],
        sourceUrls: [GOOGLE_FIELD_GUIDE, GOOGLE_2026_OBSERVATION],
        surfaces: ['web'],
        safeForGeneration: false,
        replacement: 'Use ordinary natural-language utility queries or the dedicated Google product.'
      },
      bing: unsupported(
        'Current advanced-search documentation does not define these as index operators.',
        'Use ordinary natural-language utility queries.',
        [BING_OPTIONS]
      ),
      duckduckgo: unsupported(
        'DuckDuckGo Instant Answers are result features, not documented query operators.',
        'Use ordinary natural-language utility queries.',
        [DDG_SYNTAX, DDG_SOURCES]
      )
    }
  }
] as const satisfies readonly SearchOperatorCatalogEntry[];

export const SEARCH_OPERATOR_CATALOG: SearchOperatorCatalogDocument = {
  lastReviewed: SEARCH_OPERATOR_CATALOG_LAST_REVIEWED,
  operators: SEARCH_OPERATOR_ROWS
};

const SEARCH_OPERATOR_BY_ID = new Map<string, SearchOperatorCatalogEntry>(
  SEARCH_OPERATOR_ROWS.map((operator) => [operator.id, operator])
);

export function getSearchOperatorById(
  operatorId: string
): SearchOperatorCatalogEntry | undefined {
  return SEARCH_OPERATOR_BY_ID.get(operatorId);
}

export function getSearchOperatorSupport(
  operator: SearchOperatorCatalogEntry | string,
  engineId: CoreWebSearchEngineId
): SearchOperatorEngineSupport | undefined {
  const entry =
    typeof operator === 'string' ? getSearchOperatorById(operator) : operator;
  return entry?.engines[engineId];
}

export function getSearchOperatorsForEngine(
  engineId: CoreWebSearchEngineId,
  options: SearchOperatorFilterOptions = {}
): SearchOperatorCatalogEntry[] {
  const categories = options.categories
    ? new Set<SearchOperatorCategory>(options.categories)
    : undefined;
  const statuses = options.statuses
    ? new Set<SearchOperatorSupportStatus>(options.statuses)
    : undefined;
  const surfaces = options.surfaces
    ? new Set<SearchOperatorSurface>(options.surfaces)
    : undefined;

  return SEARCH_OPERATOR_ROWS.filter((operator) => {
    const support = operator.engines[engineId];
    if (categories && !categories.has(operator.category)) {
      return false;
    }
    if (statuses && !statuses.has(support.status)) {
      return false;
    }
    if (options.safeForGenerationOnly && !support.safeForGeneration) {
      return false;
    }
    if (
      surfaces &&
      !support.surfaces.some((surface) => surfaces.has(surface))
    ) {
      return false;
    }
    return true;
  });
}

export function getSafeSearchOperatorsForEngine(
  engineId: CoreWebSearchEngineId,
  categories?: readonly SearchOperatorCategory[],
  surfaces: readonly SearchOperatorSurface[] = ['web']
): SearchOperatorCatalogEntry[] {
  return getSearchOperatorsForEngine(engineId, {
    categories,
    surfaces,
    safeForGenerationOnly: true
  });
}

export function getSearchOperatorSyntaxForEngine(
  engineId: CoreWebSearchEngineId,
  options: SearchOperatorFilterOptions = {}
): SearchOperatorSyntaxMatch[] {
  return getSearchOperatorsForEngine(engineId, options).flatMap((operator) => {
    const support = operator.engines[engineId];
    return support.syntax.map((syntax) => ({
      operator,
      support,
      syntax
    }));
  });
}

export function isSearchOperatorSafeForGeneration(
  operator: SearchOperatorCatalogEntry | string,
  engineId: CoreWebSearchEngineId
): boolean {
  return getSearchOperatorSupport(operator, engineId)?.safeForGeneration === true;
}
