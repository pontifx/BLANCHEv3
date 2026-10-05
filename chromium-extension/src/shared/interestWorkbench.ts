export type InterestSignalType = 'host' | 'token';
export type InterestFolderStatus = 'ready' | 'missing' | 'empty';

export interface InterestWorkbenchSettings {
  folderName: string;
  folderId?: string;
  walkDepth: number;
  walkCount: number;
  maxPredictions: number;
}

export interface InterestSignalSummary {
  key: string;
  type: InterestSignalType;
  label: string;
  weight: number;
  count: number;
}

export interface InterestPrediction {
  key: string;
  type: InterestSignalType;
  label: string;
  probability: number;
  support: number;
}

export interface InterestWalkPath {
  path: string[];
  probability: number;
}

export interface InterestBookmarkSummary {
  id: string;
  title: string;
  url: string;
  hostname?: string;
  addedAt: string;
  tokens: string[];
}

export interface InterestRating {
  overall: number;
  hostAffinity: number;
  tokenAffinity: number;
  coverage: number;
  matchedSignals: string[];
}

export interface InterestCurrentTabAnalysis {
  title: string;
  url: string;
  hostname?: string;
  tokens: string[];
  rating: InterestRating;
  predictions: InterestPrediction[];
  futurePaths: InterestWalkPath[];
}

export interface InterestAnalysis {
  generatedAt: string;
  folderId?: string;
  folderName: string;
  folderStatus: InterestFolderStatus;
  bookmarkCount: number;
  topSignals: InterestSignalSummary[];
  recentBookmarks: InterestBookmarkSummary[];
  warnings: string[];
  currentTab?: InterestCurrentTabAnalysis;
}

export interface InterestWorkbenchState {
  settings: InterestWorkbenchSettings;
  lastAnalysis?: InterestAnalysis;
}

export interface InterestBookmarkInput {
  id: string;
  title: string;
  url: string;
  dateAdded?: number;
}

export interface InterestContentInput {
  title: string;
  url: string;
}

export interface InterestAnalysisInput {
  settings: InterestWorkbenchSettings;
  folderId?: string;
  folderFound: boolean;
  bookmarks: InterestBookmarkInput[];
  currentTab?: InterestContentInput;
}

interface ProcessedInterestSample extends InterestBookmarkSummary {
  signalKeys: string[];
  hostKey?: string;
  tokenKeys: string[];
  sortTime: number;
}

const DEFAULT_SETTINGS: InterestWorkbenchSettings = {
  folderName: 'BLANCHE Interest Signals',
  walkDepth: 3,
  walkCount: 48,
  maxPredictions: 6
};

const STOPWORDS = new Set([
  'about',
  'after',
  'again',
  'also',
  'and',
  'are',
  'back',
  'blog',
  'can',
  'content',
  'docs',
  'for',
  'from',
  'home',
  'how',
  'http',
  'https',
  'index',
  'info',
  'into',
  'just',
  'more',
  'news',
  'not',
  'page',
  'post',
  'read',
  'site',
  'that',
  'the',
  'their',
  'this',
  'those',
  'was',
  'what',
  'when',
  'with',
  'your'
]);

const GENERIC_HOST_SEGMENTS = new Set([
  'app',
  'co',
  'com',
  'dev',
  'io',
  'net',
  'org',
  'www'
]);

export function createDefaultInterestWorkbenchSettings(): InterestWorkbenchSettings {
  return {
    ...DEFAULT_SETTINGS
  };
}

export function createDefaultInterestWorkbenchState(): InterestWorkbenchState {
  return {
    settings: createDefaultInterestWorkbenchSettings()
  };
}

export function normalizeInterestWorkbenchState(rawValue: unknown): InterestWorkbenchState {
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return createDefaultInterestWorkbenchState();
  }

  const source = rawValue as Partial<InterestWorkbenchState>;
  return {
    settings: normalizeInterestWorkbenchSettings(source.settings),
    lastAnalysis: normalizeInterestAnalysis(source.lastAnalysis)
  };
}

export function normalizeInterestWorkbenchSettings(
  rawValue: unknown
): InterestWorkbenchSettings {
  const fallback = createDefaultInterestWorkbenchSettings();
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return fallback;
  }

  const source = rawValue as Partial<InterestWorkbenchSettings>;
  return {
    folderName:
      typeof source.folderName === 'string' && source.folderName.trim().length > 0
        ? source.folderName.trim()
        : fallback.folderName,
    folderId:
      typeof source.folderId === 'string' && source.folderId.trim().length > 0
        ? source.folderId.trim()
        : undefined,
    walkDepth: normalizeWholeNumber(source.walkDepth, fallback.walkDepth, 1, 6),
    walkCount: normalizeWholeNumber(source.walkCount, fallback.walkCount, 8, 256),
    maxPredictions: normalizeWholeNumber(source.maxPredictions, fallback.maxPredictions, 3, 12)
  };
}

export function buildInterestAnalysis(input: InterestAnalysisInput): InterestAnalysis {
  const settings = normalizeInterestWorkbenchSettings(input.settings);
  const samples = input.bookmarks
    .map((bookmark) => createProcessedSample(bookmark))
    .filter((sample): sample is ProcessedInterestSample => Boolean(sample))
    .sort((left, right) => left.sortTime - right.sortTime);
  const signalWeights = buildSignalWeights(samples);
  const signalCounts = buildSignalCounts(samples);
  const transitions = buildTransitionGraph(samples);
  const folderStatus = !input.folderFound ? 'missing' : samples.length > 0 ? 'ready' : 'empty';
  const warnings = buildWarnings(folderStatus, samples.length, input.currentTab);
  const topSignals = summarizeSignals(signalWeights, signalCounts).slice(
    0,
    Math.max(settings.maxPredictions, 6)
  );

  return {
    generatedAt: new Date().toISOString(),
    folderId: input.folderId,
    folderName: settings.folderName,
    folderStatus,
    bookmarkCount: samples.length,
    topSignals,
    recentBookmarks: [...samples]
      .sort((left, right) => right.sortTime - left.sortTime)
      .slice(0, 6)
      .map((sample) => ({
        id: sample.id,
        title: sample.title,
        url: sample.url,
        hostname: sample.hostname,
        addedAt: sample.addedAt,
        tokens: sample.tokens
      })),
    warnings,
    currentTab: input.currentTab
      ? analyzeCurrentTab(input.currentTab, signalWeights, transitions, settings)
      : undefined
  };
}

function analyzeCurrentTab(
  currentTab: InterestContentInput,
  signalWeights: Map<string, number>,
  transitions: Map<string, Map<string, number>>,
  settings: InterestWorkbenchSettings
): InterestCurrentTabAnalysis {
  const sample = createProcessedSample({
    id: 'current_tab',
    title: currentTab.title,
    url: currentTab.url,
    dateAdded: Date.now()
  });

  if (!sample) {
    return {
      title: currentTab.title,
      url: currentTab.url,
      tokens: [],
      rating: {
        overall: 0,
        hostAffinity: 0,
        tokenAffinity: 0,
        coverage: 0,
        matchedSignals: []
      },
      predictions: [],
      futurePaths: []
    };
  }

  const matchKeys = sample.signalKeys.filter((key) => signalWeights.has(key));
  const tokenWeights = sample.tokenKeys.map((key) => signalWeights.get(key) ?? 0);
  const maxTokenWeight = getMaximumWeight(signalWeights, 'token');
  const maxHostWeight = getMaximumWeight(signalWeights, 'host');
  const matchedTokenWeight = tokenWeights.reduce((sum, weight) => sum + weight, 0);
  const tokenAffinity =
    sample.tokenKeys.length > 0 && maxTokenWeight > 0
      ? clamp01(matchedTokenWeight / (sample.tokenKeys.length * maxTokenWeight))
      : 0;
  const hostAffinity =
    sample.hostKey && maxHostWeight > 0
      ? clamp01((signalWeights.get(sample.hostKey) ?? 0) / maxHostWeight)
      : 0;
  const coverage =
    sample.signalKeys.length > 0 ? clamp01(matchKeys.length / sample.signalKeys.length) : 0;
  const overall = clamp01(0.45 * tokenAffinity + 0.3 * hostAffinity + 0.25 * coverage);
  const forecast = runMarkovForecast(
    sample.signalKeys,
    signalWeights,
    transitions,
    settings,
    currentTab.url
  );

  return {
    title: currentTab.title,
    url: currentTab.url,
    hostname: sample.hostname,
    tokens: sample.tokens,
    rating: {
      overall,
      hostAffinity,
      tokenAffinity,
      coverage,
      matchedSignals: matchKeys.map(formatSignalLabel)
    },
    predictions: forecast.predictions,
    futurePaths: forecast.futurePaths
  };
}

function runMarkovForecast(
  currentSignalKeys: string[],
  signalWeights: Map<string, number>,
  transitions: Map<string, Map<string, number>>,
  settings: InterestWorkbenchSettings,
  seedValue: string
): {
  predictions: InterestPrediction[];
  futurePaths: InterestWalkPath[];
} {
  const supportedStartKeys = currentSignalKeys.filter(
    (key) => signalWeights.has(key) || transitions.has(key)
  );
  const fallbackStartKeys = [...signalWeights.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 4)
    .map(([key]) => key);
  const startKeys = supportedStartKeys.length > 0 ? supportedStartKeys : fallbackStartKeys;
  if (startKeys.length === 0) {
    return {
      predictions: [],
      futurePaths: []
    };
  }

  const random = createSeededRandom(
    `${settings.folderId ?? settings.folderName}|${seedValue}|${settings.walkCount}|${settings.walkDepth}`
  );
  const predictionCounts = new Map<string, number>();
  const pathCounts = new Map<string, number>();

  for (let walkIndex = 0; walkIndex < settings.walkCount; walkIndex += 1) {
    let current = pickWeightedKey(
      startKeys.map((key) => [key, signalWeights.get(key) ?? 1] as const),
      random
    );
    if (!current) {
      continue;
    }

    const path = [formatSignalLabel(current)];
    for (let step = 0; step < settings.walkDepth; step += 1) {
      const options = transitions.get(current);
      if (!options || options.size === 0) {
        break;
      }

      const next = pickWeightedKey(
        [...options.entries()].map(([key, weight]) => [
          key,
          weight * Math.max(signalWeights.get(key) ?? 1, 1)
        ] as const),
        random
      );
      if (!next) {
        break;
      }

      path.push(formatSignalLabel(next));
      incrementCount(predictionCounts, next, 1);
      current = next;
    }

    if (path.length > 1) {
      incrementCount(pathCounts, path.join(' -> '), 1);
    }
  }

  const totalPredictions = [...predictionCounts.values()].reduce((sum, count) => sum + count, 0);
  const predictions = [...predictionCounts.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, settings.maxPredictions)
    .map(([key, support]) => ({
      key,
      type: getSignalType(key),
      label: formatSignalLabel(key),
      probability: totalPredictions > 0 ? support / totalPredictions : 0,
      support
    }));

  const futurePaths = [...pathCounts.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 5)
    .map(([key, count]) => ({
      path: key.split(' -> '),
      probability: count / settings.walkCount
    }));

  return {
    predictions,
    futurePaths
  };
}

function buildWarnings(
  folderStatus: InterestFolderStatus,
  bookmarkCount: number,
  currentTab?: InterestContentInput
): string[] {
  const warnings: string[] = [];
  if (folderStatus === 'missing') {
    warnings.push('No bookmark folder is bound yet. Create or bind a folder before training the model.');
  } else if (folderStatus === 'empty') {
    warnings.push('The bookmark folder is empty. Add a few pages that represent interesting content.');
  }

  if (bookmarkCount > 0 && bookmarkCount < 3) {
    warnings.push('The model has fewer than three bookmarks, so ratings and Markov walks will be noisy.');
  }

  if (!currentTab) {
    warnings.push('No active tab was supplied for scoring.');
  }

  return warnings;
}

function buildSignalWeights(samples: ProcessedInterestSample[]): Map<string, number> {
  const weights = new Map<string, number>();
  const denominator = Math.max(samples.length - 1, 1);

  for (const [index, sample] of samples.entries()) {
    const recencyWeight = 1 + index / denominator;
    for (const signalKey of sample.signalKeys) {
      incrementCount(weights, signalKey, recencyWeight);
    }
  }

  return weights;
}

function buildSignalCounts(samples: ProcessedInterestSample[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const sample of samples) {
    for (const signalKey of sample.signalKeys) {
      incrementCount(counts, signalKey, 1);
    }
  }

  return counts;
}

function buildTransitionGraph(
  samples: ProcessedInterestSample[]
): Map<string, Map<string, number>> {
  const graph = new Map<string, Map<string, number>>();

  for (let index = 0; index < samples.length - 1; index += 1) {
    const source = samples[index];
    const target = samples[index + 1];
    if (!source || !target) {
      continue;
    }
    const transitionWeight = 1 + index / Math.max(samples.length - 1, 1);

    for (const sourceKey of source.signalKeys) {
      let edges = graph.get(sourceKey);
      if (!edges) {
        edges = new Map<string, number>();
        graph.set(sourceKey, edges);
      }

      for (const targetKey of target.signalKeys) {
        if (sourceKey === targetKey) {
          continue;
        }

        incrementCount(edges, targetKey, transitionWeight);
      }
    }
  }

  return graph;
}

function summarizeSignals(
  signalWeights: Map<string, number>,
  signalCounts: Map<string, number>
): InterestSignalSummary[] {
  return [...signalWeights.entries()]
    .sort((left, right) => right[1] - left[1])
    .map(([key, weight]) => ({
      key,
      type: getSignalType(key),
      label: formatSignalLabel(key),
      weight,
      count: signalCounts.get(key) ?? 0
    }));
}

function createProcessedSample(
  input: InterestBookmarkInput
): ProcessedInterestSample | undefined {
  const title = input.title.trim() || input.url.trim();
  const url = input.url.trim();
  if (!url) {
    return undefined;
  }

  const hostname = normalizeHostname(tryParseUrl(url)?.hostname);
  const tokens = tokenizeContent(title, url);
  const hostKey = hostname ? createSignalKey('host', hostname) : undefined;
  const tokenKeys = tokens.map((token) => createSignalKey('token', token));
  const signalKeys = [...new Set([hostKey, ...tokenKeys].filter((entry): entry is string => Boolean(entry)))];
  const sortTime = typeof input.dateAdded === 'number' && Number.isFinite(input.dateAdded)
    ? input.dateAdded
    : Date.now();

  return {
    id: input.id,
    title,
    url,
    hostname,
    addedAt: new Date(sortTime).toISOString(),
    tokens,
    signalKeys,
    hostKey,
    tokenKeys,
    sortTime
  };
}

function tokenizeContent(title: string, rawUrl: string): string[] {
  const tokens = new Set<string>();
  const parsedUrl = tryParseUrl(rawUrl);

  if (parsedUrl) {
    const hostname = normalizeHostname(parsedUrl.hostname);
    if (hostname) {
      for (const segment of hostname.split('.')) {
        addToken(tokens, segment, true);
      }
    }

    for (const segment of parsedUrl.pathname.split(/[\/._-]+/g)) {
      addToken(tokens, segment, false);
    }

    for (const [name] of parsedUrl.searchParams.entries()) {
      addToken(tokens, name, false);
    }
  }

  for (const segment of title.split(/[^a-zA-Z0-9]+/g)) {
    addToken(tokens, segment, false);
  }

  return [...tokens].slice(0, 16);
}

function addToken(target: Set<string>, rawValue: string, fromHost: boolean): void {
  const normalized = rawValue.trim().toLowerCase();
  if (!normalized) {
    return;
  }

  const minimumLength = fromHost ? 2 : 3;
  if (normalized.length < minimumLength) {
    return;
  }

  if (/^\d+$/.test(normalized)) {
    return;
  }

  if (STOPWORDS.has(normalized)) {
    return;
  }

  if (fromHost && GENERIC_HOST_SEGMENTS.has(normalized)) {
    return;
  }

  target.add(normalized);
}

function normalizeInterestAnalysis(rawValue: unknown): InterestAnalysis | undefined {
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return undefined;
  }

  const source = rawValue as Partial<InterestAnalysis>;
  if (typeof source.folderName !== 'string' || typeof source.generatedAt !== 'string') {
    return undefined;
  }

  return {
    generatedAt: source.generatedAt,
    folderId: typeof source.folderId === 'string' ? source.folderId : undefined,
    folderName: source.folderName,
    folderStatus: normalizeFolderStatus(source.folderStatus),
    bookmarkCount:
      typeof source.bookmarkCount === 'number' && Number.isFinite(source.bookmarkCount)
        ? source.bookmarkCount
        : 0,
    topSignals: Array.isArray(source.topSignals)
      ? source.topSignals
          .map((signal) => normalizeInterestSignalSummary(signal))
          .filter((signal): signal is InterestSignalSummary => Boolean(signal))
      : [],
    recentBookmarks: Array.isArray(source.recentBookmarks)
      ? source.recentBookmarks
          .map((bookmark) => normalizeInterestBookmarkSummary(bookmark))
          .filter((bookmark): bookmark is InterestBookmarkSummary => Boolean(bookmark))
      : [],
    warnings: Array.isArray(source.warnings)
      ? source.warnings.filter((entry): entry is string => typeof entry === 'string')
      : [],
    currentTab: normalizeInterestCurrentTabAnalysis(source.currentTab)
  };
}

function normalizeInterestSignalSummary(
  rawValue: unknown
): InterestSignalSummary | undefined {
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return undefined;
  }

  const source = rawValue as Partial<InterestSignalSummary>;
  if (
    typeof source.key !== 'string' ||
    typeof source.label !== 'string' ||
    typeof source.weight !== 'number' ||
    typeof source.count !== 'number'
  ) {
    return undefined;
  }

  return {
    key: source.key,
    type: source.type === 'host' ? 'host' : 'token',
    label: source.label,
    weight: source.weight,
    count: source.count
  };
}

function normalizeInterestBookmarkSummary(
  rawValue: unknown
): InterestBookmarkSummary | undefined {
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return undefined;
  }

  const source = rawValue as Partial<InterestBookmarkSummary>;
  if (
    typeof source.id !== 'string' ||
    typeof source.title !== 'string' ||
    typeof source.url !== 'string' ||
    typeof source.addedAt !== 'string' ||
    !Array.isArray(source.tokens)
  ) {
    return undefined;
  }

  return {
    id: source.id,
    title: source.title,
    url: source.url,
    hostname: typeof source.hostname === 'string' ? source.hostname : undefined,
    addedAt: source.addedAt,
    tokens: source.tokens.filter((entry): entry is string => typeof entry === 'string')
  };
}

function normalizeInterestCurrentTabAnalysis(
  rawValue: unknown
): InterestCurrentTabAnalysis | undefined {
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return undefined;
  }

  const source = rawValue as Partial<InterestCurrentTabAnalysis>;
  if (
    typeof source.title !== 'string' ||
    typeof source.url !== 'string' ||
    !Array.isArray(source.tokens) ||
    !source.rating ||
    typeof source.rating !== 'object' ||
    Array.isArray(source.rating)
  ) {
    return undefined;
  }

  const rating = source.rating as Partial<InterestRating>;
  if (
    typeof rating.overall !== 'number' ||
    typeof rating.hostAffinity !== 'number' ||
    typeof rating.tokenAffinity !== 'number' ||
    typeof rating.coverage !== 'number' ||
    !Array.isArray(rating.matchedSignals)
  ) {
    return undefined;
  }

  return {
    title: source.title,
    url: source.url,
    hostname: typeof source.hostname === 'string' ? source.hostname : undefined,
    tokens: source.tokens.filter((entry): entry is string => typeof entry === 'string'),
    rating: {
      overall: rating.overall,
      hostAffinity: rating.hostAffinity,
      tokenAffinity: rating.tokenAffinity,
      coverage: rating.coverage,
      matchedSignals: rating.matchedSignals.filter(
        (entry): entry is string => typeof entry === 'string'
      )
    },
    predictions: Array.isArray(source.predictions)
      ? source.predictions
          .map((prediction) => normalizeInterestPrediction(prediction))
          .filter((prediction): prediction is InterestPrediction => Boolean(prediction))
      : [],
    futurePaths: Array.isArray(source.futurePaths)
      ? source.futurePaths
          .map((path) => normalizeInterestWalkPath(path))
          .filter((path): path is InterestWalkPath => Boolean(path))
      : []
  };
}

function normalizeInterestPrediction(rawValue: unknown): InterestPrediction | undefined {
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return undefined;
  }

  const source = rawValue as Partial<InterestPrediction>;
  if (
    typeof source.key !== 'string' ||
    typeof source.label !== 'string' ||
    typeof source.probability !== 'number' ||
    typeof source.support !== 'number'
  ) {
    return undefined;
  }

  return {
    key: source.key,
    type: source.type === 'host' ? 'host' : 'token',
    label: source.label,
    probability: source.probability,
    support: source.support
  };
}

function normalizeInterestWalkPath(rawValue: unknown): InterestWalkPath | undefined {
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return undefined;
  }

  const source = rawValue as Partial<InterestWalkPath>;
  if (
    !Array.isArray(source.path) ||
    typeof source.probability !== 'number'
  ) {
    return undefined;
  }

  return {
    path: source.path.filter((entry): entry is string => typeof entry === 'string'),
    probability: source.probability
  };
}

function normalizeFolderStatus(rawValue: unknown): InterestFolderStatus {
  switch (rawValue) {
    case 'ready':
    case 'missing':
    case 'empty':
      return rawValue;
    default:
      return 'missing';
  }
}

function normalizeWholeNumber(
  rawValue: unknown,
  fallback: number,
  minimum: number,
  maximum: number
): number {
  if (typeof rawValue !== 'number' || !Number.isFinite(rawValue)) {
    return fallback;
  }

  return Math.min(maximum, Math.max(minimum, Math.round(rawValue)));
}

function getMaximumWeight(
  signalWeights: Map<string, number>,
  type: InterestSignalType
): number {
  let maximum = 0;
  for (const [key, weight] of signalWeights.entries()) {
    if (getSignalType(key) === type && weight > maximum) {
      maximum = weight;
    }
  }

  return maximum;
}

function createSignalKey(type: InterestSignalType, label: string): string {
  return `${type}:${label}`;
}

function getSignalType(signalKey: string): InterestSignalType {
  return signalKey.startsWith('host:') ? 'host' : 'token';
}

function formatSignalLabel(signalKey: string): string {
  const [type, ...rest] = signalKey.split(':');
  const value = rest.join(':');
  return type === 'host' ? value : value;
}

function normalizeHostname(rawHostname?: string): string | undefined {
  if (!rawHostname) {
    return undefined;
  }

  const normalized = rawHostname.trim().toLowerCase().replace(/\.$/, '');
  if (!normalized) {
    return undefined;
  }

  return normalized.startsWith('www.') ? normalized.slice(4) : normalized;
}

function tryParseUrl(rawValue: string): URL | undefined {
  try {
    return new URL(rawValue);
  } catch {
    return undefined;
  }
}

function incrementCount(target: Map<string, number>, key: string, amount: number): void {
  target.set(key, (target.get(key) ?? 0) + amount);
}

function pickWeightedKey(
  entries: ReadonlyArray<readonly [string, number]>,
  random: () => number
): string | undefined {
  const total = entries.reduce((sum, [, weight]) => sum + Math.max(weight, 0), 0);
  if (total <= 0) {
    return undefined;
  }

  let cursor = random() * total;
  for (const [key, weight] of entries) {
    cursor -= Math.max(weight, 0);
    if (cursor <= 0) {
      return key;
    }
  }

  return entries[entries.length - 1]?.[0];
}

function createSeededRandom(seedValue: string): () => number {
  let seed = 2166136261;
  for (let index = 0; index < seedValue.length; index += 1) {
    seed ^= seedValue.charCodeAt(index);
    seed = Math.imul(seed, 16777619);
  }

  return () => {
    seed += 0x6d2b79f5;
    let value = seed;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function clamp01(value: number): number {
  return Math.min(1, Math.max(0, value));
}
