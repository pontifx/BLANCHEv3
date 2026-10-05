import type { LatentFeatureTextSource } from '../modules/latentFeatures/analyzer';

export interface DetectedDependency {
  packageName: string;
  displayName: string;
  version: string;
  sourceUrl?: string;
  evidence: string;
}

export interface DependencyAssessment extends DetectedDependency {
  latestVersion?: string;
  latestPublishedAt?: string;
  vulnerabilityIds: string[];
  advisoryUrls: string[];
  status: 'current' | 'outdated' | 'vulnerable' | 'unknown';
  note?: string;
}

const CACHE_KEY = 'blanche.dependencyIntelligence.v1';
const CACHE_AGE_MS = 24 * 60 * 60 * 1000;

const LIBRARIES = [
  { packageName: 'jquery', displayName: 'jQuery', pattern: /(?:jquery(?:-|\.|@)|jQuery v)(\d+\.\d+(?:\.\d+)?)/i },
  { packageName: 'bootstrap', displayName: 'Bootstrap', pattern: /(?:bootstrap(?:-|\.|@)|Bootstrap v?)(\d+\.\d+(?:\.\d+)?)/i },
  { packageName: 'lodash', displayName: 'Lodash', pattern: /(?:lodash(?:-|\.|@)|lodash v)(\d+\.\d+(?:\.\d+)?)/i },
  { packageName: 'react', displayName: 'React', pattern: /(?:react(?:-|\.|@)|React v)(\d+\.\d+(?:\.\d+)?)/i },
  { packageName: 'vue', displayName: 'Vue', pattern: /(?:vue(?:-|\.|@)|Vue\.js v)(\d+\.\d+(?:\.\d+)?)/i },
  { packageName: 'angular', displayName: 'AngularJS', pattern: /(?:angular(?:-|\.|@)|AngularJS v)(\d+\.\d+(?:\.\d+)?)/i }
];

export function detectDependencies(sources: LatentFeatureTextSource[]): DetectedDependency[] {
  const found = new Map<string, DetectedDependency>();
  for (const source of sources) {
    const sample = `${source.sourceUrl ?? ''}\n${source.label}\n${source.text.slice(0, 5000)}`;
    for (const library of LIBRARIES) {
      const match = library.pattern.exec(sample);
      const version = match?.[1];
      if (!version) continue;
      const key = `${library.packageName}@${version}`;
      if (!found.has(key)) {
        found.set(key, {
          packageName: library.packageName,
          displayName: library.displayName,
          version,
          sourceUrl: source.sourceUrl,
          evidence: match[0].slice(0, 160)
        });
      }
    }
  }
  return [...found.values()].slice(0, 20);
}

export async function assessDependencies(
  dependencies: DetectedDependency[],
  options: { concurrency: number; delayMs: number }
): Promise<DependencyAssessment[]> {
  const cache = await loadCache();
  const output: DependencyAssessment[] = [];
  let cursor = 0;
  let nextStartAt = 0;
  const worker = async () => {
    while (cursor < dependencies.length) {
      const dependency = dependencies[cursor++];
      if (!dependency) return;
      const key = `${dependency.packageName}@${dependency.version}`;
      const cached = cache[key];
      if (cached && Date.now() - cached.checkedAt < CACHE_AGE_MS) {
        output.push({ ...dependency, ...cached.assessment });
        continue;
      }
      const scheduledAt = Math.max(Date.now(), nextStartAt);
      nextStartAt = scheduledAt + Math.max(100, options.delayMs);
      await wait(Math.max(0, scheduledAt - Date.now()));
      const assessment = await assessDependency(dependency);
      output.push(assessment);
      cache[key] = { checkedAt: Date.now(), assessment: stripDependency(assessment) };
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(4, options.concurrency)) }, worker));
  await chrome.storage.local.set({ [CACHE_KEY]: cache });
  return output.sort((left, right) => severityRank(right.status) - severityRank(left.status));
}

async function assessDependency(dependency: DetectedDependency): Promise<DependencyAssessment> {
  try {
    const [registry, osv] = await Promise.all([
      fetchJson(`https://registry.npmjs.org/${encodeURIComponent(dependency.packageName)}`, { method: 'GET' }),
      fetchJson('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ package: { ecosystem: 'npm', name: dependency.packageName }, version: dependency.version })
      })
    ]);
    const latestVersion = getNestedString(registry, ['dist-tags', 'latest']);
    const latestPublishedAt = latestVersion
      ? getNestedString(registry, ['time', latestVersion])
      : undefined;
    const vulnerabilities = getArray(osv, 'vulns');
    const vulnerabilityIds = vulnerabilities.map((entry) => getString(entry, 'id')).filter((entry): entry is string => Boolean(entry));
    const advisoryUrls = vulnerabilities.flatMap((entry) => getArray(entry, 'references').map((reference) => getString(reference, 'url')).filter((url): url is string => Boolean(url))).slice(0, 12);
    return {
      ...dependency,
      latestVersion,
      latestPublishedAt,
      vulnerabilityIds,
      advisoryUrls,
      status: vulnerabilityIds.length > 0
        ? 'vulnerable'
        : latestVersion && compareVersions(dependency.version, latestVersion) < 0
          ? 'outdated'
          : latestVersion
            ? 'current'
            : 'unknown'
    };
  } catch (error) {
    return { ...dependency, vulnerabilityIds: [], advisoryUrls: [], status: 'unknown', note: error instanceof Error ? error.message : String(error) };
  }
}

async function fetchJson(url: string, init: RequestInit): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(url, { ...init, signal: controller.signal, cache: 'force-cache' });
    if (!response.ok) throw new Error(`${new URL(url).hostname} returned HTTP ${response.status}`);
    return response.json();
  } finally {
    clearTimeout(timer);
  }
}

async function loadCache(): Promise<Record<string, { checkedAt: number; assessment: Omit<DependencyAssessment, keyof DetectedDependency> }>> {
  const raw = (await chrome.storage.local.get(CACHE_KEY))[CACHE_KEY];
  return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw as Record<string, { checkedAt: number; assessment: Omit<DependencyAssessment, keyof DetectedDependency> }> : {};
}

function stripDependency(value: DependencyAssessment): Omit<DependencyAssessment, keyof DetectedDependency> {
  return { latestVersion: value.latestVersion, latestPublishedAt: value.latestPublishedAt, vulnerabilityIds: value.vulnerabilityIds, advisoryUrls: value.advisoryUrls, status: value.status, note: value.note };
}

function getString(value: unknown, key: string): string | undefined {
  return value && typeof value === 'object' && typeof (value as Record<string, unknown>)[key] === 'string' ? (value as Record<string, string>)[key] : undefined;
}

function getNestedString(value: unknown, path: string[]): string | undefined {
  let current: unknown = value;
  for (const segment of path) {
    if (!current || typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return typeof current === 'string' ? current : undefined;
}

function compareVersions(left: string, right: string): number {
  const parse = (value: string) => value.split(/[.+-]/).slice(0, 3).map((part) => Number(part) || 0);
  const leftParts = parse(left);
  const rightParts = parse(right);
  for (let index = 0; index < 3; index += 1) {
    const delta = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
    if (delta !== 0) return delta;
  }
  return 0;
}

function getArray(value: unknown, key: string): unknown[] {
  if (!value || typeof value !== 'object') return [];
  const candidate = (value as Record<string, unknown>)[key];
  return Array.isArray(candidate) ? candidate : [];
}

function severityRank(status: DependencyAssessment['status']): number {
  return status === 'vulnerable' ? 4 : status === 'outdated' ? 3 : status === 'unknown' ? 2 : 1;
}

function wait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
