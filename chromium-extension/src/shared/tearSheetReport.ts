import {
  BLANCHE_TEAR_SHEET_KIND,
  BLANCHE_TEAR_SHEET_SCHEMA_VERSION,
  type ArtifactCategory,
  type ArtifactDescriptor,
  type BlancheTearSheetV1,
  type ConfidenceLevel,
  type JsonObject,
  type ProvenanceDisposition,
  type TearSheetArtifactCategorySummary,
  type TearSheetArtifactExample,
  type TearSheetAssessment,
  type TearSheetCorrelatedEvidence,
  type TearSheetLimitation,
  type TearSheetMetric,
  type TearSheetObservation,
  type TearSheetOriginSummary
} from '../../../shared-schema/src';
import type { HostStateSnapshot } from './contracts';
import { javascriptTestMatchesScan } from './latentFeatureWorkbench';

const BROWSER_ONLY_CATEGORIES = new Set<ArtifactCategory>([
  'blob',
  'data-url',
  'storage-key',
  'indexeddb-database',
  'cache',
  'service-worker',
  'runtime-indicator'
]);

const CATEGORY_LABELS: Record<ArtifactCategory, string> = {
  document: 'Documents',
  frame: 'Frames',
  resource: 'Resources',
  script: 'Scripts',
  stylesheet: 'Stylesheets',
  image: 'Images',
  font: 'Fonts',
  manifest: 'Manifests',
  iframe: 'Iframes',
  worker: 'Workers',
  'service-worker': 'Service workers',
  blob: 'Blob URLs',
  'data-url': 'Data URLs',
  'storage-key': 'Browser storage keys',
  'indexeddb-database': 'IndexedDB databases',
  cache: 'Cache Storage',
  'runtime-indicator': 'Runtime indicators',
  unknown: 'Other artifacts'
};

export function buildTearSheetReport(
  snapshot: HostStateSnapshot,
  generatedAt = new Date().toISOString()
): BlancheTearSheetV1 | undefined {
  const sourceCapture = snapshot.lastExport;
  if (!sourceCapture) {
    return undefined;
  }

  const targetOrigin = sourceCapture.page.origin ?? tryGetOrigin(sourceCapture.page.url);
  const targetHostname = tryGetHostname(sourceCapture.page.url ?? targetOrigin);
  const correlatedEvidence = collectCorrelatedEvidence(snapshot, targetHostname);
  const categorySummaries = buildCategorySummaries(sourceCapture.artifacts);
  const originSummaries = buildOriginSummaries(sourceCapture.artifacts, targetOrigin);
  const provenance = countProvenance(sourceCapture.artifacts);
  const browserOnlyArtifacts = sourceCapture.artifacts.filter(isBrowserOnlyArtifact);
  const crossOriginArtifacts = targetOrigin
    ? sourceCapture.artifacts.filter((artifact) => {
        const origin = artifact.origin ?? tryGetOrigin(artifact.url);
        return Boolean(origin && origin !== targetOrigin);
      })
    : [];
  const assessment = determineAssessment(sourceCapture);
  const confidence = determineConfidence(sourceCapture.artifacts, assessment);
  const relatedCounts = countCorrelatedEvidence(correlatedEvidence);
  const evidenceAsOf = findLatestEvidenceTimestamp(
    sourceCapture.exportMetadata.exportedAt,
    correlatedEvidence
  );
  const reportRevision = hashString(JSON.stringify(correlatedEvidence));
  const metrics = buildMetrics({
    artifactCount: sourceCapture.summary.artifactCount,
    browserOnlyCount: browserOnlyArtifacts.length,
    frameCount: sourceCapture.page.frames.length,
    originCount: originSummaries.length,
    findingCount: relatedCounts.findings,
    searchResultCount: relatedCounts.searchResults,
    documentCount: relatedCounts.documents,
    trafficEndpointCount: sourceCapture.trafficLedger?.summary.entryCount ?? 0,
    highPriorityInScopeTrafficCount: (sourceCapture.trafficLedger?.entries ?? []).filter(
      (entry) => entry.scope.disposition === 'in-scope' && entry.priority.score >= 50
    ).length,
    coverageGapCount: sourceCapture.summary.visibilityGapCount
  });

  return {
    kind: BLANCHE_TEAR_SHEET_KIND,
    schemaVersion: BLANCHE_TEAR_SHEET_SCHEMA_VERSION,
    metadata: {
      reportId: `tear-sheet_${sourceCapture.exportMetadata.exportId}_${reportRevision}`,
      generatedAt,
      evidenceAsOf,
      sourceExportId: sourceCapture.exportMetadata.exportId,
      generatedBy: {
        product: 'BLANCHE',
        component: 'chromium-extension/site-report',
        version: sourceCapture.exportMetadata.generatedBy.version
      }
    },
    target: {
      url: sourceCapture.page.url,
      title: sourceCapture.page.title,
      origin: targetOrigin,
      hostname: targetHostname
    },
    executiveSummary: {
      headline: `BLANCHE observed ${sourceCapture.summary.artifactCount} browser-visible artifact${
        sourceCapture.summary.artifactCount === 1 ? '' : 's'
      }${targetHostname ? ` for ${targetHostname}` : ''}.`,
      overview: buildOverview({
        categoryCount: categorySummaries.length,
        originCount: originSummaries.length,
        mode: sourceCapture.collection.mode,
        assessment,
        relatedCounts
      }),
      assessment,
      confidence,
      metrics
    },
    captureProfile: {
      mode: sourceCapture.collection.mode,
      reloadTriggered: sourceCapture.collection.reloadTriggered,
      startedAt: sourceCapture.collection.startedAt,
      finishedAt: sourceCapture.collection.finishedAt,
      durationMs: calculateDurationMs(
        sourceCapture.collection.startedAt,
        sourceCapture.collection.finishedAt
      ),
      frameCount: sourceCapture.page.frames.length,
      collectors: sourceCapture.collectors.map((collector) => ({
        collectorId: collector.collectorId,
        name: collector.name,
        surface: collector.surface,
        status: collector.status,
        collectedAt: collector.collectedAt,
        warningCount: collector.warnings.length,
        errorCount: collector.errors.length,
        visibilityGapCount: collector.visibilityGaps.length
      })),
      permissions: sourceCapture.permissions
    },
    evidenceSummary: {
      artifactCount: sourceCapture.summary.artifactCount,
      browserOnlyArtifactCount: browserOnlyArtifacts.length,
      crossOriginArtifactCount: crossOriginArtifacts.length,
      uniqueOriginCount: originSummaries.length,
      provenance,
      categories: categorySummaries,
      origins: originSummaries
    },
    observations: buildObservations({
      artifacts: sourceCapture.artifacts,
      browserOnlyArtifacts,
      crossOriginArtifacts,
      correlatedEvidence,
      targetOrigin
    }),
    limitations: buildLimitations(sourceCapture, correlatedEvidence),
    correlatedEvidence,
    dataHandling: {
      classification: 'assessment-sensitive',
      stakeholderViewRedactsRawValues: true,
      jsonContainsFullEvidence: true,
      notice:
        'The stakeholder HTML omits raw collector payloads and storage values. The JSON evidence mode preserves the full source capture and may contain tokens, identifiers, browser storage values, URLs, and other sensitive assessment data.'
    },
    sourceCapture
  };
}

export function buildTearSheetFileStem(report: BlancheTearSheetV1): string {
  const hostname = sanitizeFilenamePart(report.target.hostname ?? 'unknown-site');
  const timestamp = report.metadata.generatedAt
    .replace(/[:.]/g, '-')
    .replace('T', '_')
    .replace(/Z$/i, 'Z');
  return `blanche_${hostname}_${timestamp}_tear-sheet`;
}

export function getArtifactCategoryLabel(category: ArtifactCategory): string {
  return CATEGORY_LABELS[category];
}

function collectCorrelatedEvidence(
  snapshot: HostStateSnapshot,
  targetHostname?: string
): TearSheetCorrelatedEvidence {
  if (!targetHostname) {
    return {
      findings: [],
      testerQuestions: [],
      searchSessions: [],
      documents: [],
      activity: []
    };
  }

  const findings = snapshot.findingsWorkbench.findings.filter(
    (finding) =>
      hostnameMatches(finding.host, targetHostname) ||
      finding.evidence.some((entry) => hostnameMatches(tryGetHostname(entry.url), targetHostname))
  );
  const findingIds = new Set(findings.map((finding) => finding.id));
  const testerQuestions = snapshot.findingsWorkbench.questions.filter((question) =>
    findingIds.has(question.findingId)
  );
  const searchSessions = snapshot.searchExecution.sessions.filter(
    (session) =>
      searchRecordMatchesHostname(session, targetHostname) ||
      session.tasks.some((task) => searchRecordMatchesHostname(task, targetHostname))
  );
  const documents = snapshot.documentWorkbench.documents.filter((document) =>
    [
      document.targetHost,
      tryGetHostname(document.url),
      tryGetHostname(document.finalUrl),
      tryGetHostname(document.sourcePageUrl)
    ].some((hostname) => hostnameMatches(hostname, targetHostname))
  );
  const latentFeatureScan = snapshot.latentFeatureWorkbench.lastScan;
  const matchingLatentFeatureScan =
    latentFeatureScan &&
    hostnameMatches(tryGetHostname(latentFeatureScan.pageUrl ?? latentFeatureScan.origin), targetHostname)
      ? latentFeatureScan
      : undefined;
  const javascriptTest = snapshot.latentFeatureWorkbench.lastJavascriptTest;
  const matchingJavascriptTest =
    javascriptTest &&
    hostnameMatches(tryGetHostname(javascriptTest.pageUrl), targetHostname) &&
    javascriptTestMatchesScan(javascriptTest, matchingLatentFeatureScan)
      ? javascriptTest
      : undefined;
  const interestAnalysis = snapshot.interestWorkbench.lastAnalysis;
  const matchingInterestAnalysis =
    interestAnalysis?.currentTab &&
    hostnameMatches(
      interestAnalysis.currentTab.hostname ?? tryGetHostname(interestAnalysis.currentTab.url),
      targetHostname
    )
      ? interestAnalysis
      : undefined;
  const activity = snapshot.feed.filter(
    (entry) =>
      hostnameMatches(entry.host, targetHostname) ||
      hostnameMatches(
        typeof entry.context?.url === 'string' ? tryGetHostname(entry.context.url) : undefined,
        targetHostname
      )
  );

  return {
    findings: findings.map(toJsonObject),
    testerQuestions: testerQuestions.map(toJsonObject),
    searchSessions: searchSessions.map(toJsonObject),
    documents: documents.map(toJsonObject),
    latentFeatureScan: matchingLatentFeatureScan
      ? toJsonObject(matchingLatentFeatureScan)
      : undefined,
    javascriptTest: matchingJavascriptTest ? toJsonObject(matchingJavascriptTest) : undefined,
    interestAnalysis: matchingInterestAnalysis ? toJsonObject(matchingInterestAnalysis) : undefined,
    activity: activity.map(toJsonObject)
  };
}

function buildCategorySummaries(
  artifacts: ArtifactDescriptor[]
): TearSheetArtifactCategorySummary[] {
  const byCategory = new Map<ArtifactCategory, ArtifactDescriptor[]>();
  for (const artifact of artifacts) {
    const current = byCategory.get(artifact.category) ?? [];
    current.push(artifact);
    byCategory.set(artifact.category, current);
  }

  return [...byCategory.entries()]
    .map(([category, entries]) => ({
      category,
      label: CATEGORY_LABELS[category],
      count: entries.length,
      provenance: countProvenance(entries),
      examples: entries.slice(0, 5).map<TearSheetArtifactExample>((artifact) => ({
        artifactId: artifact.artifactId,
        kind: artifact.kind,
        url: artifact.url,
        origin: artifact.origin,
        frameId: artifact.frameId,
        disposition: artifact.provenance.disposition,
        confidence: artifact.provenance.confidence,
        discoveredBy: artifact.discoveredBy
      }))
    }))
    .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label));
}

function buildOriginSummaries(
  artifacts: ArtifactDescriptor[],
  targetOrigin?: string
): TearSheetOriginSummary[] {
  const byOrigin = new Map<string, { count: number; categories: Set<ArtifactCategory> }>();
  for (const artifact of artifacts) {
    const origin = artifact.origin ?? tryGetOrigin(artifact.url);
    if (!origin || origin === 'null') {
      continue;
    }
    const summary = byOrigin.get(origin) ?? { count: 0, categories: new Set<ArtifactCategory>() };
    summary.count += 1;
    summary.categories.add(artifact.category);
    byOrigin.set(origin, summary);
  }

  return [...byOrigin.entries()]
    .map(([origin, summary]) => ({
      origin,
      count: summary.count,
      crossOrigin: Boolean(targetOrigin && origin !== targetOrigin),
      categories: [...summary.categories].sort()
    }))
    .sort((left, right) => right.count - left.count || left.origin.localeCompare(right.origin));
}

function buildMetrics(input: {
  artifactCount: number;
  browserOnlyCount: number;
  frameCount: number;
  originCount: number;
  findingCount: number;
  searchResultCount: number;
  documentCount: number;
  trafficEndpointCount: number;
  highPriorityInScopeTrafficCount: number;
  coverageGapCount: number;
}): TearSheetMetric[] {
  return [
    {
      id: 'artifacts',
      label: 'Artifacts',
      value: input.artifactCount,
      detail: 'Normalized browser-visible evidence records.'
    },
    {
      id: 'browser-only',
      label: 'Browser-only',
      value: input.browserOnlyCount,
      detail: 'State and runtime evidence that a traditional HTTP archive generally misses.'
    },
    {
      id: 'frames',
      label: 'Frames',
      value: input.frameCount,
      detail: 'Top-level and child frames known to Chromium.'
    },
    {
      id: 'origins',
      label: 'Origins',
      value: input.originCount,
      detail: 'Distinct artifact origins visible in the capture.'
    },
    {
      id: 'findings',
      label: 'Testing leads',
      value: input.findingCount,
      detail: 'Host-correlated findings; these are not validated vulnerabilities.'
    },
    {
      id: 'search-results',
      label: 'Search results',
      value: input.searchResultCount,
      detail: 'Results from tracked searches associated with this target.'
    },
    {
      id: 'documents',
      label: 'Documents',
      value: input.documentCount,
      detail: 'Document queue records associated with this target.'
    },
    {
      id: 'traffic-endpoints',
      label: 'Traffic endpoints',
      value: input.trafficEndpointCount,
      detail: 'Sanitized, method-aware endpoint shapes observed by Chromium.'
    },
    {
      id: 'priority-traffic',
      label: 'Priority traffic',
      value: input.highPriorityInScopeTrafficCount,
      detail: 'In-scope endpoints scoring high or urgent for triage; not vulnerability severity.'
    },
    {
      id: 'coverage-gaps',
      label: 'Coverage gaps',
      value: input.coverageGapCount,
      detail: 'Explicit surfaces BLANCHE could not fully observe.'
    }
  ];
}

function buildOverview(input: {
  categoryCount: number;
  originCount: number;
  mode: 'passive' | 'instrumented';
  assessment: TearSheetAssessment;
  relatedCounts: ReturnType<typeof countCorrelatedEvidence>;
}): string {
  const contextCount =
    input.relatedCounts.findings +
    input.relatedCounts.searchTasks +
    input.relatedCounts.documents +
    input.relatedCounts.latentFeatures;
  return `The ${input.mode} browser capture mapped ${input.categoryCount} evidence categor${
    input.categoryCount === 1 ? 'y' : 'ies'
  } across ${input.originCount} origin${input.originCount === 1 ? '' : 's'}. Collection health is ${
    input.assessment
  }. BLANCHE also correlated ${contextCount} testing-context record${contextCount === 1 ? '' : 's'} to the target. Observations are informational and require tester validation before reporting as vulnerabilities.`;
}

function buildObservations(input: {
  artifacts: ArtifactDescriptor[];
  browserOnlyArtifacts: ArtifactDescriptor[];
  crossOriginArtifacts: ArtifactDescriptor[];
  correlatedEvidence: TearSheetCorrelatedEvidence;
  targetOrigin?: string;
}): TearSheetObservation[] {
  const observations: TearSheetObservation[] = [];
  const pushArtifactObservation = (
    id: string,
    title: string,
    summary: string,
    whyItMatters: string,
    artifacts: ArtifactDescriptor[],
    tone: TearSheetObservation['tone'] = 'neutral'
  ) => {
    if (artifacts.length === 0) {
      return;
    }
    observations.push({
      id,
      title,
      summary,
      whyItMatters,
      tone,
      evidenceReferences: artifacts.map((artifact) => ({
        source: 'artifact',
        id: artifact.artifactId
      }))
    });
  };

  pushArtifactObservation(
    'browser-only-surface',
    'Browser-only state was present',
    `${input.browserOnlyArtifacts.length} artifact${
      input.browserOnlyArtifacts.length === 1 ? '' : 's'
    } came from storage, runtime, worker, cache, blob, or data-URL surfaces.`,
    'These surfaces explain behavior that cannot be reconstructed from ordinary proxy traffic alone.',
    input.browserOnlyArtifacts
  );
  pushArtifactObservation(
    'cross-origin-surface',
    'Cross-origin dependencies were visible',
    `${input.crossOriginArtifacts.length} artifact${
      input.crossOriginArtifacts.length === 1 ? '' : 's'
    } resolved outside ${input.targetOrigin ?? 'the page origin'}.`,
    'External origins can identify trust relationships, hosted assets, and follow-on testing boundaries; ownership is not inferred here.',
    input.crossOriginArtifacts,
    'attention'
  );

  const clientExecutionArtifacts = input.artifacts.filter((artifact) =>
    ['script', 'worker', 'service-worker', 'runtime-indicator'].includes(artifact.category)
  );
  pushArtifactObservation(
    'client-execution-surface',
    'Client execution surface was mapped',
    `${clientExecutionArtifacts.length} script, worker, service-worker, or runtime artifact${
      clientExecutionArtifacts.length === 1 ? '' : 's'
    } were recorded.`,
    'This inventory helps testers explain what executes in the browser and where client-side behavior originates.',
    clientExecutionArtifacts
  );

  const persistentStateArtifacts = input.artifacts.filter((artifact) =>
    ['storage-key', 'indexeddb-database', 'cache'].includes(artifact.category)
  );
  pushArtifactObservation(
    'persistent-state-surface',
    'Persistent browser state was observed',
    `${persistentStateArtifacts.length} storage, IndexedDB, or Cache Storage artifact${
      persistentStateArtifacts.length === 1 ? '' : 's'
    } were recorded.`,
    'Persisted state can explain feature controls, session behavior, offline content, and browser-only application context.',
    persistentStateArtifacts,
    'attention'
  );

  const dynamicArtifacts = input.artifacts.filter((artifact) =>
    ['blob', 'data-url'].includes(artifact.category)
  );
  pushArtifactObservation(
    'dynamic-content-surface',
    'Dynamic content URLs were present',
    `${dynamicArtifacts.length} blob or data URL artifact${dynamicArtifacts.length === 1 ? '' : 's'} were recorded.`,
    'Dynamic URLs may represent content assembled inside the page rather than fetched as a normal network response.',
    dynamicArtifacts
  );

  const findings = input.correlatedEvidence.findings;
  if (findings.length > 0) {
    observations.push({
      id: 'correlated-testing-leads',
      title: 'BLANCHE correlated tester-facing leads',
      summary: `${findings.length} finding${findings.length === 1 ? '' : 's'} in the tester workbench matched this target.`,
      whyItMatters:
        'These records provide prioritized follow-up context. They remain informational until a tester validates and dispositions them.',
      tone: 'attention',
      evidenceReferences: findings
        .map((finding) => (typeof finding.id === 'string' ? finding.id : undefined))
        .filter((id): id is string => Boolean(id))
        .map((id) => ({ source: 'finding' as const, id }))
    });
  }

  const searchReferences = collectNestedRecordIds(input.correlatedEvidence.searchSessions, 'tasks');
  const searchTaskCount = countSearchTasks(input.correlatedEvidence.searchSessions);
  const searchResultCount = countSearchResults(input.correlatedEvidence.searchSessions);
  const manualSearchCount = countSearchTasksWithStatus(
    input.correlatedEvidence.searchSessions,
    'manual-required'
  );
  const failedSearchCount = countSearchTasksWithStatus(
    input.correlatedEvidence.searchSessions,
    'failed'
  );
  if (searchTaskCount > 0) {
    const outcomeNotes = [
      `${searchResultCount} rendered result${searchResultCount === 1 ? '' : 's'}`,
      ...(manualSearchCount > 0
        ? [`${manualSearchCount} manual-required task${manualSearchCount === 1 ? '' : 's'}`]
        : []),
      ...(failedSearchCount > 0
        ? [`${failedSearchCount} failed task${failedSearchCount === 1 ? '' : 's'}`]
        : [])
    ];
    observations.push({
      id:
        searchResultCount > 0
          ? 'correlated-search-results'
          : 'correlated-search-execution',
      title:
        searchResultCount > 0
          ? 'Tracked searches returned target context'
          : 'Tracked search execution was retained',
      summary: `${searchTaskCount} target-associated search task${
        searchTaskCount === 1 ? '' : 's'
      } were retained with ${joinNaturalLanguage(outcomeNotes)}.`,
      whyItMatters:
        'Exact dork queries, zero-result outcomes, and manual-required states provide a reviewable record even when a search does not return a result.',
      tone: manualSearchCount > 0 || failedSearchCount > 0 ? 'attention' : 'neutral',
      evidenceReferences: searchReferences.map((id) => ({ source: 'search', id }))
    });
  }

  const documents = input.correlatedEvidence.documents;
  if (documents.length > 0) {
    observations.push({
      id: 'correlated-documents',
      title: 'Document evidence was associated with the target',
      summary: `${documents.length} document queue record${documents.length === 1 ? '' : 's'} matched the site or a target-related source page.`,
      whyItMatters:
        'Document hashes, keyword hits, extracted URLs, and review decisions provide auditable context without implying a vulnerability.',
      tone: 'attention',
      evidenceReferences: documents
        .map((document) => (typeof document.id === 'string' ? document.id : undefined))
        .filter((id): id is string => Boolean(id))
        .map((id) => ({ source: 'document' as const, id }))
    });
  }

  const scriptAssessments = getJsonObjectArray(
    input.correlatedEvidence.latentFeatureScan?.scriptAssessments
  );
  if (scriptAssessments.length > 0) {
    const scored = scriptAssessments
      .map((assessment) => ({
        assessment,
        priority: isJsonObject(assessment.reviewPriority)
          ? Number(assessment.reviewPriority.score ?? 0)
          : 0
      }))
      .sort((left, right) => right.priority - left.priority);
    const top = scored[0];
    const opaqueCount = scriptAssessments.filter((assessment) => {
      const transform = isJsonObject(assessment.transform) ? assessment.transform : undefined;
      const detected = Array.isArray(transform?.detected) ? transform.detected : [];
      return detected.includes('packed') || detected.includes('obfuscated');
    }).length;
    observations.push({
      id: 'correlated-javascript-purpose',
      title: 'Delivered JavaScript purpose was assessed',
      summary: `${scriptAssessments.length} retained script source${scriptAssessments.length === 1 ? '' : 's'} were assessed; ${opaqueCount} were packed or obfuscated. Highest review priority was ${top?.priority ?? 0}/100.`,
      whyItMatters:
        'Purpose, transform complexity, and behavior maturity help prioritize review. The priority score is not vulnerability severity.',
      tone: (top?.priority ?? 0) >= 50 ? 'attention' : 'neutral',
      evidenceReferences: scriptAssessments
        .map((assessment) => {
          const artifact = isJsonObject(assessment.artifact) ? assessment.artifact : undefined;
          return typeof artifact?.artifactId === 'string' ? artifact.artifactId : undefined;
        })
        .filter((id): id is string => Boolean(id))
        .map((id) => ({ source: 'javascript' as const, id }))
    });
  }

  const javascriptTest = input.correlatedEvidence.javascriptTest;
  if (javascriptTest) {
    const testRunId =
      typeof javascriptTest.testRunId === 'string'
        ? javascriptTest.testRunId
        : 'javascript-test';
    const overallStatus =
      typeof javascriptTest.overallStatus === 'string'
        ? javascriptTest.overallStatus
        : 'unknown';
    const cells = getJsonObjectArray(javascriptTest.cells);
    const observedCount = cells.filter((cell) => cell.status === 'observed').length;
    const unverifiedObservedCount = cells.filter(
      (cell) => cell.status === 'observed-unverified'
    ).length;
    const unresolvedCount = cells.filter(
      (cell) =>
        cell.status === 'blocked' ||
        cell.status === 'manual-required' ||
        cell.status === 'failed'
    ).length;
    observations.push({
      id: 'correlated-javascript-startup-observation',
      title: 'Instrumented JavaScript startup observation was retained',
      summary: `The bounded one-reload observation was ${overallStatus}: ${observedCount} extension-verified cell${observedCount === 1 ? '' : 's'}, ${unverifiedObservedCount} page-world-unverified cell${unverifiedObservedCount === 1 ? '' : 's'}, and ${unresolvedCount} blocked, failed, or manual cell${unresolvedCount === 1 ? '' : 's'}.`,
      whyItMatters:
        'The matrix distinguishes observed startup behavior from static evidence and explicit coverage gaps; it does not claim exhaustive path execution.',
      tone: overallStatus === 'complete' ? 'neutral' : 'attention',
      evidenceReferences: [{ source: 'javascript', id: testRunId }]
    });
  }

  const latentCandidates = getJsonObjectArray(input.correlatedEvidence.latentFeatureScan?.candidates);
  if (latentCandidates.length > 0) {
    observations.push({
      id: 'correlated-latent-features',
      title: 'Shipped client-feature candidates were correlated',
      summary: `${latentCandidates.length} latent feature candidate${latentCandidates.length === 1 ? '' : 's'} matched the current site scan.`,
      whyItMatters:
        'These candidates describe delivered client controls and evidence sources; they do not prove authorization, entitlement, or server-side availability.',
      tone: 'attention',
      evidenceReferences: latentCandidates
        .map((candidate) => (typeof candidate.id === 'string' ? candidate.id : undefined))
        .filter((id): id is string => Boolean(id))
        .map((id) => ({ source: 'latent-feature' as const, id }))
    });
  }

  if (observations.length === 0) {
    observations.push({
      id: 'baseline-capture',
      title: 'A baseline browser snapshot was retained',
      summary: 'No higher-level observation met the report thresholds for this capture.',
      whyItMatters:
        'The raw evidence still provides a time-bounded record of what the browser exposed during collection.',
      tone: 'neutral',
      evidenceReferences: []
    });
  }

  return observations;
}

function buildLimitations(
  sourceCapture: HostStateSnapshot['lastExport'],
  correlatedEvidence: TearSheetCorrelatedEvidence
): TearSheetLimitation[] {
  if (!sourceCapture) {
    return [];
  }

  const limitations: TearSheetLimitation[] = [
    {
      code: 'NOT_FULL_HTTP_ARCHIVE',
      title: 'This is not a complete HTTP transaction archive',
      detail:
        'The browser capture includes resource timing and browser-only state, but not complete request and response headers, bodies, cookies, status history, redirect chains, or a full network waterfall. Use Burp HTTP history for transaction-level evidence.',
      source: 'methodology'
    },
    {
      code: 'BOUNDED_COLLECTION',
      title: 'Collection is intentionally bounded',
      detail:
        'Resource, cache, storage-value, and instrumentation buffers have configured caps. The source capture is lossless relative to what BLANCHE retained, not necessarily every event the page produced.',
      source: 'methodology'
    },
    {
      code: 'INFORMATIONAL_ONLY',
      title: 'Observations are not validated vulnerabilities',
      detail:
        'This report explains browser evidence and testing leads. A tester must validate impact, scope, authorization, and reportability.',
      source: 'methodology'
    },
    {
      code: 'HOST_CORRELATED_CONTEXT',
      title: 'Workbench context is host-correlated, not capture-session evidence',
      detail:
        'Findings, searches, documents, latent-feature scans, interest analysis, and activity are included only when their recorded hostname exactly matches the captured site. Their original timestamps are preserved, but they may come from a different task or visit and must be reviewed before attribution to this capture.',
      source: 'methodology'
    }
  ];

  const scriptAssessments = getJsonObjectArray(
    correlatedEvidence.latentFeatureScan?.scriptAssessments
  );
  if (scriptAssessments.length > 0) {
    limitations.push({
      code: 'JAVASCRIPT_PURPOSE_HEURISTIC',
      title: 'JavaScript purpose is evidence-backed triage',
      detail:
        'Static transform, purpose, behavior, and review-priority results come from bounded retained source and runtime evidence. Packing, truncation, unresolved chunks, source maps, and environment-dependent paths can limit conclusions. Review priority is not vulnerability severity.',
      source: 'methodology'
    });
  }
  if (correlatedEvidence.javascriptTest) {
    limitations.push({
      code: 'JAVASCRIPT_STARTUP_PATH_ONLY',
      title: 'JavaScript startup observation covers one path',
      detail:
        'The action reloads the explicitly in-scope current tab once and observes bounded startup behavior. Same-window page instrumentation is explicitly unverified because the inspected page can fabricate or suppress that channel; independently recorded Traffic ledger evidence remains distinguishable. The action does not click controls, submit forms, replay transactions, or prove that unobserved paths are absent.',
      source: 'methodology'
    });
  }

  for (const warning of sourceCapture.warnings) {
    limitations.push({
      code: warning.code,
      title: 'Collector warning',
      detail: warning.message,
      source: 'warning'
    });
  }
  for (const error of sourceCapture.errors) {
    limitations.push({
      code: error.code,
      title: error.recoverable ? 'Recoverable collection error' : 'Collection error',
      detail: error.message,
      source: 'error'
    });
  }
  for (const gap of sourceCapture.visibilityGaps) {
    limitations.push({
      code: gap.code,
      title: `Visibility gap: ${gap.reason}`,
      detail: gap.message,
      source: 'visibility-gap'
    });
  }

  return dedupeLimitations(limitations);
}

function determineAssessment(sourceCapture: NonNullable<HostStateSnapshot['lastExport']>): TearSheetAssessment {
  if (
    sourceCapture.summary.errorCount > 0 ||
    sourceCapture.collectors.some((collector) => collector.status === 'error')
  ) {
    return 'degraded';
  }
  if (
    sourceCapture.collection.mode === 'passive' ||
    sourceCapture.summary.warningCount > 0 ||
    sourceCapture.summary.visibilityGapCount > 0 ||
    sourceCapture.collectors.some((collector) => collector.status === 'partial')
  ) {
    return 'limited';
  }
  return 'healthy';
}

function determineConfidence(
  artifacts: ArtifactDescriptor[],
  assessment: TearSheetAssessment
): ConfidenceLevel {
  if (artifacts.length === 0 || assessment === 'degraded') {
    return 'low';
  }
  const provenance = countProvenance(artifacts);
  const nonObservedRatio = (provenance.inferred + provenance.unavailable) / artifacts.length;
  if (assessment === 'limited' || nonObservedRatio > 0.25) {
    return 'medium';
  }
  return 'high';
}

function countProvenance(
  artifacts: ArtifactDescriptor[]
): Record<ProvenanceDisposition, number> {
  const output: Record<ProvenanceDisposition, number> = {
    observed: 0,
    inferred: 0,
    unavailable: 0
  };
  for (const artifact of artifacts) {
    output[artifact.provenance.disposition] += 1;
  }
  return output;
}

function countCorrelatedEvidence(evidence: TearSheetCorrelatedEvidence): {
  findings: number;
  searchTasks: number;
  searchResults: number;
  documents: number;
  latentFeatures: number;
} {
  return {
    findings: evidence.findings.length,
    searchTasks: countSearchTasks(evidence.searchSessions),
    searchResults: countSearchResults(evidence.searchSessions),
    documents: evidence.documents.length,
    latentFeatures: getJsonObjectArray(evidence.latentFeatureScan?.candidates).length
  };
}

function countSearchTasks(searchSessions: JsonObject[]): number {
  return searchSessions.reduce(
    (count, session) => count + getJsonObjectArray(session.tasks).length,
    0
  );
}

function countSearchTasksWithStatus(searchSessions: JsonObject[], status: string): number {
  let count = 0;
  for (const session of searchSessions) {
    for (const task of getJsonObjectArray(session.tasks)) {
      if (task.status === status) {
        count += 1;
      }
    }
  }
  return count;
}

function countSearchResults(searchSessions: JsonObject[]): number {
  let count = 0;
  for (const session of searchSessions) {
    for (const task of getJsonObjectArray(session.tasks)) {
      count += typeof task.resultCount === 'number' ? Math.max(0, task.resultCount) : 0;
    }
  }
  return count;
}

function collectNestedRecordIds(records: JsonObject[], nestedKey: string): string[] {
  const ids: string[] = [];
  for (const record of records) {
    for (const nested of getJsonObjectArray(record[nestedKey])) {
      if (typeof nested.id === 'string') {
        ids.push(nested.id);
      }
    }
  }
  return ids;
}

function searchRecordMatchesHostname(
  record: { target?: string } | object,
  targetHostname: string
): boolean {
  const candidate = record as { target?: unknown; targets?: unknown };
  if (
    typeof candidate.target === 'string' &&
    hostnameMatches(parseLooseHostname(candidate.target), targetHostname)
  ) {
    return true;
  }

  return getStringArray(candidate.targets).some((target) =>
    hostnameMatches(parseLooseHostname(target), targetHostname)
  );
}

function getStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0);
}

function joinNaturalLanguage(values: string[]): string {
  if (values.length <= 1) {
    return values[0] ?? 'no recorded outcomes';
  }
  if (values.length === 2) {
    return `${values[0]} and ${values[1]}`;
  }
  return `${values.slice(0, -1).join(', ')}, and ${values.at(-1)}`;
}

function getJsonObjectArray(value: unknown): JsonObject[] {
  return Array.isArray(value)
    ? value.filter(
        (entry): entry is JsonObject => typeof entry === 'object' && entry !== null && !Array.isArray(entry)
      )
    : [];
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function calculateDurationMs(startedAt: string, finishedAt: string): number | undefined {
  const started = Date.parse(startedAt);
  const finished = Date.parse(finishedAt);
  if (!Number.isFinite(started) || !Number.isFinite(finished) || finished < started) {
    return undefined;
  }
  return finished - started;
}

function findLatestEvidenceTimestamp(
  sourceExportedAt: string,
  evidence: TearSheetCorrelatedEvidence
): string {
  let latestTimestamp = sourceExportedAt;
  let latestValue = Date.parse(sourceExportedAt);

  const visit = (value: unknown, key?: string) => {
    if (typeof value === 'string' && key?.endsWith('At')) {
      const timestamp = Date.parse(value);
      if (Number.isFinite(timestamp) && (!Number.isFinite(latestValue) || timestamp > latestValue)) {
        latestTimestamp = value;
        latestValue = timestamp;
      }
      return;
    }
    if (Array.isArray(value)) {
      for (const entry of value) {
        visit(entry);
      }
      return;
    }
    if (typeof value === 'object' && value !== null) {
      for (const [childKey, entry] of Object.entries(value)) {
        visit(entry, childKey);
      }
    }
  };

  visit(evidence);
  return latestTimestamp;
}

function hashString(value: string): string {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(36);
}

function dedupeLimitations(limitations: TearSheetLimitation[]): TearSheetLimitation[] {
  const seen = new Set<string>();
  return limitations.filter((limitation) => {
    const key = `${limitation.source}:${limitation.code}:${limitation.detail}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function toJsonObject(value: object): JsonObject {
  return JSON.parse(JSON.stringify(value)) as JsonObject;
}

function tryGetOrigin(rawUrl?: string): string | undefined {
  if (!rawUrl) {
    return undefined;
  }
  try {
    const origin = new URL(rawUrl).origin;
    return origin === 'null' ? undefined : origin;
  } catch {
    return undefined;
  }
}

function tryGetHostname(rawUrl?: string): string | undefined {
  if (!rawUrl) {
    return undefined;
  }
  try {
    return normalizeHostname(new URL(rawUrl).hostname);
  } catch {
    return undefined;
  }
}

function parseLooseHostname(rawValue?: string): string | undefined {
  if (!rawValue) {
    return undefined;
  }
  const normalized = rawValue.trim();
  if (!normalized) {
    return undefined;
  }
  return tryGetHostname(normalized) ?? tryGetHostname(`https://${normalized.replace(/^site:/i, '')}`);
}

function hostnameMatches(candidate: string | undefined, target: string): boolean {
  const normalizedCandidate = normalizeHostname(candidate);
  const normalizedTarget = normalizeHostname(target);
  if (!normalizedCandidate || !normalizedTarget) {
    return false;
  }
  return normalizedCandidate === normalizedTarget;
}

function isBrowserOnlyArtifact(artifact: ArtifactDescriptor): boolean {
  return (
    BROWSER_ONLY_CATEGORIES.has(artifact.category) ||
    artifact.kind.startsWith('instrumented-') ||
    Boolean(artifact.url && /^(blob|data):/i.test(artifact.url)) ||
    artifact.discoveredBy.includes('instrumentation')
  );
}

function normalizeHostname(rawValue?: string): string | undefined {
  const normalized = rawValue?.trim().toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
  return normalized || undefined;
}

function sanitizeFilenamePart(rawValue: string): string {
  return rawValue
    .toLowerCase()
    .replace(/[^a-z0-9.-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^[.-]+|[.-]+$/g, '')
    .slice(0, 80) || 'unknown-site';
}
