import {
  SCRIPT_ANALYSIS_DEFAULT_LIMITS,
  SCRIPT_ANALYSIS_HARD_LIMITS,
  SCRIPT_BEHAVIOR_PATTERN_RULES,
  SCRIPT_PURPOSE_ANALYSIS_KIND,
  SCRIPT_PURPOSE_PATTERN_RULES,
  SCRIPT_PURPOSE_RUBRIC_VERSION,
  SCRIPT_PURPOSE_SCORE_MODEL,
  SCRIPT_PURPOSE_SCORE_THRESHOLDS,
  SCRIPT_REVIEW_PRIORITY_WEIGHTS,
  SCRIPT_TRANSFORM_PATTERN_RULES,
  type ScriptAnalysisCoverage,
  type ScriptBehaviorAxis,
  type ScriptBehaviorClaim,
  type ScriptBehaviorMaturity,
  type ScriptCoverageGap,
  type ScriptEvidenceClass,
  type ScriptEvidenceRecord,
  type ScriptIndicatorKind,
  type ScriptPurposeAnalysisContext,
  type ScriptPurposeAnalysisInput,
  type ScriptPurposeAnalysisOptions,
  type ScriptPurposeAnalysisResult,
  type ScriptPurposeCategory,
  type ScriptPurposeClaim,
  type ScriptPurposeConfidence,
  type ScriptPurposeSourceInput,
  type ScriptReviewPriority,
  type ScriptReviewPriorityFactor,
  type ScriptRuntimeObservationInput,
  type ScriptSanitizedIndicator,
  type ScriptScopeInput,
  type ScriptTestPlan,
  type ScriptTestPlanStage,
  type ScriptTransformAssessment,
  type ScriptTransformKind,
  type ScriptTransformMetrics,
  type ScriptTransformSignal
} from './scriptPurposeRubric';

const BEHAVIOR_AXES: readonly ScriptBehaviorAxis[] = [
  'network',
  'dom-ui',
  'data-handling',
  'identity-session-authorization',
  'server-state-change',
  'client-storage',
  'dynamic-code-loading',
  'persistence-background-realtime',
  'cross-origin-transfer',
  'latent-debug-admin'
] as const;

const DEFAULT_SCOPE: ScriptScopeInput = {
  disposition: 'unknown',
  ownership: 'unknown',
  matchedRuleIds: []
};

interface EvidenceAccumulator {
  add(input: Omit<ScriptEvidenceRecord, 'evidenceId'>, signature?: string): string | undefined;
  records: ScriptEvidenceRecord[];
}

interface PurposeAccumulator {
  score: number;
  evidenceRefs: string[];
  evidenceClasses: Set<ScriptEvidenceClass>;
  strong: boolean;
}

interface BehaviorAccumulator {
  maturity: ScriptBehaviorMaturity;
  evidenceRefs: string[];
  evidenceClasses: Set<ScriptEvidenceClass>;
  summaries: string[];
}

interface RuntimeEvidence {
  observation: ScriptRuntimeObservationInput;
  evidenceRef: string;
}

interface ResolvedLimits {
  maxEvidence: number;
  maxIndicators: number;
  maxClaims: number;
  maxSnippetCharacters: number;
}

/** Analyze one script body synchronously. The function performs no network or runtime actions. */
export function analyzeScriptPurpose(
  source: ScriptPurposeSourceInput,
  context: ScriptPurposeAnalysisContext = {}
): ScriptPurposeAnalysisResult {
  const limits = resolveLimits(context.options);
  const artifactSeed = artifactIdentitySeed(source);
  const artifactId = `script_${stableHash(artifactSeed)}`;
  const evidence = createEvidenceAccumulator(
    artifactSeed,
    limits.maxEvidence,
    limits.maxSnippetCharacters
  );
  const metrics = measureSource(source.text);
  const runtimeEvidence = recordRuntimeEvidence(
    context.runtimeObservations ?? [],
    evidence,
    source,
    limits
  );
  const transform = analyzeTransform(source, metrics, evidence, limits);
  const indicators = extractIndicators(source, context, runtimeEvidence, evidence, limits);
  const coverage = assessCoverage(source, context, transform, metrics);
  const purposeClaims = analyzePurposes(
    source,
    context,
    runtimeEvidence,
    coverage,
    evidence,
    limits
  );
  const behaviorClaims = analyzeBehaviors(
    source,
    runtimeEvidence,
    indicators,
    coverage,
    evidence,
    limits
  );
  const scope = normalizeScope(context.scope);
  const reviewPriority = calculateReviewPriority(
    purposeClaims,
    behaviorClaims,
    indicators
  );

  return {
    kind: SCRIPT_PURPOSE_ANALYSIS_KIND,
    rubricVersion: SCRIPT_PURPOSE_RUBRIC_VERSION,
    artifact: {
      artifactId,
      sourceKind: source.sourceKind,
      label: source.label,
      sourceUrl: source.sourceUrl,
      finalUrl: source.finalUrl,
      contentType: source.contentType,
      sha256: normalizeSha256(source.sha256),
      acquiredAt: source.acquiredAt,
      scope
    },
    transform,
    coverage,
    purposeClaims,
    behaviorClaims,
    indicators,
    evidence: evidence.records,
    reviewPriority,
    testPlan: buildTestPlan(source, scope, transform, coverage, behaviorClaims, runtimeEvidence)
  };
}

/** Convenience wrapper for callers that already hold a single input envelope. */
export function analyzeScriptPurposeInput(
  input: ScriptPurposeAnalysisInput
): ScriptPurposeAnalysisResult {
  const { source, ...context } = input;
  return analyzeScriptPurpose(source, context);
}

function analyzeTransform(
  source: ScriptPurposeSourceInput,
  metrics: ScriptTransformMetrics,
  evidence: EvidenceAccumulator,
  limits: ResolvedLimits
): ScriptTransformAssessment {
  if (metrics.characterCount === 0) {
    return {
      primary: 'unknown',
      detected: ['unknown'],
      complexityScore: 0,
      confidence: 'low',
      metrics,
      signals: []
    };
  }

  const signals: ScriptTransformSignal[] = [];
  const detected = new Set<ScriptTransformKind>();
  const minified =
    metrics.longestLineLength >= 1_000 ||
    metrics.meanNonEmptyLineLength >= 420 ||
    (metrics.characterCount >= 2_000 && metrics.whitespaceRatio <= 0.055);
  const readable =
    !minified &&
    metrics.meanNonEmptyLineLength <= 180 &&
    metrics.whitespaceRatio >= 0.075;

  if (minified) {
    const evidenceRef = evidence.add({
      evidenceClass: 'content-metric',
      disposition: 'observed',
      label: 'Minification metrics',
      detail: `Longest line ${metrics.longestLineLength}; mean non-empty line ${metrics.meanNonEmptyLineLength}; whitespace ratio ${metrics.whitespaceRatio}.`,
      sourceUrl: source.sourceUrl
    });
    detected.add('minified');
    if (evidenceRef) signals.push({
      code: 'TRANSFORM_MINIFIED_METRICS',
      kind: 'minified',
      weight: 25,
      detail: 'Line length and whitespace metrics are consistent with minification.',
      evidenceRefs: [evidenceRef]
    });
  } else if (readable) {
    const evidenceRef = evidence.add({
      evidenceClass: 'content-metric',
      disposition: 'observed',
      label: 'Readable source metrics',
      detail: `Mean non-empty line ${metrics.meanNonEmptyLineLength}; whitespace ratio ${metrics.whitespaceRatio}.`,
      sourceUrl: source.sourceUrl
    });
    detected.add('readable');
    if (evidenceRef) signals.push({
      code: 'TRANSFORM_READABLE_METRICS',
      kind: 'readable',
      weight: 0,
      detail: 'Line length and whitespace metrics are consistent with readable source.',
      evidenceRefs: [evidenceRef]
    });
  }

  for (const rule of SCRIPT_TRANSFORM_PATTERN_RULES) {
    const match = findFirstPattern(source.text, rule.patterns, rule.flags);
    if (!match) continue;
    const evidenceRef = evidence.add({
      evidenceClass: rule.evidenceClass,
      disposition: 'observed',
      label: rule.label,
      detail: rule.detail,
      sourceUrl: source.sourceUrl,
      startOffset: match.index,
      endOffset: match.index + match.text.length,
      snippet: matchSnippet(
        source.text,
        match.index,
        match.text.length,
        limits.maxSnippetCharacters
      )
    });
    detected.add(rule.kind);
    if (evidenceRef) signals.push({
      code: rule.code,
      kind: rule.kind,
      weight: rule.weight,
      detail: rule.detail,
      evidenceRefs: [evidenceRef]
    });
  }

  if (detected.size === 0) detected.add('readable');
  const primary = strongestTransform(detected);
  const baseComplexity =
    primary === 'obfuscated' ? 80 :
    primary === 'packed' ? 70 :
    primary === 'bundled' ? 45 :
    primary === 'minified' ? 25 : 0;
  const secondaryUplift = Math.min(20, Math.max(0, signals.length - 1) * 4);
  const complexityScore = clampScore(
    Math.max(baseComplexity, ...signals.map((signal) => signal.weight)) + secondaryUplift
  );
  const confidence: ScriptPurposeConfidence =
    signals.some((signal) => signal.kind === 'packed' || signal.kind === 'obfuscated') ? 'high' :
    signals.length > 0 ? 'medium' : 'low';

  return {
    primary,
    detected: [...detected].sort(compareTransforms),
    complexityScore,
    confidence,
    metrics,
    signals
  };
}

function analyzePurposes(
  source: ScriptPurposeSourceInput,
  context: ScriptPurposeAnalysisContext,
  runtimeEvidence: RuntimeEvidence[],
  coverage: ScriptAnalysisCoverage,
  evidence: EvidenceAccumulator,
  limits: ResolvedLimits
): ScriptPurposeClaim[] {
  const accumulators = new Map<ScriptPurposeCategory, PurposeAccumulator>();
  const add = (
    category: ScriptPurposeCategory,
    points: number,
    evidenceRef: string,
    evidenceClass: ScriptEvidenceClass
  ) => {
    const accumulator = accumulators.get(category) ?? {
      score: 0,
      evidenceRefs: [],
      evidenceClasses: new Set<ScriptEvidenceClass>(),
      strong: false
    };
    accumulator.score += points;
    addUnique(accumulator.evidenceRefs, evidenceRef);
    accumulator.evidenceClasses.add(evidenceClass);
    accumulator.strong ||= points >= 3;
    accumulators.set(category, accumulator);
  };

  for (const rule of SCRIPT_PURPOSE_PATTERN_RULES) {
    const match = findFirstPattern(source.text, rule.patterns, rule.flags);
    if (!match) continue;
    const evidenceRef = evidence.add({
      evidenceClass: rule.evidenceClass,
      disposition: rule.evidenceClass === 'literal' ? 'inferred' : 'observed',
      label: rule.label,
      detail: rule.detail,
      sourceUrl: source.sourceUrl,
      startOffset: match.index,
      endOffset: match.index + match.text.length,
      snippet: matchSnippet(source.text, match.index, match.text.length, limits.maxSnippetCharacters)
    });
    if (evidenceRef) add(rule.category, rule.points, evidenceRef, rule.evidenceClass);
  }

  if (context.sourceMap?.status === 'matched') {
    const symbols = uniqueStrings(context.sourceMap.symbols ?? []).slice(0, 100);
    for (const category of purposeCategoriesForSymbols(symbols)) {
      const evidenceRef = evidence.add({
        evidenceClass: 'source-map',
        disposition: 'observed',
        label: 'Matched source-map semantics',
        detail: `Matched source-map symbols support ${category}.`,
        sourceUrl: context.sourceMap.url,
        snippet: sanitizeSnippet(symbols.filter((symbol) => symbolSuggestsPurpose(symbol, category)).slice(0, 8).join(', '), limits.maxSnippetCharacters)
      }, `source-map:${category}`);
      if (evidenceRef) add(category, 5, evidenceRef, 'source-map');
    }
  }

  for (const entry of runtimeEvidence) {
    const categories = entry.observation.purposeHints?.length
      ? entry.observation.purposeHints
      : defaultPurposesForAxis(entry.observation.axis);
    for (const category of uniqueStrings(categories).filter(isPurposeCategory)) {
      if (category === 'unknown') continue;
      add(category, 5, entry.evidenceRef, 'runtime');
    }
  }

  if (accumulators.size === 0) {
    return [{
      category: 'unknown',
      role: 'primary',
      score: 0,
      confidence: 'low',
      reason: 'No purpose category met the evidence threshold.',
      evidenceRefs: []
    }];
  }

  const ranked = [...accumulators.entries()]
    .sort((left, right) => right[1].score - left[1].score || left[0].localeCompare(right[0]));
  let primaryAssigned = false;
  return ranked.slice(0, limits.maxClaims).map(([category, accumulator]) => {
    const independentlySupported = accumulator.evidenceClasses.size >= 2;
    let role: ScriptPurposeClaim['role'] = 'candidate';
    if (
      !primaryAssigned &&
      accumulator.score >= SCRIPT_PURPOSE_SCORE_THRESHOLDS.primary &&
      accumulator.strong &&
      independentlySupported
    ) {
      role = 'primary';
      primaryAssigned = true;
    } else if (accumulator.score >= SCRIPT_PURPOSE_SCORE_THRESHOLDS.secondary) {
      role = 'secondary';
    }
    return {
      category,
      role,
      score: accumulator.score,
      confidence: confidenceForClaim(
        accumulator.score,
        accumulator.evidenceClasses,
        coverage
      ),
      reason:
        role === 'primary'
          ? 'Meets the primary-purpose score, strength, and independent-evidence requirements.'
          : role === 'secondary'
            ? 'Meets the secondary-purpose evidence threshold.'
            : 'Retained as a candidate because its evidence does not meet a stronger threshold.',
      evidenceRefs: accumulator.evidenceRefs
    };
  });
}

function analyzeBehaviors(
  source: ScriptPurposeSourceInput,
  runtimeEvidence: RuntimeEvidence[],
  indicators: ScriptSanitizedIndicator[],
  coverage: ScriptAnalysisCoverage,
  evidence: EvidenceAccumulator,
  limits: ResolvedLimits
): ScriptBehaviorClaim[] {
  const accumulators = new Map<ScriptBehaviorAxis, BehaviorAccumulator>();
  for (const axis of BEHAVIOR_AXES) {
    accumulators.set(axis, {
      maturity: 0,
      evidenceRefs: [],
      evidenceClasses: new Set<ScriptEvidenceClass>(),
      summaries: []
    });
  }

  const add = (
    axis: ScriptBehaviorAxis,
    maturity: ScriptBehaviorMaturity,
    evidenceRef: string,
    evidenceClass: ScriptEvidenceClass,
    summary: string
  ) => {
    const accumulator = accumulators.get(axis)!;
    accumulator.maturity = Math.max(accumulator.maturity, maturity) as ScriptBehaviorMaturity;
    addUnique(accumulator.evidenceRefs, evidenceRef);
    accumulator.evidenceClasses.add(evidenceClass);
    addUnique(accumulator.summaries, summary);
  };

  for (const rule of SCRIPT_BEHAVIOR_PATTERN_RULES) {
    const match = findFirstPattern(source.text, rule.patterns, rule.flags);
    if (!match) continue;
    const evidenceRef = evidence.add({
      evidenceClass: rule.evidenceClass,
      disposition: rule.evidenceClass === 'literal' ? 'inferred' : 'observed',
      label: rule.label,
      detail: rule.detail,
      sourceUrl: source.sourceUrl,
      startOffset: match.index,
      endOffset: match.index + match.text.length,
      snippet: matchSnippet(
        source.text,
        match.index,
        match.text.length,
        limits.maxSnippetCharacters
      )
    }, `behavior:${rule.code}:${match.index}`);
    if (evidenceRef) add(rule.axis, rule.maturity, evidenceRef, rule.evidenceClass, rule.summary);
  }

  const crossOriginIndicators = indicators.filter((indicator) => indicator.kind === 'host');
  const sourceHost = safeUrl(source.finalUrl ?? source.sourceUrl)?.hostname.toLowerCase();
  const differentHost = sourceHost
    ? crossOriginIndicators.find((indicator) => indicator.value !== sourceHost)
    : undefined;
  if (differentHost) {
    add(
      'cross-origin-transfer',
      1,
      differentHost.evidenceRefs[0] ?? '',
      'literal',
      'The artifact references a destination on another origin; transmission was not established statically.'
    );
  }

  for (const entry of runtimeEvidence) {
    add(
      entry.observation.axis,
      3,
      entry.evidenceRef,
      'runtime',
      `Attributable runtime behavior was supplied for ${entry.observation.axis}.`
    );
    if (
      entry.observation.targetUrl &&
      isCrossOrigin(entry.observation.targetUrl, source.finalUrl ?? source.sourceUrl)
    ) {
      add(
        'cross-origin-transfer',
        3,
        entry.evidenceRef,
        'runtime',
        'An attributable runtime observation crossed the script origin boundary.'
      );
    }
  }

  return BEHAVIOR_AXES.map((axis) => {
    const accumulator = accumulators.get(axis)!;
    return {
      axis,
      maturity: accumulator.maturity,
      confidence: confidenceForBehavior(accumulator, coverage),
      summary:
        accumulator.summaries[0] ??
        `No ${axis} behavior was observed; this is not evidence that the behavior is absent.`,
      evidenceRefs: accumulator.evidenceRefs.filter(Boolean)
    };
  });
}

function extractIndicators(
  source: ScriptPurposeSourceInput,
  context: ScriptPurposeAnalysisContext,
  runtimeEvidence: RuntimeEvidence[],
  evidence: EvidenceAccumulator,
  limits: ResolvedLimits
): ScriptSanitizedIndicator[] {
  const indicators = new Map<string, ScriptSanitizedIndicator>();
  const add = (
    kind: ScriptIndicatorKind,
    value: string,
    confidence: ScriptPurposeConfidence,
    evidenceRef: string
  ) => {
    if (!value || indicators.size >= limits.maxIndicators) return;
    const key = `${kind}:${value}`;
    const existing = indicators.get(key);
    if (existing) {
      addUnique(existing.evidenceRefs, evidenceRef);
      existing.confidence = strongerConfidence(existing.confidence, confidence);
      return;
    }
    indicators.set(key, {
      indicatorId: `indicator_${stableHash(`${artifactIdentitySeed(source)}:${key}`)}`,
      kind,
      value,
      confidence,
      evidenceRefs: evidenceRef ? [evidenceRef] : []
    });
  };

  const endpointPattern = /["'`]((?:(?:https?|wss?):\/\/[^\s"'`\\]{1,500}|\/(?:api|graphql|v\d+|auth|admin|internal|config|events|collect)(?:\/[^\s"'`\\]{0,450})?))["'`]/gi;
  for (const match of source.text.matchAll(endpointPattern)) {
    if (indicators.size >= limits.maxIndicators) break;
    const raw = match[1];
    if (!raw) continue;
    const sanitized = sanitizeEndpoint(raw, source.finalUrl ?? source.sourceUrl);
    if (!sanitized) continue;
    const evidenceRef = evidence.add({
      evidenceClass: 'literal',
      disposition: 'inferred',
      label: 'Sanitized endpoint reference',
      detail: 'A URL literal was retained with values and identifier-like path segments removed.',
      sourceUrl: source.sourceUrl,
      startOffset: match.index,
      endOffset: match.index + match[0].length,
      snippet: sanitized.endpoint
    }, `endpoint:${sanitized.endpoint}`);
    if (evidenceRef) {
      add('endpoint', sanitized.endpoint, 'low', evidenceRef);
      if (sanitized.host) add('host', sanitized.host, 'low', evidenceRef);
    }
  }

  const storagePattern = /(?:localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)\s*\(\s*["'`]([^"'`]{1,160})["'`]/gi;
  for (const match of source.text.matchAll(storagePattern)) {
    const raw = match[1];
    if (!raw || indicators.size >= limits.maxIndicators) break;
    const value = sanitizeNamedIndicator(raw);
    if (!value) continue;
    const evidenceRef = evidence.add({
      evidenceClass: 'literal', disposition: 'observed', label: 'Storage key reference',
      detail: 'A browser-storage key name is referenced; no stored value was collected.',
      sourceUrl: source.sourceUrl, startOffset: match.index, endOffset: match.index + match[0].length,
      snippet: value
    }, `storage-key:${value}`);
    if (evidenceRef) add('storage-key', value, 'medium', evidenceRef);
  }

  const featurePattern = /(?:isFeatureEnabled|getFeatureFlag|checkGate|getBooleanValue|variation)\s*\(\s*["'`]([^"'`]{1,160})["'`]/gi;
  for (const match of source.text.matchAll(featurePattern)) {
    const raw = match[1];
    if (!raw || indicators.size >= limits.maxIndicators) break;
    const value = sanitizeNamedIndicator(raw);
    if (!value) continue;
    const evidenceRef = evidence.add({
      evidenceClass: 'literal', disposition: 'observed', label: 'Feature key reference',
      detail: 'A feature-provider call names a feature key.', sourceUrl: source.sourceUrl,
      startOffset: match.index, endOffset: match.index + match[0].length, snippet: value
    }, `feature-key:${value}`);
    if (evidenceRef) add('feature-key', value, 'medium', evidenceRef);
  }

  const eventPattern = /(?:addEventListener|dispatchEvent|\.emit)\s*\(\s*["'`]([A-Za-z][A-Za-z0-9_.:-]{0,100})["'`]/gi;
  for (const match of source.text.matchAll(eventPattern)) {
    const raw = match[1];
    if (!raw || indicators.size >= limits.maxIndicators) break;
    const value = sanitizeNamedIndicator(raw);
    if (!value) continue;
    const evidenceRef = evidence.add({
      evidenceClass: 'literal', disposition: 'inferred', label: 'Event name reference',
      detail: 'A named event is registered or emitted.', sourceUrl: source.sourceUrl,
      startOffset: match.index, endOffset: match.index + match[0].length, snippet: value
    }, `event-name:${value}`);
    if (evidenceRef) add('event-name', value, 'low', evidenceRef);
  }

  const sourceMapReference = findSourceMapReference(source.text);
  if (sourceMapReference) {
    const value = sanitizeSourceMapReference(sourceMapReference.value, source.finalUrl ?? source.sourceUrl);
    if (value) {
      const evidenceRef = evidence.add({
        evidenceClass: 'literal', disposition: 'observed', label: 'Source-map reference',
        detail: 'The artifact declares a source-map location.', sourceUrl: source.sourceUrl,
        startOffset: sourceMapReference.index,
        endOffset: sourceMapReference.index + sourceMapReference.value.length,
        snippet: value
      }, `source-map:${value}`);
      if (evidenceRef) {
        add(
          'source-map',
          value,
          context.sourceMap?.status === 'matched' ? 'high' : 'medium',
          evidenceRef
        );
      }
    }
  }

  for (const entry of runtimeEvidence) {
    if (!entry.observation.targetUrl) continue;
    const sanitized = sanitizeEndpoint(
      entry.observation.targetUrl,
      source.finalUrl ?? source.sourceUrl
    );
    if (!sanitized) continue;
    add('endpoint', sanitized.endpoint, 'high', entry.evidenceRef);
    if (sanitized.host) add('host', sanitized.host, 'high', entry.evidenceRef);
  }

  return [...indicators.values()].sort(
    (left, right) => left.kind.localeCompare(right.kind) || left.value.localeCompare(right.value)
  );
}

function assessCoverage(
  source: ScriptPurposeSourceInput,
  context: ScriptPurposeAnalysisContext,
  transform: ScriptTransformAssessment,
  metrics: ScriptTransformMetrics
): ScriptAnalysisCoverage {
  const declaredBytes = Math.max(metrics.byteLength, normalizeCount(source.declaredByteLength));
  const gaps: ScriptCoverageGap[] = [];
  const addGap = (code: ScriptCoverageGap['code'], material: boolean, detail: string) => {
    if (!gaps.some((gap) => gap.code === code)) gaps.push({ code, material, detail });
  };

  if (metrics.characterCount === 0) addGap('EMPTY_SOURCE', true, 'The source body is empty.');
  if (source.truncated) addGap('TRUNCATED_SOURCE', true, 'The supplied source body is truncated.');
  if (!normalizeSha256(source.sha256)) addGap('MISSING_CONTENT_HASH', false, 'No caller-supplied SHA-256 identifies the original bytes.');
  addGap('HEURISTIC_STATIC_ANALYSIS', false, 'Static results come from deterministic lexical and structural rules rather than a full JavaScript parser.');

  const sourceMapReference = findSourceMapReference(source.text);
  if (context.sourceMap?.status === 'mismatch') {
    addGap('SOURCE_MAP_MISMATCH', true, 'The supplied source map did not match the artifact.');
  } else if (sourceMapReference && context.sourceMap?.status !== 'matched') {
    addGap('SOURCE_MAP_UNAVAILABLE', true, 'The artifact names a source map that was not supplied and verified.');
  }
  if (/\bimport\s*\(/.test(source.text)) {
    addGap('UNRESOLVED_DYNAMIC_IMPORT', true, 'Dynamic imports are referenced but their target bodies were not part of this artifact.');
  }
  if (transform.primary === 'packed' || transform.primary === 'obfuscated') {
    addGap('UNRESOLVED_PACKED_PAYLOAD', true, 'Packed or obfuscated execution stages were detected but not decoded by this pure analyzer.');
  }
  if (/WebAssembly|\.wasm(?:[?#"'`]|$)/i.test(source.text)) {
    addGap('UNRESOLVED_WASM', true, 'WebAssembly is referenced but its module body was not analyzed here.');
  }
  if ((context.runtimeObservations?.length ?? 0) === 0) {
    addGap('RUNTIME_NOT_OBSERVED', false, 'No attributable runtime observations were supplied.');
  }

  const byteCoverageRatio = declaredBytes === 0
    ? 0
    : round(Math.min(1, metrics.byteLength / declaredBytes), 4);
  const materialGapCount = gaps.filter((gap) => gap.material).length;
  const status: ScriptAnalysisCoverage['status'] =
    metrics.characterCount === 0 || transform.primary === 'packed' || transform.primary === 'obfuscated'
      ? 'limited'
      : materialGapCount > 0 || byteCoverageRatio < 1
        ? 'partial'
        : 'complete';

  return {
    status,
    analyzedBytes: metrics.byteLength,
    declaredBytes,
    byteCoverageRatio,
    runtimeObservationCount: context.runtimeObservations?.length ?? 0,
    gaps
  };
}

function calculateReviewPriority(
  purposes: ScriptPurposeClaim[],
  behaviors: ScriptBehaviorClaim[],
  indicators: ScriptSanitizedIndicator[]
): ScriptReviewPriority {
  const factors: ScriptReviewPriorityFactor[] = [];
  const byAxis = new Map(behaviors.map((behavior) => [behavior.axis, behavior]));
  const addBehaviorFactor = (
    code: string,
    baseWeight: number,
    axis: ScriptBehaviorAxis,
    reason: string
  ) => {
    const behavior = byAxis.get(axis);
    if (!behavior || behavior.maturity === 0) return;
    factors.push({
      code,
      baseWeight,
      appliedWeight: applyMaturity(baseWeight, behavior.maturity),
      reason,
      evidenceRefs: behavior.evidenceRefs
    });
  };

  addBehaviorFactor('STATE_CHANGE', SCRIPT_REVIEW_PRIORITY_WEIGHTS.STATE_CHANGE, 'server-state-change', 'Potentially state-changing server behavior warrants review.');
  addBehaviorFactor('IDENTITY_ACCESS', SCRIPT_REVIEW_PRIORITY_WEIGHTS.IDENTITY_ACCESS, 'identity-session-authorization', 'Identity, session, or authorization handling warrants review.');
  addBehaviorFactor('SENSITIVE_DATA', SCRIPT_REVIEW_PRIORITY_WEIGHTS.SENSITIVE_DATA, 'data-handling', 'Potentially sensitive data semantics warrant review.');
  addBehaviorFactor('DYNAMIC_EXECUTION', SCRIPT_REVIEW_PRIORITY_WEIGHTS.DYNAMIC_EXECUTION, 'dynamic-code-loading', 'Dynamic code or module loading warrants review.');
  addBehaviorFactor('CROSS_ORIGIN', SCRIPT_REVIEW_PRIORITY_WEIGHTS.CROSS_ORIGIN, 'cross-origin-transfer', 'Cross-origin references or observed transfers warrant boundary review.');
  addBehaviorFactor('PERSISTENCE_REALTIME', SCRIPT_REVIEW_PRIORITY_WEIGHTS.PERSISTENCE_REALTIME, 'persistence-background-realtime', 'Persistent, background, or realtime behavior warrants review.');
  addBehaviorFactor('LATENT_CONTROL', SCRIPT_REVIEW_PRIORITY_WEIGHTS.LATENT_CONTROL, 'latent-debug-admin', 'Latent, debug, or administrative controls warrant review.');

  const adminPurpose = purposes.find((claim) => claim.category === 'developer-debug-admin');
  if (adminPurpose) {
    factors.push({
      code: 'PRIVILEGED_ADMIN',
      baseWeight: SCRIPT_REVIEW_PRIORITY_WEIGHTS.PRIVILEGED_ADMIN,
      appliedWeight: applyMaturity(
        SCRIPT_REVIEW_PRIORITY_WEIGHTS.PRIVILEGED_ADMIN,
        byAxis.get('latent-debug-admin')?.maturity ?? 1
      ),
      reason: 'Developer, debug, or administrative purpose evidence warrants privileged-surface review.',
      evidenceRefs: adminPurpose.evidenceRefs
    });
  }

  const hosts = indicators.filter((indicator) => indicator.kind === 'host');
  if (hosts.length >= 3) {
    factors.push({
      code: 'NETWORK_FANOUT',
      baseWeight: SCRIPT_REVIEW_PRIORITY_WEIGHTS.NETWORK_FANOUT,
      appliedWeight: applyMaturity(
        SCRIPT_REVIEW_PRIORITY_WEIGHTS.NETWORK_FANOUT,
        byAxis.get('network')?.maturity ?? 1
      ),
      reason: `The artifact references ${hosts.length} distinct network hosts.`,
      evidenceRefs: uniqueStrings(hosts.flatMap((indicator) => indicator.evidenceRefs))
    });
  }

  const substantive = purposes.filter((claim) => claim.score >= SCRIPT_PURPOSE_SCORE_THRESHOLDS.secondary);
  const categories = new Set(substantive.map((claim) => claim.category));
  const securityMaturity = behaviors
    .filter((behavior) => !['network', 'dom-ui', 'dynamic-code-loading'].includes(behavior.axis))
    .reduce((maximum, behavior) => Math.max(maximum, behavior.maturity), 0);
  if (
    categories.size > 0 &&
    [...categories].every((category) => category === 'loader-runtime' || category === 'third-party-integration') &&
    securityMaturity === 0
  ) {
    const refs = substantive.flatMap((claim) => claim.evidenceRefs);
    factors.push({
      code: 'VENDOR_ONLY', baseWeight: SCRIPT_REVIEW_PRIORITY_WEIGHTS.VENDOR_ONLY,
      appliedWeight: SCRIPT_REVIEW_PRIORITY_WEIGHTS.VENDOR_ONLY,
      reason: 'Current evidence supports only loader/runtime or third-party integration behavior.',
      evidenceRefs: uniqueStrings(refs)
    });
  } else if (categories.size === 1 && categories.has('telemetry-analytics') && securityMaturity === 0) {
    const claim = substantive.find((entry) => entry.category === 'telemetry-analytics');
    factors.push({
      code: 'TELEMETRY_ONLY', baseWeight: SCRIPT_REVIEW_PRIORITY_WEIGHTS.TELEMETRY_ONLY,
      appliedWeight: SCRIPT_REVIEW_PRIORITY_WEIGHTS.TELEMETRY_ONLY,
      reason: 'Current evidence supports only telemetry or analytics behavior.', evidenceRefs: claim?.evidenceRefs ?? []
    });
  } else if (categories.size === 1 && categories.has('app-shell-ui') && securityMaturity === 0) {
    const claim = substantive.find((entry) => entry.category === 'app-shell-ui');
    factors.push({
      code: 'STATIC_UI_ONLY', baseWeight: SCRIPT_REVIEW_PRIORITY_WEIGHTS.STATIC_UI_ONLY,
      appliedWeight: SCRIPT_REVIEW_PRIORITY_WEIGHTS.STATIC_UI_ONLY,
      reason: 'Current evidence supports only static UI or rendering behavior.', evidenceRefs: claim?.evidenceRefs ?? []
    });
  }

  const score = clampScore(factors.reduce((total, factor) => total + factor.appliedWeight, 0));
  return {
    scoreModel: SCRIPT_PURPOSE_SCORE_MODEL,
    score,
    band:
      score >= SCRIPT_PURPOSE_SCORE_THRESHOLDS.urgent ? 'urgent' :
      score >= SCRIPT_PURPOSE_SCORE_THRESHOLDS.high ? 'high' :
      score >= SCRIPT_PURPOSE_SCORE_THRESHOLDS.medium ? 'medium' : 'low',
    isVulnerabilitySeverity: false,
    factors
  };
}

function buildTestPlan(
  source: ScriptPurposeSourceInput,
  scope: ScriptScopeInput,
  transform: ScriptTransformAssessment,
  coverage: ScriptAnalysisCoverage,
  behaviors: ScriptBehaviorClaim[],
  runtimeEvidence: RuntimeEvidence[]
): ScriptTestPlan {
  const sourceAvailable = source.text.length > 0;
  const materialGaps = coverage.gaps.filter((gap) => gap.material);
  const stateChange = behaviors.find((behavior) => behavior.axis === 'server-state-change')?.maturity ?? 0;
  const activeThirdParty = scope.ownership === 'third-party' || scope.ownership === 'shared';
  const explicitlyInScope = scope.disposition === 'in-scope';
  const stage0: ScriptTestPlanStage = {
    stage: 0,
    mode: 'offline-static',
    status: sourceAvailable ? 'complete' : 'blocked',
    objective: 'Inventory transforms, purposes, behavior references, and sanitized indicators without executing the artifact.',
    actions: [
      'Preserve the original content hash and acquisition metadata.',
      'Review transform signals, evidence spans, coverage gaps, and extracted indicators.',
      'Correlate explicit source-map and import references without guessing resource names.'
    ],
    successCriteria: [
      'Every retained claim cites bounded evidence.',
      'Sensitive values and URL parameter values are absent from indicators.',
      'Material coverage gaps are recorded.'
    ],
    stopConditions: ['Stop if the source is empty or its identity cannot be tied to the reviewed artifact.'],
    terminationReason: sourceAvailable ? 'NONE' : 'NO_SOURCE'
  };
  const stage1: ScriptTestPlanStage = {
    stage: 1,
    mode: 'isolated-sandbox',
    status: sourceAvailable ? 'ready' : 'blocked',
    objective: 'Resolve runtime decoding and capability registration in an isolated local harness.',
    actions: [
      'Execute only in a disposable browser or worker context with real network access blocked.',
      'Replace network, storage, worker, navigation, and dialog APIs with recording test doubles.',
      'Exercise exported handlers and captured callbacks with synthetic, non-sensitive fixtures.',
      ...(transform.primary === 'packed' || transform.primary === 'obfuscated'
        ? ['Capture decoded code passed to dynamic execution primitives and analyze it as a new derived artifact.']
        : [])
    ],
    successCriteria: [
      'Each observed capability is attributable to this artifact.',
      'Derived code and traces retain hashes and parent evidence references.',
      'No real external request or persistent host mutation occurs.'
    ],
    stopConditions: [
      'Stop on attempted native process, filesystem, extension-privilege, or unmocked network access.',
      'Stop if decoding exceeds the configured host resource or time budget.'
    ],
    terminationReason: sourceAvailable ? 'NONE' : 'NO_SOURCE'
  };
  const stage2: ScriptTestPlanStage = {
    stage: 2,
    mode: 'passive-observation',
    status: runtimeEvidence.length > 0 ? 'complete' : sourceAvailable ? 'conditional' : 'blocked',
    objective: 'Correlate real page behavior to the artifact during an operator-driven in-scope scenario.',
    actions: [
      'Observe initiators, registered handlers, DOM changes, storage names, and sanitized request templates.',
      'Use normal page navigation and supplied test fixtures; do not guess routes, chunks, credentials, or feature values.',
      'Attach attributable runtime observations to the corresponding behavior axes.'
    ],
    successCriteria: [
      'Referenced behavior is distinguished from behavior observed at runtime.',
      'Each observation retains scenario, initiator, scope, and evidence identity.',
      'Negative results are stated as not observed for the exercised scenarios.'
    ],
    stopConditions: [
      'Stop before a redirect or request leaves executable scope.',
      'Stop before any real transaction, message, upload, entitlement change, or destructive workflow.'
    ],
    terminationReason:
      !sourceAvailable ? 'NO_SOURCE' :
      runtimeEvidence.length > 0 ? 'NONE' : 'RUNTIME_EVIDENCE_REQUIRED'
  };

  let stage3Status: ScriptTestPlanStage['status'] = 'ready';
  let stage3Reason: ScriptTestPlanStage['terminationReason'] = 'NONE';
  if (!sourceAvailable) {
    stage3Status = 'blocked';
    stage3Reason = 'NO_SOURCE';
  } else if (activeThirdParty) {
    stage3Status = 'blocked';
    stage3Reason = 'THIRD_PARTY_ACTIVE_TEST_BLOCKED';
  } else if (!explicitlyInScope) {
    stage3Status = 'blocked';
    stage3Reason = 'EXPLICIT_SCOPE_REQUIRED';
  } else if (stateChange > 0) {
    stage3Status = 'conditional';
    stage3Reason = 'STATE_CHANGE_REVIEW_REQUIRED';
  } else if (runtimeEvidence.length === 0) {
    stage3Status = 'conditional';
    stage3Reason = 'RUNTIME_EVIDENCE_REQUIRED';
  } else if (materialGaps.length > 0) {
    stage3Status = 'conditional';
    stage3Reason = 'STATIC_COVERAGE_GAP';
  }

  const stage3: ScriptTestPlanStage = {
    stage: 3,
    mode: 'authorized-active',
    status: stage3Status,
    objective: 'Validate selected behavior at the server boundary only under the executable engagement scope.',
    actions: [
      'Select a reviewed claim and define its expected safe result before sending a request.',
      'Enforce the approved host, method, path, identity, rate, and redirect constraints for every request.',
      'Use designated test accounts and synthetic data; preserve request and response evidence with sensitive values redacted.',
      'Require a separate human-reviewed test case before any state-changing operation.'
    ],
    successCriteria: [
      'The tested behavior is reproducible and tied to the original script claim.',
      'Observed server behavior is reported separately from static review priority.',
      'All mutations have an explicit rollback or use disposable test data.'
    ],
    stopConditions: [
      'Stop on scope ambiguity, ownership ambiguity, an unexpected redirect, real-user data, or third-party traffic.',
      'Stop before spending, publishing, messaging, privilege changes, or irreversible state changes.',
      'Stop if rate, request-count, or test-case bounds are reached.'
    ],
    terminationReason: stage3Reason
  };

  return {
    generatedFromRubric: SCRIPT_PURPOSE_RUBRIC_VERSION,
    stages: [stage0, stage1, stage2, stage3]
  };
}

function recordRuntimeEvidence(
  observations: ScriptRuntimeObservationInput[],
  evidence: EvidenceAccumulator,
  source: ScriptPurposeSourceInput,
  limits: ResolvedLimits
): RuntimeEvidence[] {
  return observations.slice(0, limits.maxEvidence).flatMap((observation) => {
    const evidenceRef = evidence.add({
      evidenceClass: 'runtime',
      disposition: 'observed',
      label: `Runtime observation: ${observation.axis}`,
      detail: sanitizeSnippet(observation.detail, limits.maxSnippetCharacters),
      sourceUrl: source.sourceUrl,
      snippet: observation.targetUrl
        ? sanitizeEndpoint(observation.targetUrl, source.finalUrl ?? source.sourceUrl)?.endpoint
        : undefined
    }, observation.evidenceId ? `runtime:${observation.evidenceId}` : undefined);
    return evidenceRef ? [{ observation, evidenceRef }] : [];
  });
}

function createEvidenceAccumulator(
  seed: string,
  maximum: number,
  maximumSnippetCharacters: number
): EvidenceAccumulator {
  const records: ScriptEvidenceRecord[] = [];
  const signatures = new Map<string, string>();
  let sequence = 0;
  return {
    records,
    add(input, explicitSignature) {
      const signature = explicitSignature ?? [
        input.evidenceClass,
        input.label,
        input.startOffset ?? '',
        input.endOffset ?? '',
        input.detail
      ].join(':');
      const existing = signatures.get(signature);
      if (existing) return existing;
      if (records.length >= maximum) return undefined;
      const evidenceId = `evidence_${stableHash(`${seed}:${sequence}:${signature}`)}`;
      records.push({
        ...input,
        detail: sanitizeSnippet(input.detail, 500),
        snippet: input.snippet
          ? sanitizeSnippet(input.snippet, maximumSnippetCharacters)
          : undefined,
        evidenceId
      });
      sequence += 1;
      signatures.set(signature, evidenceId);
      return evidenceId;
    }
  };
}

function measureSource(text: string): ScriptTransformMetrics {
  const lines = text.split(/\r?\n/);
  const nonEmpty = lines.filter((line) => line.trim().length > 0);
  const whitespaceCount = (text.match(/\s/g) ?? []).length;
  return {
    characterCount: text.length,
    byteLength: utf8ByteLength(text),
    lineCount: lines.length,
    nonEmptyLineCount: nonEmpty.length,
    longestLineLength: lines.reduce((maximum, line) => Math.max(maximum, line.length), 0),
    meanNonEmptyLineLength: nonEmpty.length === 0
      ? 0
      : Math.round(nonEmpty.reduce((total, line) => total + line.length, 0) / nonEmpty.length),
    whitespaceRatio: text.length === 0 ? 0 : round(whitespaceCount / text.length, 4)
  };
}

function resolveLimits(options: ScriptPurposeAnalysisOptions | undefined): ResolvedLimits {
  return {
    maxEvidence: clampLimit(options?.maxEvidence, SCRIPT_ANALYSIS_DEFAULT_LIMITS.maxEvidence, SCRIPT_ANALYSIS_HARD_LIMITS.maxEvidence),
    maxIndicators: clampLimit(options?.maxIndicators, SCRIPT_ANALYSIS_DEFAULT_LIMITS.maxIndicators, SCRIPT_ANALYSIS_HARD_LIMITS.maxIndicators),
    maxClaims: clampLimit(options?.maxClaims, SCRIPT_ANALYSIS_DEFAULT_LIMITS.maxClaims, SCRIPT_ANALYSIS_HARD_LIMITS.maxClaims),
    maxSnippetCharacters: clampLimit(options?.maxSnippetCharacters, SCRIPT_ANALYSIS_DEFAULT_LIMITS.maxSnippetCharacters, SCRIPT_ANALYSIS_HARD_LIMITS.maxSnippetCharacters)
  };
}

function confidenceForClaim(
  score: number,
  evidenceClasses: Set<ScriptEvidenceClass>,
  coverage: ScriptAnalysisCoverage
): ScriptPurposeConfidence {
  const strong = [...evidenceClasses].some((value) =>
    value === 'runtime' || value === 'source-map' || value === 'structural-pattern'
  );
  let confidence: ScriptPurposeConfidence =
    evidenceClasses.size >= 2 && strong ? 'high' : score >= 4 || strong ? 'medium' : 'low';
  if (coverage.gaps.some((gap) => gap.material) && confidence === 'high') confidence = 'medium';
  if (coverage.gaps.some((gap) => gap.code === 'EMPTY_SOURCE')) confidence = 'low';
  return confidence;
}

function confidenceForBehavior(
  accumulator: BehaviorAccumulator,
  coverage: ScriptAnalysisCoverage
): ScriptPurposeConfidence {
  if (accumulator.maturity === 0 || accumulator.maturity === 1) return 'low';
  if (accumulator.maturity === 3) {
    return coverage.gaps.some((gap) => gap.material) ? 'medium' : 'high';
  }
  return accumulator.evidenceClasses.size >= 2 && !coverage.gaps.some((gap) => gap.material)
    ? 'high'
    : 'medium';
}

function purposeCategoriesForSymbols(symbols: string[]): ScriptPurposeCategory[] {
  const categories = new Set<ScriptPurposeCategory>();
  for (const category of [
    'loader-runtime', 'app-shell-ui', 'api-data', 'identity-access', 'feature-configuration',
    'telemetry-analytics', 'storage-offline', 'realtime-messaging',
    'file-media-crypto-payment', 'developer-debug-admin', 'third-party-integration'
  ] as const) {
    if (symbols.some((symbol) => symbolSuggestsPurpose(symbol, category))) categories.add(category);
  }
  return [...categories];
}

function symbolSuggestsPurpose(symbol: string, category: ScriptPurposeCategory): boolean {
  const patterns: Record<Exclude<ScriptPurposeCategory, 'unknown'>, RegExp> = {
    'loader-runtime': /loader|runtime|chunk|module|bootstrap/i,
    'app-shell-ui': /render|component|router|view|layout|page/i,
    'api-data': /api|fetch|request|query|mutation|client/i,
    'identity-access': /auth|identity|login|logout|token|session|permission/i,
    'feature-configuration': /feature|flag|experiment|config|rollout|gate/i,
    'telemetry-analytics': /telemetry|analytics|metric|track|beacon|event/i,
    'storage-offline': /storage|indexeddb|cache|offline|serviceworker/i,
    'realtime-messaging': /websocket|realtime|subscribe|message|eventsource/i,
    'file-media-crypto-payment': /file|media|upload|download|crypto|payment|stripe|paypal/i,
    'developer-debug-admin': /debug|developer|admin|internal|console/i,
    'third-party-integration': /integration|provider|vendor|sentry|segment|intercom/i
  };
  return category !== 'unknown' && patterns[category].test(symbol);
}

function defaultPurposesForAxis(axis: ScriptBehaviorAxis): ScriptPurposeCategory[] {
  const mapping: Record<ScriptBehaviorAxis, ScriptPurposeCategory[]> = {
    network: ['api-data'],
    'dom-ui': ['app-shell-ui'],
    'data-handling': ['api-data'],
    'identity-session-authorization': ['identity-access'],
    'server-state-change': ['api-data'],
    'client-storage': ['storage-offline'],
    'dynamic-code-loading': ['loader-runtime'],
    'persistence-background-realtime': ['realtime-messaging', 'storage-offline'],
    'cross-origin-transfer': ['third-party-integration'],
    'latent-debug-admin': ['feature-configuration', 'developer-debug-admin']
  };
  return mapping[axis];
}

function findFirstPattern(
  text: string,
  patterns: readonly string[],
  flags = 'i'
): { index: number; text: string } | undefined {
  let earliest: { index: number; text: string } | undefined;
  for (const pattern of patterns) {
    const match = new RegExp(pattern, flags.replace(/g/g, '')).exec(text);
    if (!match || (earliest && match.index >= earliest.index)) continue;
    earliest = { index: match.index, text: match[0] };
  }
  return earliest;
}

function strongestTransform(detected: Set<ScriptTransformKind>): ScriptTransformKind {
  for (const kind of ['obfuscated', 'packed', 'bundled', 'minified', 'readable'] as const) {
    if (detected.has(kind)) return kind;
  }
  return 'unknown';
}

function compareTransforms(left: ScriptTransformKind, right: ScriptTransformKind): number {
  const rank: Record<ScriptTransformKind, number> = {
    obfuscated: 0, packed: 1, bundled: 2, minified: 3, readable: 4, unknown: 5
  };
  return rank[left] - rank[right];
}

function matchSnippet(text: string, index: number, length: number, maximum = 240): string {
  const radius = Math.max(30, Math.floor((maximum - length) / 2));
  return sanitizeSnippet(text.slice(Math.max(0, index - radius), index + length + radius), maximum);
}

function sanitizeSnippet(value: string, maximum: number): string {
  return value
    .replace(/Bearer\s+[A-Za-z0-9._~+\/-]+=*/gi, 'Bearer [redacted]')
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, '[redacted-jwt]')
    .replace(/([?&][A-Za-z0-9_.~-]{1,80}=)[^&#\s"'`]*/g, '$1[redacted]')
    .replace(/((?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*["'`])[^"'`]+/gi, '$1[redacted]')
    .replace(/\b(?:[A-Fa-f0-9]{32,}|[A-Za-z0-9+/_-]{48,}={0,2})\b/g, '[redacted-long-value]')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maximum);
}

function sanitizeEndpoint(raw: string, base?: string): { endpoint: string; host?: string } | undefined {
  const parsed = safeUrl(raw, base);
  if (!parsed || !['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol)) return undefined;
  const host = parsed.hostname.toLowerCase();
  const port = parsed.port ? `:${parsed.port}` : '';
  const path = parsed.pathname
    .split('/')
    .map((segment) => templatePathSegment(segment))
    .join('/') || '/';
  const parameterNames = uniqueStrings([...parsed.searchParams.keys()])
    .filter((name) => /^[A-Za-z0-9_.~-]{1,80}$/.test(name))
    .sort()
    .slice(0, 30);
  const query = parameterNames.length > 0 ? `?${parameterNames.join('&')}` : '';
  return { endpoint: `${parsed.protocol}//${host}${port}${path}${query}`, host };
}

function sanitizeSourceMapReference(raw: string, base?: string): string | undefined {
  if (/^data:/i.test(raw)) return 'data:[inline-source-map]';
  const parsed = safeUrl(raw, base);
  if (!parsed) return sanitizeNamedIndicator(raw);
  parsed.username = '';
  parsed.password = '';
  parsed.hash = '';
  parsed.search = '';
  return parsed.toString();
}

function sanitizeNamedIndicator(raw: string): string | undefined {
  const trimmed = raw.trim().replace(/\s+/g, ' ').slice(0, 160);
  if (!trimmed || /[\u0000-\u001f]/.test(trimmed)) return undefined;
  if (/^[A-Za-z0-9+/_-]{40,}={0,2}$/.test(trimmed) || /^[A-Fa-f0-9]{24,}$/.test(trimmed)) {
    return `[opaque:${stableHash(trimmed)}]`;
  }
  return trimmed;
}

function templatePathSegment(segment: string): string {
  if (!segment) return '';
  if (
    /^\d{2,}$/.test(segment) ||
    /^[A-Fa-f0-9]{8,}$/.test(segment) ||
    /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(segment) ||
    /^[A-Za-z0-9_-]{20,}$/.test(segment) ||
    /%40|@/.test(segment)
  ) return '{id}';
  return segment.slice(0, 100);
}

function findSourceMapReference(text: string): { value: string; index: number } | undefined {
  const match = /[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)/i.exec(text);
  return match?.[1] ? { value: match[1], index: match.index } : undefined;
}

function isCrossOrigin(target: string, source: string | undefined): boolean {
  const targetUrl = safeUrl(target, source);
  const sourceUrl = safeUrl(source);
  return Boolean(targetUrl && sourceUrl && targetUrl.origin !== sourceUrl.origin);
}

function safeUrl(raw: string | undefined, base?: string): URL | undefined {
  if (!raw) return undefined;
  try {
    return base ? new URL(raw, base) : new URL(raw);
  } catch {
    return undefined;
  }
}

function applyMaturity(weight: number, maturity: ScriptBehaviorMaturity): number {
  const multiplier: Record<ScriptBehaviorMaturity, number> = { 0: 0, 1: 0.25, 2: 0.67, 3: 1 };
  return Math.round(weight * multiplier[maturity]);
}

function normalizeScope(scope: ScriptScopeInput | undefined): ScriptScopeInput {
  if (!scope) return { ...DEFAULT_SCOPE, matchedRuleIds: [] };
  return {
    disposition: scope.disposition,
    ownership: scope.ownership,
    policyId: scope.policyId,
    policyVersion: scope.policyVersion,
    matchedRuleIds: uniqueStrings(scope.matchedRuleIds ?? [])
  };
}

function artifactIdentitySeed(source: ScriptPurposeSourceInput): string {
  const contentIdentity = normalizeSha256(source.sha256) ?? [
    source.text.length,
    stableHash(source.text)
  ].join(':');
  const deliveryOccurrence =
    typeof source.deliveryIndex === 'number' &&
    Number.isSafeInteger(source.deliveryIndex) &&
    source.deliveryIndex >= 0
      ? source.deliveryIndex
      : 0;
  const sourceLocator = [
    source.label.trim().slice(0, 500),
    (source.finalUrl ?? source.sourceUrl ?? '').trim().slice(0, 2048)
  ].join(':');
  return [
    source.sourceKind,
    stableHash(sourceLocator),
    deliveryOccurrence,
    contentIdentity
  ].join(':');
}

function normalizeSha256(value: string | undefined): string | undefined {
  const normalized = value?.trim().toLowerCase();
  return normalized && /^[a-f0-9]{64}$/.test(normalized) ? normalized : undefined;
}

function normalizeCount(value: number | undefined): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0;
}

function clampLimit(value: number | undefined, fallback: number, maximum: number): number {
  return typeof value === 'number' && Number.isFinite(value)
    ? Math.max(1, Math.min(maximum, Math.floor(value)))
    : fallback;
}

function clampScore(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function strongerConfidence(
  left: ScriptPurposeConfidence,
  right: ScriptPurposeConfidence
): ScriptPurposeConfidence {
  const rank: Record<ScriptPurposeConfidence, number> = { high: 3, medium: 2, low: 1 };
  return rank[right] > rank[left] ? right : left;
}

function isPurposeCategory(value: string): value is ScriptPurposeCategory {
  return [
    'loader-runtime', 'app-shell-ui', 'api-data', 'identity-access', 'feature-configuration',
    'telemetry-analytics', 'storage-offline', 'realtime-messaging',
    'file-media-crypto-payment', 'developer-debug-admin', 'third-party-integration', 'unknown'
  ].includes(value);
}

function uniqueStrings<T extends string>(values: readonly T[]): T[] {
  return [...new Set(values)];
}

function addUnique<T>(values: T[], value: T): void {
  if (!values.includes(value)) values.push(value);
}

function stableHash(value: string): string {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(36);
}

function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x80) bytes += 1;
    else if (code < 0x800) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        index += 1;
      } else bytes += 3;
    } else bytes += 3;
  }
  return bytes;
}

function round(value: number, digits: number): number {
  const scale = 10 ** digits;
  return Math.round(value * scale) / scale;
}
