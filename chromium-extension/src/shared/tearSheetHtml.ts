import type {
  ArtifactDescriptor,
  BlancheTearSheetV1,
  JsonObject,
  TearSheetArtifactCategorySummary,
  TearSheetObservation
} from '../../../shared-schema/src';
import { getArtifactCategoryLabel } from './tearSheetReport';

export function renderTearSheetHtml(report: BlancheTearSheetV1): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'" />
    <title>${escapeHtml(report.target.hostname ?? report.target.title ?? 'Site')} · BLANCHE Site Tear Sheet</title>
    <style>${TEAR_SHEET_DOCUMENT_CSS}</style>
  </head>
  <body>
    <main class="tear-document">
      ${renderTearSheetStakeholderBody(report)}
    </main>
  </body>
</html>\n`;
}

export function renderTearSheetStakeholderBody(report: BlancheTearSheetV1): string {
  const findingCards = report.correlatedEvidence.findings.map(renderFindingCard).join('');
  const searchRows = buildSearchRows(report.correlatedEvidence.searchSessions);
  const documentRows = report.correlatedEvidence.documents.map(renderDocumentRow).join('');
  const latentCandidates = getJsonObjectArray(report.correlatedEvidence.latentFeatureScan?.candidates);
  const scriptAssessments = getJsonObjectArray(
    report.correlatedEvidence.latentFeatureScan?.scriptAssessments
  );
  const javascriptTest = report.correlatedEvidence.javascriptTest;
  const observationCards = report.observations.map(renderObservation).join('');
  const collectorRows = report.captureProfile.collectors
    .map(
      (collector) => `
        <tr>
          <td><strong>${escapeHtml(collector.name)}</strong><small>${escapeHtml(collector.collectorId)}</small></td>
          <td>${escapeHtml(collector.surface)}</td>
          <td><span class="tear-pill tear-status-${escapeHtml(collector.status)}">${escapeHtml(collector.status)}</span></td>
          <td>${collector.warningCount}</td>
          <td>${collector.errorCount}</td>
          <td>${collector.visibilityGapCount}</td>
        </tr>`
    )
    .join('');
  const categoryCards = report.evidenceSummary.categories.map(renderCategoryCard).join('');
  const originRows = report.evidenceSummary.origins
    .map(
      (origin) => `
        <tr>
          <td><code>${escapeHtml(origin.origin)}</code></td>
          <td>${origin.count}</td>
          <td>${origin.crossOrigin ? '<span class="tear-pill tear-status-partial">Cross-origin</span>' : 'Page origin'}</td>
          <td>${origin.categories.map((category) => escapeHtml(getArtifactCategoryLabel(category))).join(', ')}</td>
        </tr>`
    )
    .join('');
  const artifactRows = report.sourceCapture.artifacts.map(renderArtifactRow).join('');
  const limitations = report.limitations
    .map(
      (limitation) => `
        <li>
          <div class="tear-limit-heading">
            <strong>${escapeHtml(limitation.title)}</strong>
            <code>${escapeHtml(limitation.code)}</code>
          </div>
          <p>${escapeHtml(limitation.detail)}</p>
        </li>`
    )
    .join('');

  return `
    <div class="tear-report-root" data-tear-sheet-report>
    <header class="tear-hero">
      <div class="tear-kicker">BLANCHE · Site Evidence Tear Sheet</div>
      <div class="tear-hero-grid">
        <div>
          <h1>${escapeHtml(report.target.hostname ?? report.target.title ?? 'Captured site')}</h1>
          <p class="tear-lead">${escapeHtml(report.executiveSummary.headline)}</p>
        </div>
        <dl class="tear-identity">
          <div><dt>Captured</dt><dd>${escapeHtml(formatTimestamp(report.captureProfile.finishedAt))}</dd></div>
          <div><dt>Evidence as of</dt><dd>${escapeHtml(formatTimestamp(report.metadata.evidenceAsOf))}</dd></div>
          <div><dt>Report generated</dt><dd>${escapeHtml(formatTimestamp(report.metadata.generatedAt))}</dd></div>
          <div><dt>Mode</dt><dd>${escapeHtml(report.captureProfile.mode)}</dd></div>
          <div><dt>Assessment</dt><dd><span class="tear-pill tear-assessment-${escapeHtml(report.executiveSummary.assessment)}">${escapeHtml(report.executiveSummary.assessment)}</span></dd></div>
          <div><dt>Confidence</dt><dd>${escapeHtml(report.executiveSummary.confidence)}</dd></div>
        </dl>
      </div>
      <div class="tear-target-line">
        <span>${escapeHtml(report.target.title ?? '(untitled page)')}</span>
        <code>${escapeHtml(maskUrl(report.target.url) ?? '(URL unavailable)')}</code>
      </div>
      <p>${escapeHtml(report.executiveSummary.overview)}</p>
    </header>

    <section class="tear-sensitive-banner" role="note">
      <strong>Evidence handling</strong>
      <span>This stakeholder view masks raw values and URL query data. The companion JSON preserves full evidence and must be handled as assessment-sensitive.</span>
    </section>

    <section class="tear-section">
      <div class="tear-section-heading"><div><span>01</span><h2>Executive snapshot</h2></div><p>Counts reconcile to report JSON and the embedded source capture.</p></div>
      <div class="tear-metric-grid">
        ${report.executiveSummary.metrics
          .map(
            (metric) => `
              <article class="tear-metric">
                <strong>${escapeHtml(String(metric.value ?? ''))}</strong>
                <h3>${escapeHtml(metric.label)}</h3>
                <p>${escapeHtml(metric.detail)}</p>
              </article>`
          )
          .join('')}
      </div>
    </section>

    <section class="tear-section">
      <div class="tear-section-heading"><div><span>02</span><h2>What BLANCHE observed</h2></div><p>Informational testing context with direct evidence references.</p></div>
      <div class="tear-observation-list">${observationCards}</div>
    </section>

    <section class="tear-section">
      <div class="tear-section-heading"><div><span>03</span><h2>Browser evidence inventory</h2></div><p>Normalized artifacts grouped by browser surface.</p></div>
      <div class="tear-category-grid">${categoryCards}</div>
      <div class="tear-provenance-row">
        <span><strong>${report.evidenceSummary.provenance.observed}</strong> observed</span>
        <span><strong>${report.evidenceSummary.provenance.inferred}</strong> inferred</span>
        <span><strong>${report.evidenceSummary.provenance.unavailable}</strong> unavailable provenance</span>
      </div>
    </section>

    <section class="tear-section">
      <div class="tear-section-heading"><div><span>04</span><h2>Origin relationships</h2></div><p>Cross-origin means different from the captured page origin; it does not establish third-party ownership.</p></div>
      ${originRows ? `<div class="tear-table-wrap"><table><thead><tr><th>Origin</th><th>Artifacts</th><th>Relationship</th><th>Evidence types</th></tr></thead><tbody>${originRows}</tbody></table></div>` : '<p class="tear-empty">No artifact origins were available.</p>'}
    </section>

    <section class="tear-section">
      <div class="tear-section-heading"><div><span>05</span><h2>Correlated testing context</h2></div><p>Host-associated workbench records captured at report time.</p></div>
      <div class="tear-context-grid">
        <article class="tear-context-panel">
          <h3>Tester-facing leads <span>${report.correlatedEvidence.findings.length}</span></h3>
          ${findingCards || '<p class="tear-empty">No tester findings matched this site.</p>'}
        </article>
        <article class="tear-context-panel">
          <h3>Tracked search tasks <span>${searchRows.count}</span></h3>
          ${searchRows.markup || '<p class="tear-empty">No tracked search sessions matched this site.</p>'}
        </article>
        <article class="tear-context-panel">
          <h3>Document records <span>${report.correlatedEvidence.documents.length}</span></h3>
          ${documentRows || '<p class="tear-empty">No document records matched this site.</p>'}
        </article>
        <article class="tear-context-panel">
          <h3>Latent feature candidates <span>${latentCandidates.length}</span></h3>
          ${latentCandidates.length > 0 ? latentCandidates.map(renderLatentFeature).join('') : '<p class="tear-empty">No matching latent-feature scan was retained.</p>'}
        </article>
        <article class="tear-context-panel">
          <h3>Delivered JavaScript <span>${scriptAssessments.length}</span></h3>
          ${scriptAssessments.length > 0 ? scriptAssessments.map(renderScriptAssessment).join('') : '<p class="tear-empty">No script-purpose assessments matched this site.</p>'}
        </article>
        <article class="tear-context-panel">
          <h3>JavaScript startup observation</h3>
          ${javascriptTest ? renderJavascriptTest(javascriptTest) : '<p class="tear-empty">No matching instrumented JavaScript startup observation was retained.</p>'}
        </article>
      </div>
    </section>

    <section class="tear-section">
      <div class="tear-section-heading"><div><span>06</span><h2>Collection coverage</h2></div><p>How BLANCHE gathered the evidence and where collection was limited.</p></div>
      <div class="tear-capture-facts">
        <div><strong>${escapeHtml(report.captureProfile.mode)}</strong><span>Collection mode</span></div>
        <div><strong>${report.captureProfile.reloadTriggered ? 'Yes' : 'No'}</strong><span>Reload triggered</span></div>
        <div><strong>${escapeHtml(formatDuration(report.captureProfile.durationMs))}</strong><span>Elapsed collection</span></div>
        <div><strong>${report.captureProfile.frameCount}</strong><span>Frames</span></div>
      </div>
      <div class="tear-table-wrap"><table><thead><tr><th>Collector</th><th>Surface</th><th>Status</th><th>Warnings</th><th>Errors</th><th>Gaps</th></tr></thead><tbody>${collectorRows}</tbody></table></div>
      <details class="tear-details" data-disclosure-key="report-permissions">
        <summary>Permissions recorded with the capture</summary>
        <div class="tear-permission-grid">
          <div><strong>Granted extension permissions</strong><p>${renderStringList(report.captureProfile.permissions.grantedPermissions)}</p></div>
          <div><strong>Granted host permissions</strong><p>${renderStringList(report.captureProfile.permissions.grantedHostPermissions)}</p></div>
        </div>
      </details>
    </section>

    <section class="tear-section">
      <div class="tear-section-heading"><div><span>07</span><h2>Limitations and interpretation</h2></div><p>Required context for defensible stakeholder use.</p></div>
      <ul class="tear-limit-list">${limitations}</ul>
    </section>

    <section class="tear-section tear-artifact-appendix">
      <div class="tear-section-heading"><div><span>08</span><h2>Redacted evidence index</h2></div><p>One row per normalized artifact. Raw attributes and full values remain only in JSON evidence.</p></div>
      <div class="tear-table-wrap"><table><thead><tr><th>Evidence ID</th><th>Category</th><th>Kind / location</th><th>Frame</th><th>Provenance</th><th>Confidence</th></tr></thead><tbody>${artifactRows}</tbody></table></div>
    </section>

    <footer class="tear-footer">
      <div><strong>Report ID</strong><code>${escapeHtml(report.metadata.reportId)}</code></div>
      <div><strong>Source export</strong><code>${escapeHtml(report.metadata.sourceExportId)}</code></div>
      <p>Generated by BLANCHE. This tear sheet describes observed and inferred assessment evidence; it does not assign vulnerability validity or severity.</p>
    </footer>
    </div>`;
}

export function maskStakeholderUrl(rawUrl?: string): string | undefined {
  return maskUrl(rawUrl);
}

function renderObservation(observation: TearSheetObservation): string {
  return `
    <article class="tear-observation tear-observation-${escapeHtml(observation.tone)}">
      <div class="tear-observation-heading">
        <h3>${escapeHtml(observation.title)}</h3>
        <span>${observation.evidenceReferences.length} evidence ref${observation.evidenceReferences.length === 1 ? '' : 's'}</span>
      </div>
      <p>${escapeHtml(observation.summary)}</p>
      <small>${escapeHtml(observation.whyItMatters)}</small>
    </article>`;
}

function renderCategoryCard(category: TearSheetArtifactCategorySummary): string {
  const exampleLabels = category.examples
    .map((example) => escapeHtml(maskUrl(example.url) ?? example.kind))
    .join('<br />');
  return `
    <article class="tear-category">
      <div><strong>${category.count}</strong><h3>${escapeHtml(category.label)}</h3></div>
      <p>${category.provenance.observed} observed · ${category.provenance.inferred} inferred · ${category.provenance.unavailable} unavailable</p>
      ${exampleLabels ? `<small>${exampleLabels}</small>` : ''}
    </article>`;
}

function renderFindingCard(finding: JsonObject): string {
  const title = typeof finding.title === 'string' ? finding.title : 'Untitled finding';
  const summary = typeof finding.summary === 'string' ? finding.summary : '';
  const severity = typeof finding.severity === 'string' ? finding.severity : 'info';
  const status = typeof finding.status === 'string' ? finding.status : 'new';
  return `
    <div class="tear-context-item">
      <div><strong>${escapeHtml(title)}</strong><span class="tear-pill">${escapeHtml(severity)} · ${escapeHtml(status)}</span></div>
      ${summary ? `<p>${escapeHtml(summary)}</p>` : ''}
    </div>`;
}

function buildSearchRows(searchSessions: JsonObject[]): { count: number; markup: string } {
  const sessionRows: string[] = [];
  let taskCount = 0;
  for (const session of searchSessions) {
    const tasks = getJsonObjectArray(session.tasks);
    taskCount += tasks.length;
    const label = typeof session.label === 'string' ? session.label : 'Tracked search session';
    const rawMode =
      typeof session.mode === 'string'
        ? session.mode
        : session.automatic === true
          ? 'default-recipe'
          : 'classic';
    const mode = formatSearchMode(rawMode);
    const targets = uniqueStrings([
      ...getStringArray(session.targets),
      ...(typeof session.target === 'string' ? [session.target] : [])
    ]);
    const catalogReviewedAt =
      typeof session.catalogReviewedAt === 'string' ? session.catalogReviewedAt : undefined;
    const sessionWarnings = getStringArray(session.warnings);
    sessionRows.push(`
      <div class="tear-context-item">
        <div>
          <strong>${escapeHtml(label)}</strong>
          <span class="tear-pill">${escapeHtml(mode)}</span>
        </div>
        <p>${tasks.length} task${tasks.length === 1 ? '' : 's'}${
          targets.length > 0 ? ` · Targets: ${escapeHtml(targets.join(', '))}` : ''
        }</p>
        ${
          catalogReviewedAt
            ? `<small>Operator catalog reviewed ${escapeHtml(formatTimestamp(catalogReviewedAt))}</small>`
            : ''
        }
        ${
          sessionWarnings.length > 0
            ? `<p><strong>Session warnings:</strong> ${escapeHtml(sessionWarnings.join(' · '))}</p>`
            : ''
        }
        ${tasks.length > 0 ? tasks.map((task) => renderSearchTask(task, mode, targets)).join('') : '<small>No tasks were recorded for this session.</small>'}
      </div>`);
  }
  return { count: taskCount, markup: sessionRows.join('') };
}

function renderSearchTask(task: JsonObject, sessionMode: string, sessionTargets: string[]): string {
  const engine = typeof task.engineName === 'string' ? task.engineName : 'Search';
  const category = typeof task.category === 'string' ? task.category : 'custom';
  const status = typeof task.status === 'string' ? task.status : 'unknown';
  const resultCount =
    typeof task.resultCount === 'number' && Number.isFinite(task.resultCount)
      ? Math.max(0, Math.floor(task.resultCount))
      : getJsonObjectArray(task.results).length;
  const query = typeof task.query === 'string' ? task.query : '';
  const dialect =
    typeof task.dialect === 'string'
      ? task.dialect
      : typeof task.engineId === 'string'
        ? task.engineId
        : 'unspecified';
  const dorkId = typeof task.dorkId === 'string' ? task.dorkId : undefined;
  const dorkTitle = typeof task.dorkTitle === 'string' ? task.dorkTitle : undefined;
  const catalogReviewedAt =
    typeof task.catalogReviewedAt === 'string' ? task.catalogReviewedAt : undefined;
  const operatorIds = getStringArray(task.operatorIds);
  const taskTargets = uniqueStrings([
    ...getStringArray(task.targets),
    ...(typeof task.target === 'string' ? [task.target] : []),
    ...sessionTargets
  ]);
  const nerdSurface = isJsonObject(task.nerdSurface) ? task.nerdSurface : undefined;
  const surfaceName =
    typeof nerdSurface?.name === 'string' && nerdSurface.name.trim().length > 0
      ? nerdSurface.name
      : undefined;
  const surfaceMode =
    typeof nerdSurface?.mode === 'string' && nerdSurface.mode.trim().length > 0
      ? nerdSurface.mode
      : undefined;
  const surfaceMethod =
    typeof nerdSurface?.method === 'string' && nerdSurface.method.trim().length > 0
      ? nerdSurface.method
      : undefined;
  const destination = surfaceName
    ? `${surfaceName} · NERD ${formatSearchMode(surfaceMode ?? 'surface')}${
        surfaceMethod ? ` · ${surfaceMethod.toUpperCase()}` : ''
      }`
    : `${engine} · engine`;
  const warnings = uniqueStrings([
    ...getStringArray(task.warnings),
    ...(typeof task.manualReason === 'string' ? [task.manualReason] : []),
    ...(typeof task.error === 'string' ? [task.error] : [])
  ]);

  return `
    <article class="tear-details">
      <div>
        <strong>${escapeHtml(dorkTitle ?? category)}</strong>
        <span class="tear-pill">${escapeHtml(status)}</span>
      </div>
      <p><strong>Session mode:</strong> ${escapeHtml(sessionMode)} · <strong>Destination:</strong> ${escapeHtml(destination)}</p>
      <p><strong>Dialect:</strong> ${escapeHtml(dialect)} · <strong>Results:</strong> ${resultCount}</p>
      ${dorkId ? `<small>Dork ID: ${escapeHtml(dorkId)}</small>` : ''}
      <small>Operator IDs: ${operatorIds.length > 0 ? escapeHtml(operatorIds.join(', ')) : 'none recorded'}</small>
      ${taskTargets.length > 0 ? `<small>Targets: ${escapeHtml(taskTargets.join(', '))}</small>` : ''}
      ${catalogReviewedAt ? `<small>Operator catalog reviewed ${escapeHtml(formatTimestamp(catalogReviewedAt))}</small>` : ''}
      <p><strong>Exact query</strong><br /><code>${escapeHtml(query)}</code></p>
      ${
        warnings.length > 0
          ? `<p><strong>Warnings / outcome notes:</strong> ${escapeHtml(warnings.join(' · '))}</p>`
          : '<small>Warnings: none recorded</small>'
      }
    </article>`;
}

function formatSearchMode(rawMode: string): string {
  const normalized = rawMode.trim().toLowerCase();
  if (normalized === 'nerd' || normalized === 'nerd-mode') {
    return 'NERD mode';
  }
  if (normalized === 'dork-suite') {
    return 'Dork suite';
  }
  if (normalized === 'default-recipe') {
    return 'Default recipe';
  }
  if (normalized === 'form') {
    return 'form';
  }
  if (normalized === 'get') {
    return 'GET';
  }
  if (normalized === 'template') {
    return 'URL template';
  }
  return rawMode || 'Classic';
}

function getStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter(
        (entry): entry is string => typeof entry === 'string' && entry.trim().length > 0
      )
    : [];
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function renderDocumentRow(document: JsonObject): string {
  const filename =
    typeof document.filename === 'string'
      ? document.filename
      : typeof document.url === 'string'
        ? maskUrl(document.url) ?? 'Document'
        : 'Document';
  const status = typeof document.status === 'string' ? document.status : 'unknown';
  const mimeType = typeof document.mimeType === 'string' ? document.mimeType : 'type unknown';
  const sha256 = typeof document.sha256 === 'string' ? document.sha256 : undefined;
  const analysis = isJsonObject(document.analysis) ? document.analysis : undefined;
  const keywordCount = getJsonObjectArray(analysis?.interestingKeywords).length;
  const extractedUrlCount = Array.isArray(analysis?.extractedUrls) ? analysis.extractedUrls.length : 0;
  return `
    <div class="tear-context-item">
      <div><strong>${escapeHtml(filename)}</strong><span>${escapeHtml(status)}</span></div>
      <p>${escapeHtml(mimeType)} · ${keywordCount} keyword hit${keywordCount === 1 ? '' : 's'} · ${extractedUrlCount} extracted URL${extractedUrlCount === 1 ? '' : 's'}</p>
      ${sha256 ? `<small>SHA-256 ${escapeHtml(sha256)}</small>` : ''}
    </div>`;
}

function renderLatentFeature(candidate: JsonObject): string {
  const key = typeof candidate.key === 'string' ? candidate.key : 'Unnamed candidate';
  const confidence = typeof candidate.confidence === 'string' ? candidate.confidence : 'unknown';
  const surface = typeof candidate.controlSurface === 'string' ? candidate.controlSurface : 'unknown surface';
  return `
    <div class="tear-context-item">
      <div><strong>${escapeHtml(key)}</strong><span>${escapeHtml(confidence)}</span></div>
      <p>${escapeHtml(surface)} · ${candidate.probeable === true ? 'locally probeable' : 'observation only'}</p>
    </div>`;
}

function renderScriptAssessment(assessment: JsonObject): string {
  const artifact = isJsonObject(assessment.artifact) ? assessment.artifact : {};
  const transform = isJsonObject(assessment.transform) ? assessment.transform : {};
  const coverage = isJsonObject(assessment.coverage) ? assessment.coverage : {};
  const priority = isJsonObject(assessment.reviewPriority) ? assessment.reviewPriority : {};
  const label = typeof artifact.label === 'string' ? artifact.label : 'Delivered script';
  const sourceUrl =
    typeof artifact.finalUrl === 'string'
      ? artifact.finalUrl
      : typeof artifact.sourceUrl === 'string'
        ? artifact.sourceUrl
        : undefined;
  const detected = Array.isArray(transform.detected)
    ? transform.detected.filter((value): value is string => typeof value === 'string').slice(0, 5)
    : [];
  const purposes = getJsonObjectArray(assessment.purposeClaims)
    .filter((claim) => claim.role === 'primary' || claim.role === 'secondary')
    .map((claim) => (typeof claim.category === 'string' ? claim.category : undefined))
    .filter((value): value is string => Boolean(value))
    .slice(0, 4);
  const score = typeof priority.score === 'number' ? priority.score : 0;
  const band = typeof priority.band === 'string' ? priority.band : 'unknown';
  const coverageStatus = typeof coverage.status === 'string' ? coverage.status : 'unknown';
  return `
    <div class="tear-context-item">
      <div><strong>${escapeHtml(label)}</strong><span>priority ${score} · ${escapeHtml(band)}</span></div>
      <p>${escapeHtml(detected.join(', ') || 'transform unknown')} · ${escapeHtml(purposes.join(', ') || 'purpose unknown')} · ${escapeHtml(coverageStatus)} coverage</p>
      ${sourceUrl ? `<small>${escapeHtml(maskUrl(sourceUrl) ?? '')}</small>` : ''}
      <small>Review priority is not vulnerability severity.</small>
    </div>`;
}

function renderJavascriptTest(test: JsonObject): string {
  const status = typeof test.overallStatus === 'string' ? test.overallStatus : 'unknown';
  const completedAt = typeof test.completedAt === 'string' ? formatTimestamp(test.completedAt) : 'unknown time';
  const cells = getJsonObjectArray(test.cells);
  const runtimeStats = isJsonObject(test.runtimeStats) ? test.runtimeStats : {};
  const eventCount = typeof runtimeStats.eventCount === 'number' ? runtimeStats.eventCount : 0;
  const observedCount = cells.filter((cell) => cell.status === 'observed').length;
  const unverifiedObservedCount = cells.filter(
    (cell) => cell.status === 'observed-unverified'
  ).length;
  const staticOnlyCount = cells.filter((cell) => cell.status === 'static-only').length;
  const blockedCount = cells.filter(
    (cell) =>
      cell.status === 'blocked' || cell.status === 'manual-required' || cell.status === 'failed'
  ).length;
  const scopeDisposition =
    typeof test.scopeDisposition === 'string' ? test.scopeDisposition : 'unknown';
  const scopePolicyId = typeof test.scopePolicyId === 'string' ? test.scopePolicyId : 'unknown';
  const scopePolicyVersion =
    typeof test.scopePolicyVersion === 'string' ? test.scopePolicyVersion : '';
  const instrumentationIntegrity =
    typeof test.instrumentationIntegrity === 'string' ? test.instrumentationIntegrity : 'none';
  return `
    <div class="tear-context-item">
      <div><strong>${escapeHtml(status)}</strong><span>${escapeHtml(completedAt)}</span></div>
      <p>${eventCount} bounded runtime event${eventCount === 1 ? '' : 's'} · ${observedCount} extension-verified cell${observedCount === 1 ? '' : 's'} · ${unverifiedObservedCount} page-world-unverified cell${unverifiedObservedCount === 1 ? '' : 's'} · ${staticOnlyCount} static-only cell${staticOnlyCount === 1 ? '' : 's'} · ${blockedCount} blocked, failed, or manual cell${blockedCount === 1 ? '' : 's'}</p>
      <small>Scope: ${escapeHtml(scopeDisposition)} · policy ${escapeHtml(scopePolicyId)} ${escapeHtml(scopePolicyVersion)} · instrumentation integrity: ${escapeHtml(instrumentationIntegrity)}</small>
      ${cells.slice(0, 12).map((cell) => `
        <small>${escapeHtml(typeof cell.title === 'string' ? cell.title : 'Test cell')}: ${escapeHtml(typeof cell.status === 'string' ? cell.status : 'unknown')}</small>
      `).join('')}
      <small>${status === 'failed' ? 'The startup attempt failed before a complete observation was retained.' : 'One startup reload was observed; unobserved and interactive paths remain outside this run.'}</small>
      ${instrumentationIntegrity === 'page-world-unverified' ? '<small>Same-window page instrumentation can be fabricated or suppressed by the inspected page and is not per-script runtime proof.</small>' : ''}
    </div>`;
}

function renderArtifactRow(artifact: ArtifactDescriptor): string {
  const location = maskUrl(artifact.url) ?? artifact.kind;
  return `
    <tr>
      <td><code>${escapeHtml(artifact.artifactId)}</code></td>
      <td>${escapeHtml(getArtifactCategoryLabel(artifact.category))}</td>
      <td><strong>${escapeHtml(artifact.kind)}</strong><small>${escapeHtml(location)}</small></td>
      <td>${artifact.frameId ?? '—'}</td>
      <td>${escapeHtml(artifact.provenance.disposition)}</td>
      <td>${escapeHtml(artifact.provenance.confidence)}</td>
    </tr>`;
}

function maskUrl(rawUrl?: string): string | undefined {
  if (!rawUrl) {
    return undefined;
  }
  if (/^data:/i.test(rawUrl)) {
    const mediaType = rawUrl.slice(5).split(/[;,]/, 1)[0];
    return `data:${mediaType || 'content'};[payload omitted]`;
  }
  try {
    const parsed = new URL(rawUrl);
    parsed.pathname = parsed.pathname
      .split('/')
      .map((segment) => (isSensitivePathSegment(segment) ? '[segment omitted]' : segment))
      .join('/');
    if (parsed.search) {
      parsed.search = '?[query omitted]';
    }
    if (parsed.hash) {
      parsed.hash = '#[fragment omitted]';
    }
    if (parsed.username || parsed.password) {
      parsed.username = '[credentials omitted]';
      parsed.password = '';
    }
    return parsed.toString();
  } catch {
    return rawUrl.length > 180 ? `${rawUrl.slice(0, 177)}…` : rawUrl;
  }
}

function isSensitivePathSegment(rawSegment: string): boolean {
  let segment = rawSegment;
  try {
    segment = decodeURIComponent(rawSegment);
  } catch {
    // Keep the encoded segment for conservative pattern matching.
  }
  if (/^(?:access[_-]?token|auth|bearer|credential|jwt|password|secret|session)(?:[=:_-].*)?$/i.test(segment)) {
    return true;
  }
  if (segment.length >= 32 && /^[a-z0-9+/_=-]+$/i.test(segment)) {
    return true;
  }
  return segment.split('.').length === 3 && segment.length >= 40;
}

function renderStringList(items: string[]): string {
  return items.length > 0 ? items.map((item) => `<code>${escapeHtml(item)}</code>`).join(' ') : 'None recorded';
}

function formatTimestamp(timestamp: string): string {
  if (/^\d{4}-\d{2}-\d{2}$/.test(timestamp)) {
    return timestamp;
  }
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? timestamp : date.toLocaleString();
}

function formatDuration(durationMs?: number): string {
  if (durationMs === undefined) {
    return 'Unknown';
  }
  if (durationMs < 1000) {
    return `${durationMs} ms`;
  }
  return `${(durationMs / 1000).toFixed(durationMs < 10000 ? 1 : 0)} s`;
}

function getJsonObjectArray(value: unknown): JsonObject[] {
  return Array.isArray(value) ? value.filter(isJsonObject) : [];
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

const TEAR_SHEET_DOCUMENT_CSS = `
  :root { color-scheme: light; --ink:#172126; --muted:#617078; --paper:#f5f7f6; --card:#fff; --line:#d8e0dd; --accent:#157a5b; --accent-soft:#e5f4ee; --warn:#9a6416; --warn-soft:#fff3d9; --danger:#a53d44; --danger-soft:#fdebec; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--paper); color:var(--ink); font:15px/1.55 "Segoe UI", Inter, Arial, sans-serif; }
  .tear-document { width:min(1180px, calc(100% - 40px)); margin:0 auto; padding:38px 0 54px; }
  h1,h2,h3,p,dl,dd { margin:0; }
  h1 { font-size:clamp(2.2rem,6vw,4.8rem); line-height:.98; letter-spacing:-.045em; }
  h2 { font-size:1.45rem; letter-spacing:-.02em; }
  h3 { font-size:1rem; }
  code { font:0.82em/1.45 ui-monospace,SFMono-Regular,Consolas,monospace; overflow-wrap:anywhere; }
  small { display:block; color:var(--muted); }
  .tear-hero,.tear-section,.tear-sensitive-banner,.tear-footer { background:var(--card); border:1px solid var(--line); border-radius:14px; }
  .tear-hero { padding:clamp(24px,5vw,54px); border-top:5px solid var(--accent); }
  .tear-kicker { color:var(--accent); font-size:.78rem; font-weight:800; letter-spacing:.16em; text-transform:uppercase; margin-bottom:30px; }
  .tear-hero-grid { display:grid; grid-template-columns:minmax(0,1.5fr) minmax(250px,.5fr); gap:40px; align-items:start; }
  .tear-lead { color:var(--muted); font-size:1.08rem; margin-top:14px; max-width:60ch; }
  .tear-identity { display:grid; gap:12px; }
  .tear-identity div { display:grid; grid-template-columns:90px 1fr; gap:12px; border-bottom:1px solid var(--line); padding-bottom:9px; }
  .tear-identity dt { color:var(--muted); }
  .tear-identity dd { font-weight:700; }
  .tear-target-line { display:flex; flex-wrap:wrap; justify-content:space-between; gap:10px 18px; padding:15px 0; margin:30px 0 16px; border-top:1px solid var(--line); border-bottom:1px solid var(--line); }
  .tear-target-line code { color:var(--accent); }
  .tear-sensitive-banner { display:flex; gap:16px; margin:18px 0; padding:16px 20px; background:var(--warn-soft); border-color:#edcc8f; }
  .tear-sensitive-banner strong { color:var(--warn); white-space:nowrap; }
  .tear-section { margin-top:18px; padding:26px; }
  .tear-section-heading { display:flex; justify-content:space-between; gap:24px; align-items:flex-start; margin-bottom:20px; }
  .tear-section-heading > div { display:flex; gap:12px; align-items:center; }
  .tear-section-heading > div > span { display:inline-grid; place-items:center; width:32px; height:32px; border-radius:50%; background:var(--accent-soft); color:var(--accent); font-weight:800; }
  .tear-section-heading > p { max-width:48ch; color:var(--muted); text-align:right; }
  .tear-metric-grid,.tear-category-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; }
  .tear-metric,.tear-category,.tear-context-panel { border:1px solid var(--line); border-radius:10px; padding:16px; background:#fbfcfb; }
  .tear-metric > strong,.tear-category > div > strong { display:block; color:var(--accent); font-size:2rem; line-height:1; }
  .tear-metric h3,.tear-category h3 { margin:7px 0; }
  .tear-metric p,.tear-category p { color:var(--muted); font-size:.88rem; }
  .tear-category small { margin-top:9px; overflow-wrap:anywhere; }
  .tear-provenance-row { display:flex; flex-wrap:wrap; gap:12px; margin-top:14px; }
  .tear-provenance-row span { padding:7px 10px; border-radius:7px; background:var(--accent-soft); }
  .tear-observation-list { display:grid; gap:12px; }
  .tear-observation { border:1px solid var(--line); border-left:4px solid var(--accent); border-radius:9px; padding:16px; }
  .tear-observation-attention { border-left-color:var(--warn); background:#fffdfa; }
  .tear-observation-heading,.tear-context-item > div,.tear-limit-heading { display:flex; justify-content:space-between; gap:16px; align-items:flex-start; }
  .tear-observation-heading span,.tear-context-item span { color:var(--muted); font-size:.82rem; white-space:nowrap; }
  .tear-observation p { margin:7px 0; }
  .tear-pill { display:inline-flex; padding:2px 8px; border:1px solid var(--line); border-radius:999px; font-size:.78rem; text-transform:capitalize; }
  .tear-assessment-healthy,.tear-status-ok { color:var(--accent); background:var(--accent-soft); border-color:#b6ddce; }
  .tear-assessment-limited,.tear-status-partial { color:var(--warn); background:var(--warn-soft); border-color:#edcc8f; }
  .tear-assessment-degraded,.tear-status-error { color:var(--danger); background:var(--danger-soft); border-color:#edb6ba; }
  .tear-table-wrap { overflow:auto; border:1px solid var(--line); border-radius:10px; }
  table { width:100%; border-collapse:collapse; min-width:720px; }
  th,td { padding:11px 12px; text-align:left; vertical-align:top; border-bottom:1px solid var(--line); }
  th { color:var(--muted); font-size:.75rem; letter-spacing:.06em; text-transform:uppercase; background:#f5f8f7; }
  tr:last-child td { border-bottom:0; }
  td small { max-width:460px; overflow-wrap:anywhere; }
  .tear-context-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; }
  .tear-context-panel h3 { display:flex; justify-content:space-between; margin-bottom:12px; }
  .tear-context-panel h3 span { color:var(--accent); }
  .tear-context-item { padding:12px 0; border-top:1px solid var(--line); }
  .tear-context-item:first-of-type { border-top:0; padding-top:0; }
  .tear-context-item p { margin-top:5px; color:var(--muted); }
  .tear-capture-facts { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px; margin-bottom:14px; }
  .tear-capture-facts div { border:1px solid var(--line); border-radius:8px; padding:12px; }
  .tear-capture-facts strong { display:block; font-size:1.1rem; text-transform:capitalize; }
  .tear-capture-facts span { color:var(--muted); font-size:.82rem; }
  .tear-details { margin-top:14px; border:1px solid var(--line); border-radius:9px; padding:12px 14px; }
  .tear-details summary { cursor:pointer; font-weight:700; }
  .tear-permission-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; margin-top:12px; }
  .tear-permission-grid p { display:flex; gap:6px; flex-wrap:wrap; margin-top:7px; }
  .tear-permission-grid code { padding:3px 6px; background:var(--paper); border-radius:5px; }
  .tear-limit-list { list-style:none; margin:0; padding:0; display:grid; gap:10px; }
  .tear-limit-list li { border:1px solid var(--line); border-radius:9px; padding:14px; }
  .tear-limit-list p { margin-top:6px; color:var(--muted); }
  .tear-empty { color:var(--muted); padding:10px 0; }
  .tear-footer { margin-top:18px; padding:20px 24px; display:grid; gap:8px; color:var(--muted); }
  .tear-footer div { display:flex; gap:12px; }
  @media (max-width:850px) { .tear-hero-grid,.tear-context-grid { grid-template-columns:1fr; } .tear-metric-grid,.tear-category-grid,.tear-capture-facts { grid-template-columns:repeat(2,minmax(0,1fr)); } .tear-section-heading { display:block; } .tear-section-heading > p { margin-top:8px; text-align:left; } }
  @media (max-width:520px) { .tear-document { width:min(100% - 20px,1180px); padding:10px 0 28px; } .tear-metric-grid,.tear-category-grid,.tear-capture-facts,.tear-permission-grid { grid-template-columns:1fr; } .tear-sensitive-banner { display:grid; } }
  @media print { body { background:#fff; font-size:10.5pt; } .tear-document { width:100%; padding:0; } .tear-hero,.tear-section,.tear-sensitive-banner,.tear-footer { break-inside:avoid; box-shadow:none; } .tear-artifact-appendix { break-before:page; } .tear-details { display:block; } }
`;
