import {
  BLANCHE_EXPORT_KIND,
  BLANCHE_SCHEMA_VERSION,
  type BlancheExportV1,
  type ExportWarning
} from '../../../shared-schema/src';
import type { ExportBuildInput } from '../shared/contracts';
import { createId } from '../shared/helpers';

export class ExportBuilder {
  build(input: ExportBuildInput): BlancheExportV1 {
    const collectorWarnings = input.collectors.flatMap((collector) => collector.warnings);
    const collectorErrors = input.collectors.flatMap((collector) => collector.errors);
    const collectorVisibilityGaps = input.collectors.flatMap((collector) => collector.visibilityGaps);
    const warnings = dedupeWarnings([...input.warnings, ...collectorWarnings]);
    const errors = [...input.errors, ...collectorErrors];
    const visibilityGaps = [...input.visibilityGaps, ...collectorVisibilityGaps];
    const artifactCountsByCategory = input.artifacts.reduce<Record<string, number>>(
      (accumulator, artifact) => {
        accumulator[artifact.category] = (accumulator[artifact.category] ?? 0) + 1;
        return accumulator;
      },
      {}
    );

    return {
      kind: BLANCHE_EXPORT_KIND,
      schemaVersion: BLANCHE_SCHEMA_VERSION,
      exportMetadata: {
        exportId: createId('export'),
        exportedAt: new Date().toISOString(),
        generatedBy: {
          product: 'BLANCHE',
          component: input.component,
          version: input.hostVersion,
          moduleId: input.module.id,
          moduleVersion: input.module.version
        }
      },
      module: input.module,
      page: input.page,
      collection: input.collection,
      permissions: input.permissions,
      collectors: input.collectors,
      artifacts: input.artifacts,
      trafficLedger: input.trafficLedger,
      warnings,
      errors,
      visibilityGaps,
      summary: {
        artifactCount: input.artifacts.length,
        artifactCountsByCategory,
        warningCount: warnings.length,
        errorCount: errors.length,
        visibilityGapCount: visibilityGaps.length
      }
    };
  }
}

function dedupeWarnings(warnings: ExportWarning[]): ExportWarning[] {
  const seen = new Set<string>();
  return warnings.filter((warning) => {
    const key = `${warning.collectorId ?? 'core'}:${warning.code}:${warning.message}`;
    if (seen.has(key)) {
      return false;
    }

    seen.add(key);
    return true;
  });
}
