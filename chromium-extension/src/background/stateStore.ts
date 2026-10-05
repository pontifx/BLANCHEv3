import type { BlancheExportV1, JsonValue } from '../../../shared-schema/src';
import type {
  CollectionSessionRecord,
  FeedEntry,
  ModuleDefinition,
  ModulePersistedState
} from '../shared/contracts';
import {
  createDefaultInterestWorkbenchState,
  normalizeInterestWorkbenchState,
  type InterestWorkbenchState
} from '../shared/interestWorkbench';
import {
  createDefaultSearchWorkbenchState,
  normalizeSearchWorkbenchState,
  type SearchWorkbenchState
} from '../shared/searchWorkbench';
import {
  createDefaultDocumentWorkbenchState,
  normalizeDocumentWorkbenchState,
  type DocumentWorkbenchState
} from '../shared/documentWorkbench';
import {
  createDefaultEngagementProfilesState,
  normalizeEngagementProfilesState,
  type EngagementProfilesState
} from '../shared/engagementProfiles';
import {
  createDefaultLatentFeatureWorkbenchState,
  normalizeLatentFeatureWorkbenchState,
  type LatentFeatureWorkbenchState
} from '../shared/latentFeatureWorkbench';
import {
  createDefaultSearchExecutionState,
  normalizeSearchExecutionState,
  type SearchExecutionState
} from '../shared/searchExecution';
import {
  createDefaultFindingsWorkbenchState,
  normalizeFindingsWorkbenchState,
  type FindingsWorkbenchState
} from '../shared/findingsWorkbench';

const STORAGE_KEY = 'blanche.hostState.v1';

export interface PersistedHostState {
  modules: Record<string, ModulePersistedState>;
  sessions: CollectionSessionRecord[];
  searchWorkbench: SearchWorkbenchState;
  searchExecution: SearchExecutionState;
  findingsWorkbench: FindingsWorkbenchState;
  interestWorkbench: InterestWorkbenchState;
  documentWorkbench: DocumentWorkbenchState;
  engagementProfiles: EngagementProfilesState;
  latentFeatureWorkbench: LatentFeatureWorkbenchState;
  feed: FeedEntry[];
  /** Hostnames already auto-seeded into OSINT, so first-sight-of-a-new-host only fires once. */
  seededHostnames: string[];
  lastExport?: BlancheExportV1;
}

export class StateStore {
  async load(modules: ModuleDefinition[]): Promise<PersistedHostState> {
    const stored = (await chrome.storage.local.get(STORAGE_KEY))[STORAGE_KEY] as
      | PersistedHostState
      | undefined;

    const normalizedModules: Record<string, ModulePersistedState> = {};

    for (const module of modules) {
      const existingState = stored?.modules[module.descriptor.id];
      normalizedModules[module.descriptor.id] = {
        enabled: existingState?.enabled ?? true,
        settings: {
          ...buildDefaultSettings(module.descriptor),
          ...(existingState?.settings ?? {})
        }
      };
    }

    return {
      modules: normalizedModules,
      sessions: stored?.sessions ?? [],
      searchWorkbench: normalizeSearchWorkbenchState(
        stored?.searchWorkbench ?? createDefaultSearchWorkbenchState()
      ),
      searchExecution: normalizeSearchExecutionState(
        stored?.searchExecution ?? createDefaultSearchExecutionState()
      ),
      findingsWorkbench: normalizeFindingsWorkbenchState(
        stored?.findingsWorkbench ?? createDefaultFindingsWorkbenchState()
      ),
      interestWorkbench: normalizeInterestWorkbenchState(
        stored?.interestWorkbench ?? createDefaultInterestWorkbenchState()
      ),
      documentWorkbench: normalizeDocumentWorkbenchState(
        stored?.documentWorkbench ?? createDefaultDocumentWorkbenchState()
      ),
      engagementProfiles: normalizeEngagementProfilesState(
        stored?.engagementProfiles ?? createDefaultEngagementProfilesState()
      ),
      latentFeatureWorkbench: normalizeLatentFeatureWorkbenchState(
        stored?.latentFeatureWorkbench ?? createDefaultLatentFeatureWorkbenchState()
      ),
      feed: stored?.feed ?? [],
      seededHostnames: stored?.seededHostnames ?? [],
      lastExport: stored?.lastExport
    };
  }

  async save(state: PersistedHostState): Promise<void> {
    await chrome.storage.local.set({
      [STORAGE_KEY]: state
    });
  }
}

export function buildDefaultSettings(
  descriptor: ModuleDefinition['descriptor']
): Record<string, JsonValue> {
  return descriptor.settingsSchema.reduce<Record<string, JsonValue>>((accumulator, field) => {
    accumulator[field.key] = field.defaultValue;
    return accumulator;
  }, {});
}
