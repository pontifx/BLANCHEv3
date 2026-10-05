import type { JsonValue, ScopePolicy } from '../../../shared-schema/src';
import { normalizeScopePolicy } from './scopePolicy';

/**
 * A named, operator-authored bundle of settings across every module, so starting a session is
 * "pick a profile" instead of hand-tuning a dozen toggles. The structured scope policy is the
 * executable source of truth; scopeNotes remains operator context only.
 */
export interface EngagementProfile {
  id: string;
  name: string;
  scopeNotes: string;
  scopePolicy: ScopePolicy;
  moduleSettings: Record<string, Record<string, JsonValue>>;
  enabledModuleIds: string[];
  createdAt: string;
  updatedAt: string;
}

export interface EngagementProfilesState {
  savedProfiles: EngagementProfile[];
  activeProfileId?: string;
  activatedAt?: string;
}

export function createDefaultEngagementProfilesState(): EngagementProfilesState {
  return {
    savedProfiles: []
  };
}

export function normalizeEngagementProfilesState(rawValue: unknown): EngagementProfilesState {
  const fallback = createDefaultEngagementProfilesState();
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return fallback;
  }

  const source = rawValue as Partial<EngagementProfilesState>;
  const savedProfiles = Array.isArray(source.savedProfiles)
    ? source.savedProfiles
        .map((entry) => normalizeEngagementProfile(entry))
        .filter((entry): entry is EngagementProfile => Boolean(entry))
    : [];

  const activeProfileId =
    typeof source.activeProfileId === 'string' &&
    savedProfiles.some((profile) => profile.id === source.activeProfileId)
      ? source.activeProfileId
      : undefined;

  return {
    savedProfiles,
    activeProfileId,
    activatedAt:
      activeProfileId && typeof source.activatedAt === 'string'
        ? source.activatedAt
        : undefined
  };
}

export function createEngagementProfile(input: {
  name: string;
  scopeNotes: string;
  scopePolicy?: ScopePolicy;
  moduleSettings: Record<string, Record<string, JsonValue>>;
  enabledModuleIds: string[];
}): EngagementProfile {
  const timestamp = new Date().toISOString();
  const id = createEngagementProfileId();
  return {
    id,
    name: input.name.trim(),
    scopeNotes: input.scopeNotes.trim(),
    scopePolicy: input.scopePolicy
      ? normalizeProfileScopePolicy(input.scopePolicy, id)
      : createDefaultScopePolicy(id),
    moduleSettings: input.moduleSettings,
    enabledModuleIds: [...new Set(input.enabledModuleIds)],
    createdAt: timestamp,
    updatedAt: timestamp
  };
}

function normalizeEngagementProfile(rawValue: unknown): EngagementProfile | undefined {
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return undefined;
  }

  const source = rawValue as Partial<EngagementProfile>;
  const name = typeof source.name === 'string' ? source.name.trim() : '';
  if (!name) {
    return undefined;
  }

  const id =
    typeof source.id === 'string' && source.id.trim().length > 0
      ? source.id
      : createEngagementProfileId();

  return {
    id,
    name,
    scopeNotes: typeof source.scopeNotes === 'string' ? source.scopeNotes : '',
    scopePolicy: normalizeProfileScopePolicy(source.scopePolicy, id),
    moduleSettings: isModuleSettingsMap(source.moduleSettings) ? source.moduleSettings : {},
    enabledModuleIds: Array.isArray(source.enabledModuleIds)
      ? source.enabledModuleIds.filter((entry): entry is string => typeof entry === 'string')
      : [],
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

export function createDefaultScopePolicy(profileId = 'unconfigured'): ScopePolicy {
  return {
    policyId: `engagement:${profileId}`,
    version: '1',
    defaultDisposition: 'review',
    evaluation: 'highest-priority-exclude-on-tie',
    rules: []
  };
}

function normalizeProfileScopePolicy(rawValue: unknown, profileId: string): ScopePolicy {
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return createDefaultScopePolicy(profileId);
  }

  try {
    return normalizeScopePolicy(rawValue as ScopePolicy);
  } catch {
    return createDefaultScopePolicy(profileId);
  }
}

function isModuleSettingsMap(value: unknown): value is Record<string, Record<string, JsonValue>> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function createEngagementProfileId(): string {
  return `profile_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}
