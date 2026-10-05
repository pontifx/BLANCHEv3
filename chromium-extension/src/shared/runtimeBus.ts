import type {
  BlancheTrafficLedgerV1,
  JsonObject,
  JsonValue,
  TrafficLedgerSummary
} from '../../../shared-schema/src';
import type {
  HostStateSnapshot,
  ModuleActionResult,
  RuntimeCallerSurface,
  TrafficLedgerQuery,
  TrafficLedgerQueryResult
} from './contracts';
import type { EngagementProfilesState } from './engagementProfiles';
import type { InterestWorkbenchState } from './interestWorkbench';
import type { SearchWorkbenchState } from './searchWorkbench';
import type { SearchExecutionSettings } from './searchExecution';
import type { NerdSearchCandidate } from './nerdSearch';

export interface RuntimeMessageMap {
  'core/getState': {
    request: {
      includeLogs?: boolean;
    };
    response: HostStateSnapshot;
  };
  'core/toggleModule': {
    request: {
      moduleId: string;
      enabled: boolean;
    };
    response: HostStateSnapshot;
  };
  'core/updateModuleSettings': {
    request: {
      moduleId: string;
      settings: Record<string, JsonValue>;
    };
    response: HostStateSnapshot;
  };
  'core/updateSearchWorkbench': {
    request: {
      searchWorkbench: SearchWorkbenchState;
    };
    response: HostStateSnapshot;
  };
  'core/startSearchSession': {
    request: {
      useDefaultRecipe?: boolean;
      tabId?: number;
    };
    response: HostStateSnapshot;
  };
  'core/startDorkSuite': {
    request: {
      tabId?: number;
    };
    response: HostStateSnapshot;
  };
  'core/discoverNerdSearchSurfaces': {
    request: {
      tabId: number;
    };
    response: {
      surfaces: NerdSearchCandidate[];
    };
  };
  'core/highlightNerdSearchSurface': {
    request: {
      tabId: number;
      inputSelector: string;
    };
    response: {
      highlighted: boolean;
      topFrameOnly: true;
      reason?: string;
    };
  };
  'core/pickNerdSearchSurface': {
    request: {
      tabId: number;
    };
    response: {
      surface?: NerdSearchCandidate;
      selector?: string;
      topFrameOnly: true;
      reason?: string;
    };
  };
  'core/startNerdSuite': {
    request: {
      surfaceId: string;
      tabId?: number;
    };
    response: HostStateSnapshot;
  };
  'core/updateSearchExecutionSettings': {
    request: {
      settings: Partial<SearchExecutionSettings>;
    };
    response: HostStateSnapshot;
  };
  'core/answerTesterQuestion': {
    request: {
      questionId: string;
      actionId: string;
      tabId?: number;
    };
    response: HostStateSnapshot;
  };
  'core/updateInterestWorkbench': {
    request: {
      interestWorkbench: InterestWorkbenchState;
    };
    response: HostStateSnapshot;
  };
  'core/runInterestAction': {
    request: {
      action: 'analyze' | 'create-folder' | 'bookmark-tab';
      tabId?: number;
    };
    response: HostStateSnapshot;
  };
  'core/updateEngagementProfiles': {
    request: {
      engagementProfiles: EngagementProfilesState;
    };
    response: HostStateSnapshot;
  };
  'core/activateEngagementProfile': {
    request: {
      profileId: string;
    };
    response: HostStateSnapshot;
  };
  'core/runAction': {
    request: {
      moduleId: string;
      actionId: string;
      tabId?: number;
      caller: RuntimeCallerSurface;
      input?: JsonObject;
    };
    response: ModuleActionResult;
  };
  'traffic/query': {
    request: TrafficLedgerQuery;
    response: TrafficLedgerQueryResult;
  };
  'traffic/export': {
    request: {
      sourceSessionId?: string;
      tabId?: number;
      targetOrigin?: string;
      since?: string;
      limit?: number;
    };
    response: BlancheTrafficLedgerV1;
  };
  'traffic/updateSettings': {
    request: {
      enabled?: boolean;
      maxEntries?: number;
    };
    response: TrafficLedgerSummary;
  };
  'traffic/clear': {
    request: Record<string, never>;
    response: TrafficLedgerSummary;
  };
}

export interface RuntimeEnvelope<TType extends keyof RuntimeMessageMap = keyof RuntimeMessageMap> {
  channel: 'blanche';
  type: TType;
  payload: RuntimeMessageMap[TType]['request'];
}

export type RuntimeResponseEnvelope<TType extends keyof RuntimeMessageMap> =
  | {
      ok: true;
      payload: RuntimeMessageMap[TType]['response'];
    }
  | {
      ok: false;
      error: string;
    };

export function isRuntimeEnvelope(message: unknown): message is RuntimeEnvelope {
  return (
    typeof message === 'object' &&
    message !== null &&
    'channel' in message &&
    (message as { channel?: string }).channel === 'blanche' &&
    'type' in message &&
    'payload' in message
  );
}

export async function sendRuntimeMessage<TType extends keyof RuntimeMessageMap>(
  type: TType,
  payload: RuntimeMessageMap[TType]['request']
): Promise<RuntimeMessageMap[TType]['response']> {
  const envelope: RuntimeEnvelope<TType> = {
    channel: 'blanche',
    type,
    payload
  };

  const response = (await chrome.runtime.sendMessage(envelope)) as RuntimeResponseEnvelope<TType>;
  if (!response.ok) {
    throw new Error(response.error);
  }

  return response.payload;
}
