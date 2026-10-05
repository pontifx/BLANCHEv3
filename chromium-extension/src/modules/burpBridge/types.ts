import type { CollectionMode, JsonObject } from '../../../../shared-schema/src';

export interface BurpBridgeSettings {
  defaultMode: CollectionMode;
  reloadBeforeCollect: boolean;
  autoCaptureOnNavigation: boolean;
  autoSendToBurp: boolean;
  burpIngestUrl: string;
  resourceEntryLimit: number;
  cacheEntryLimit: number;
  storageValueLimit: number;
}

export interface PageFrameSnapshot {
  url?: string;
  title?: string;
  origin?: string;
  referrer?: string;
  readyState: string;
  visibilityState: string;
  contentType?: string;
  characterSet?: string;
  navigation: JsonObject;
  runtimeIndicators: JsonObject;
  resources: JsonObject[];
  dom: {
    scripts: JsonObject[];
    stylesheets: JsonObject[];
    images: JsonObject[];
    manifests: JsonObject[];
    iframes: JsonObject[];
    fonts: JsonObject[];
  };
  storage: {
    localStorage: JsonObject[];
    sessionStorage: JsonObject[];
    indexedDb: JsonObject[];
    cacheStorage: JsonObject[];
  };
  workers: {
    serviceWorkers: JsonObject[];
    workerHints: JsonObject[];
  };
}

export interface PageFrameCollectorPayload {
  snapshot: PageFrameSnapshot;
  warnings: Array<{
    code: string;
    message: string;
  }>;
  visibilityGaps: Array<{
    code: string;
    message: string;
    reason:
      | 'cross-origin'
      | 'permission'
      | 'api-unavailable'
      | 'timing'
      | 'unsupported-context'
      | 'implementation-gap';
  }>;
}

export interface InstrumentationEventRecord {
  id: string;
  type:
    | 'blob-created'
    | 'blob-revoked'
    | 'script-added'
    | 'stylesheet-added'
    | 'image-added'
    | 'iframe-added'
    | 'worker-constructed'
    | 'shared-worker-constructed'
    | 'websocket-constructed'
    | 'eventsource-constructed'
    | 'network-request'
    | 'beacon-sent'
    | 'storage-write'
    | 'route-change'
    | 'runtime-error'
    | 'unhandled-rejection'
    | 'dom-mutation'
    | 'feature-candidates-observed'
    | 'lifecycle';
  observedAt: string;
  pageUrl?: string;
  frameHref?: string;
  url?: string;
  attributes: JsonObject;
}

export interface InstrumentationSnapshot {
  version: string;
  startedAt: string;
  pageUrl?: string;
  events: InstrumentationEventRecord[];
  warnings: string[];
  coverage?: {
    eventBuffer: {
      limit: number;
      retainedEventCount: number;
      droppedEventCount: number;
      droppedByReason: Record<string, number>;
    };
    responseObservation?: {
      responseLimit: number;
      perResponseByteLimit: number;
      totalByteLimit: number;
      eligibleResponseCount: number;
      startedResponseCount: number;
      observedResponseCount: number;
      candidateEventCount: number;
      capturedBytes: number;
      droppedResponseCount: number;
      truncatedResponseCount: number;
      droppedByReason: Record<string, number>;
      truncatedByReason: Record<string, number>;
    };
  };
}

export interface ContentInstrumentationResponse {
  instrumented: boolean;
  integrity: 'extension-verified' | 'page-world-unverified';
  frameUrl?: string;
  topFrame: boolean;
  snapshot?: InstrumentationSnapshot;
  warnings: string[];
}
