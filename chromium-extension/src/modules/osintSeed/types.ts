import type { JsonObject } from '../../../../shared-schema/src';

export interface OsintSeedSettings {
  autoSendToBurp: boolean;
  burpSeedUrl: string;
  relatedHostLimit: number;
}

export interface SeedCollectionPayload {
  pageUrl?: string;
  pageOrigin?: string;
  pageTitle?: string;
  referrer?: string;
  signals: {
    anchors: string[];
    scripts: string[];
    stylesheets: string[];
    images: string[];
    forms: string[];
    iframes: string[];
    manifests: string[];
  };
  signalSummary: JsonObject;
}
