import type { DocumentAcquisitionSettings } from '../../shared/documentWorkbench';

export type ResolvedDocumentAcquisitionSettings = DocumentAcquisitionSettings;

export interface DocumentCandidate {
  url: string;
  finalUrl?: string;
  sourcePageUrl?: string;
  sourceTabId?: number;
  mimeType?: string;
  contentEncoding?: string;
  contentLength?: number;
  filename?: string;
}
