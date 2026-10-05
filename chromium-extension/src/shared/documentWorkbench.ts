export type DocumentSource =
  | 'web-request'
  | 'current-page-link'
  | 'indexed-search'
  | 'manual';

export type DocumentStatus =
  | 'discovered'
  | 'queued'
  | 'acquiring'
  | 'acquired'
  | 'reviewed'
  | 'downloaded'
  | 'duplicate'
  | 'blocked'
  | 'failed';

export interface InterestingKeywordHit {
  keyword: string;
  count: number;
}

export interface DocumentAnalysis {
  compressionTypes: string[];
  extractedUrls: string[];
  interestingKeywords: InterestingKeywordHit[];
  scannedTextBytes: number;
  notes: string[];
}

export interface AcquiredDocument {
  id: string;
  sessionId: string;
  url: string;
  finalUrl?: string;
  targetHost?: string;
  source: DocumentSource;
  sourcePageUrl?: string;
  sourceTabId?: number;
  filename?: string;
  downloadFilename?: string;
  downloadId?: number;
  mimeType?: string;
  contentEncoding?: string;
  byteLength?: number;
  sha256?: string;
  firstSeenAt: string;
  lastSeenAt: string;
  acquiredAt?: string;
  status: DocumentStatus;
  failureReason?: string;
  analysis?: DocumentAnalysis;
  interestScore?: number;
  queueReason?: string;
  downloadDecision?: 'review' | 'rule-approved' | 'manual' | 'not-downloaded';
}

export interface DocumentSession {
  id: string;
  label: string;
  folderName: string;
  createdAt: string;
  updatedAt: string;
  documentCount: number;
  acquiredCount: number;
  lastDownloadId?: number;
}

export interface DocumentWorkbenchState {
  activeSessionId: string;
  sessions: DocumentSession[];
  documents: AcquiredDocument[];
}

export interface DocumentAcquisitionSettings {
  autoCaptureBrowsedDocuments: boolean;
  autoDownloadDocuments: boolean;
  maxDocumentBytes: number;
  downloadFolderRoot: string;
  interestingKeywords: string;
  autoDownloadScoreThreshold: number;
  downloadRuleKeywords: string;
}

const DEFAULT_KEYWORDS = [
  'password',
  'passwd',
  'credential',
  'secret',
  'token',
  'api_key',
  'apikey',
  'bearer',
  'authorization',
  'client_secret',
  'private key',
  'aws_access_key_id',
  'connection string',
  'jdbc',
  'ldap',
  'saml',
  'oauth',
  'sso',
  'vpn',
  'admin',
  'internal',
  'confidential',
  'restricted',
  'staging',
  'dev',
  'prod',
  'database',
  'payroll',
  'ssn'
];

export const DEFAULT_DOCUMENT_KEYWORDS = DEFAULT_KEYWORDS.join(', ');

export function createDefaultDocumentWorkbenchState(): DocumentWorkbenchState {
  const session = createDocumentSession();
  return {
    activeSessionId: session.id,
    sessions: [session],
    documents: []
  };
}

export function createDocumentSession(label?: string): DocumentSession {
  const timestamp = new Date().toISOString();
  const id = createDocumentWorkbenchId('docs');
  const normalizedLabel = label?.trim() || `Session ${timestamp.slice(0, 19).replace('T', ' ')}`;
  return {
    id,
    label: normalizedLabel,
    folderName: `${sanitizePathSegment(normalizedLabel)}-${id.slice(-8)}`,
    createdAt: timestamp,
    updatedAt: timestamp,
    documentCount: 0,
    acquiredCount: 0
  };
}

export function normalizeDocumentWorkbenchState(rawValue: unknown): DocumentWorkbenchState {
  const fallback = createDefaultDocumentWorkbenchState();
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return fallback;
  }

  const source = rawValue as Partial<DocumentWorkbenchState>;
  const sessions = Array.isArray(source.sessions)
    ? source.sessions
        .map((session) => normalizeDocumentSession(session))
        .filter((session): session is DocumentSession => Boolean(session))
    : [];
  const normalizedSessions = sessions.length > 0 ? sessions : fallback.sessions;
  const activeSessionId =
    typeof source.activeSessionId === 'string' &&
    normalizedSessions.some((session) => session.id === source.activeSessionId)
      ? source.activeSessionId
      : normalizedSessions[0]?.id ?? fallback.activeSessionId;
  const documents = Array.isArray(source.documents)
    ? source.documents
        .map((document) => normalizeAcquiredDocument(document, activeSessionId))
        .filter((document): document is AcquiredDocument => Boolean(document))
    : [];

  return recalculateDocumentSessionCounts({
    activeSessionId,
    sessions: normalizedSessions,
    documents
  });
}

export function recalculateDocumentSessionCounts(
  state: DocumentWorkbenchState
): DocumentWorkbenchState {
  return {
    ...state,
    sessions: state.sessions.map((session) => {
      const sessionDocuments = state.documents.filter((document) => document.sessionId === session.id);
      const lastDownloadId = [...sessionDocuments]
        .reverse()
        .find((document) => typeof document.downloadId === 'number')?.downloadId;

      return {
        ...session,
        documentCount: sessionDocuments.length,
        acquiredCount: sessionDocuments.filter((document) => ['acquired', 'reviewed', 'downloaded'].includes(document.status)).length,
        updatedAt:
          sessionDocuments
            .map((document) => document.lastSeenAt)
            .sort()
            .at(-1) ?? session.updatedAt,
        lastDownloadId
      };
    })
  };
}

export function parseInterestingKeywords(rawValue: unknown): string[] {
  const rawText = typeof rawValue === 'string' ? rawValue : DEFAULT_DOCUMENT_KEYWORDS;
  const keywords = new Set<string>();
  for (const part of rawText.split(/[\n,;]+/g)) {
    const keyword = part.trim().toLowerCase();
    if (keyword) {
      keywords.add(keyword);
    }
  }

  return [...keywords];
}

export function sanitizePathSegment(rawValue: string): string {
  const sanitized = rawValue
    .trim()
    .replace(/[<>:"/\\|?*\u0000-\u001f]+/g, '-')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');

  return sanitized.slice(0, 80) || 'documents';
}

export function getActiveDocumentSession(state: DocumentWorkbenchState): DocumentSession {
  return (
    state.sessions.find((session) => session.id === state.activeSessionId) ??
    state.sessions[0] ??
    createDocumentSession()
  );
}

function normalizeDocumentSession(rawValue: unknown): DocumentSession | undefined {
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return undefined;
  }

  const source = rawValue as Partial<DocumentSession>;
  const id = typeof source.id === 'string' && source.id ? source.id : createDocumentWorkbenchId('docs');
  const createdAt = typeof source.createdAt === 'string' ? source.createdAt : new Date().toISOString();
  const label = typeof source.label === 'string' && source.label.trim() ? source.label.trim() : 'Documents';
  return {
    id,
    label,
    folderName:
      typeof source.folderName === 'string' && source.folderName.trim()
        ? sanitizePathSegment(source.folderName)
        : `${sanitizePathSegment(label)}-${id.slice(-8)}`,
    createdAt,
    updatedAt: typeof source.updatedAt === 'string' ? source.updatedAt : createdAt,
    documentCount: typeof source.documentCount === 'number' ? source.documentCount : 0,
    acquiredCount: typeof source.acquiredCount === 'number' ? source.acquiredCount : 0,
    lastDownloadId: typeof source.lastDownloadId === 'number' ? source.lastDownloadId : undefined
  };
}

function normalizeAcquiredDocument(
  rawValue: unknown,
  fallbackSessionId: string
): AcquiredDocument | undefined {
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return undefined;
  }

  const source = rawValue as Partial<AcquiredDocument>;
  if (typeof source.url !== 'string' || !source.url.trim()) {
    return undefined;
  }

  const firstSeenAt =
    typeof source.firstSeenAt === 'string' ? source.firstSeenAt : new Date().toISOString();
  return {
    id: typeof source.id === 'string' && source.id ? source.id : createDocumentWorkbenchId('doc'),
    sessionId:
      typeof source.sessionId === 'string' && source.sessionId ? source.sessionId : fallbackSessionId,
    url: source.url,
    finalUrl: typeof source.finalUrl === 'string' ? source.finalUrl : undefined,
    targetHost: typeof source.targetHost === 'string' ? source.targetHost : undefined,
    source: normalizeDocumentSource(source.source),
    sourcePageUrl: typeof source.sourcePageUrl === 'string' ? source.sourcePageUrl : undefined,
    sourceTabId: typeof source.sourceTabId === 'number' ? source.sourceTabId : undefined,
    filename: typeof source.filename === 'string' ? source.filename : undefined,
    downloadFilename: typeof source.downloadFilename === 'string' ? source.downloadFilename : undefined,
    downloadId: typeof source.downloadId === 'number' ? source.downloadId : undefined,
    mimeType: typeof source.mimeType === 'string' ? source.mimeType : undefined,
    contentEncoding: typeof source.contentEncoding === 'string' ? source.contentEncoding : undefined,
    byteLength: typeof source.byteLength === 'number' ? source.byteLength : undefined,
    sha256: typeof source.sha256 === 'string' ? source.sha256 : undefined,
    firstSeenAt,
    lastSeenAt: typeof source.lastSeenAt === 'string' ? source.lastSeenAt : firstSeenAt,
    acquiredAt: typeof source.acquiredAt === 'string' ? source.acquiredAt : undefined,
    status: normalizeDocumentStatus(source.status),
    failureReason: typeof source.failureReason === 'string' ? source.failureReason : undefined,
    analysis: normalizeDocumentAnalysis(source.analysis),
    interestScore: typeof source.interestScore === 'number' ? source.interestScore : undefined,
    queueReason: typeof source.queueReason === 'string' ? source.queueReason : undefined,
    downloadDecision:
      source.downloadDecision === 'review' || source.downloadDecision === 'rule-approved' || source.downloadDecision === 'manual' || source.downloadDecision === 'not-downloaded'
        ? source.downloadDecision
        : undefined
  };
}

function normalizeDocumentAnalysis(rawValue: unknown): DocumentAnalysis | undefined {
  if (!rawValue || typeof rawValue !== 'object' || Array.isArray(rawValue)) {
    return undefined;
  }

  const source = rawValue as Partial<DocumentAnalysis>;
  return {
    compressionTypes: Array.isArray(source.compressionTypes)
      ? source.compressionTypes.filter((entry): entry is string => typeof entry === 'string')
      : [],
    extractedUrls: Array.isArray(source.extractedUrls)
      ? source.extractedUrls.filter((entry): entry is string => typeof entry === 'string')
      : [],
    interestingKeywords: Array.isArray(source.interestingKeywords)
      ? source.interestingKeywords
          .filter(
            (entry): entry is InterestingKeywordHit =>
              Boolean(entry) &&
              typeof entry === 'object' &&
              typeof (entry as InterestingKeywordHit).keyword === 'string' &&
              typeof (entry as InterestingKeywordHit).count === 'number'
          )
      : [],
    scannedTextBytes:
      typeof source.scannedTextBytes === 'number' ? source.scannedTextBytes : 0,
    notes: Array.isArray(source.notes)
      ? source.notes.filter((entry): entry is string => typeof entry === 'string')
      : []
  };
}

function normalizeDocumentSource(value: unknown): DocumentSource {
  switch (value) {
    case 'web-request':
    case 'current-page-link':
    case 'indexed-search':
    case 'manual':
      return value;
    default:
      return 'manual';
  }
}

function normalizeDocumentStatus(value: unknown): DocumentStatus {
  switch (value) {
    case 'discovered':
    case 'queued':
    case 'acquiring':
    case 'acquired':
    case 'reviewed':
    case 'downloaded':
    case 'duplicate':
    case 'blocked':
    case 'failed':
      return value;
    default:
      return 'discovered';
  }
}

function createDocumentWorkbenchId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}
