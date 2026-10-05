import type { JsonObject } from '../../../shared-schema/src';

export type FindingKind =
  | 'search-result'
  | 'document'
  | 'library'
  | 'archive-drift'
  | 'client-feature'
  | 'client-script'
  | 'extracted-url'
  | 'diagnostic';
export type FindingSeverity = 'info' | 'notice' | 'warning' | 'high';
export type FindingStatus = 'new' | 'reviewed' | 'reported' | 'dismissed';
export type QuestionStatus = 'open' | 'answered' | 'dismissed';

export interface FindingEvidence {
  label: string;
  detail: string;
  url?: string;
}

export interface FindingRecord {
  id: string;
  kind: FindingKind;
  severity: FindingSeverity;
  status: FindingStatus;
  score: number;
  title: string;
  summary: string;
  createdAt: string;
  updatedAt: string;
  host?: string;
  evidence: FindingEvidence[];
  context?: JsonObject;
}

export interface TesterQuestion {
  id: string;
  findingId: string;
  status: QuestionStatus;
  score: number;
  prompt: string;
  reason: string;
  createdAt: string;
  actions: Array<{
    id: string;
    label: string;
    kind: 'inspect' | 'report' | 'follow-up' | 'dismiss';
  }>;
}

export interface FindingsWorkbenchState {
  findings: FindingRecord[];
  questions: TesterQuestion[];
}

export interface FindingInput {
  kind: FindingKind;
  score: number;
  title: string;
  summary: string;
  host?: string;
  evidence?: FindingEvidence[];
  context?: JsonObject;
  question?: {
    prompt: string;
    reason: string;
    actions?: TesterQuestion['actions'];
  };
}

export function createDefaultFindingsWorkbenchState(): FindingsWorkbenchState {
  return {
    findings: [],
    questions: []
  };
}

export function normalizeFindingsWorkbenchState(value: unknown): FindingsWorkbenchState {
  if (!isRecord(value)) {
    return createDefaultFindingsWorkbenchState();
  }
  return {
    findings: Array.isArray(value.findings)
      ? value.findings.filter(isRecord).map((entry) => entry as unknown as FindingRecord).slice(0, 500)
      : [],
    questions: Array.isArray(value.questions)
      ? value.questions.filter(isRecord).map((entry) => entry as unknown as TesterQuestion).slice(0, 200)
      : []
  };
}

export function scoreToSeverity(score: number): FindingSeverity {
  if (score >= 85) return 'high';
  if (score >= 65) return 'warning';
  if (score >= 35) return 'notice';
  return 'info';
}

export function shouldAskQuestion(score: number): boolean {
  return score >= 75;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
