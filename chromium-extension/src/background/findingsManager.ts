import type { JsonObject } from '../../../shared-schema/src';
import {
  scoreToSeverity,
  shouldAskQuestion,
  type FindingEvidence,
  type FindingKind,
  type FindingRecord,
  type FindingInput,
  type FindingsWorkbenchState,
  type TesterQuestion
} from '../shared/findingsWorkbench';

export class FindingsManager {
  constructor(
    private state: FindingsWorkbenchState,
    private readonly onChange: (state: FindingsWorkbenchState) => Promise<void>
  ) {}

  snapshot(): FindingsWorkbenchState {
    return this.state;
  }

  async refreshBadge(): Promise<void> {
    await this.updateBadge();
  }

  async add(input: FindingInput): Promise<FindingRecord> {
    const now = new Date().toISOString();
    const score = Math.max(0, Math.min(100, Math.round(input.score)));
    const signature = findingSignature(input);
    const existing = this.state.findings.find(
      (entry) => findingSignature(entry) === signature
    );

    const finding: FindingRecord = existing
      ? {
          ...existing,
          score: Math.max(existing.score, score),
          severity: scoreToSeverity(Math.max(existing.score, score)),
          title: input.title,
          summary: input.summary,
          updatedAt: now,
          evidence: dedupeEvidence([...existing.evidence, ...(input.evidence ?? [])]),
          context: input.context ?? existing.context
        }
      : {
          id: createId('finding'),
          kind: input.kind,
          severity: scoreToSeverity(score),
          status: 'new',
          score,
          title: input.title,
          summary: input.summary,
          createdAt: now,
          updatedAt: now,
          host: input.host,
          evidence: input.evidence ?? [],
          context: input.context
        };

    const findings = existing
      ? this.state.findings.map((entry) => (entry.id === existing.id ? finding : entry))
      : [finding, ...this.state.findings].slice(0, 500);
    let questions = this.state.questions;
    if (
      input.question &&
      shouldAskQuestion(score) &&
      !questions.some((entry) => entry.findingId === finding.id && entry.status === 'open')
    ) {
      const question: TesterQuestion = {
          id: createId('question'),
          findingId: finding.id,
          status: 'open',
          score,
          prompt: input.question.prompt,
          reason: input.question.reason,
          createdAt: now,
          actions:
            input.question.actions ?? [
              { id: 'inspect', label: 'Inspect', kind: 'inspect' },
              { id: 'report', label: 'Mark reportable', kind: 'report' },
              { id: 'dismiss', label: 'Dismiss', kind: 'dismiss' }
            ]
        };
      questions = [question, ...questions].slice(0, 200);
    }

    this.state = { findings, questions };
    await this.commit();
    return finding;
  }

  async answer(questionId: string, actionId: string): Promise<void> {
    const question = this.state.questions.find((entry) => entry.id === questionId);
    if (!question) throw new Error(`Unknown tester question: ${questionId}`);
    const action = question.actions.find((entry) => entry.id === actionId);
    if (!action) throw new Error(`Unknown question action: ${actionId}`);

    const findingStatus = action.kind === 'report' ? 'reported' : action.kind === 'dismiss' ? 'dismissed' : 'reviewed';
    this.state = {
      findings: this.state.findings.map((entry) =>
        entry.id === question.findingId
          ? { ...entry, status: findingStatus, updatedAt: new Date().toISOString() }
          : entry
      ),
      questions: this.state.questions.map((entry) =>
        entry.id === questionId
          ? { ...entry, status: action.kind === 'dismiss' ? 'dismissed' : 'answered' }
          : entry
      )
    };
    await this.commit();
  }

  private async commit(): Promise<void> {
    await this.onChange(this.state);
    await this.updateBadge();
  }

  private async updateBadge(): Promise<void> {
    const count = this.state.questions.filter((entry) => entry.status === 'open').length;
    if (chrome.action?.setBadgeText) {
      await chrome.action.setBadgeText({ text: count > 0 ? String(Math.min(99, count)) : '' });
      await chrome.action.setBadgeBackgroundColor({ color: '#c26a31' });
    }
  }
}

function dedupeEvidence(entries: FindingEvidence[]): FindingEvidence[] {
  const seen = new Set<string>();
  return entries.filter((entry) => {
    const key = `${entry.label}:${entry.detail}:${entry.url ?? ''}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 50);
}

function findingSignature(input: Pick<FindingInput, 'kind' | 'host' | 'title' | 'summary'>): string {
  if (input.kind === 'client-feature') return `client-feature:${input.host ?? ''}`.toLowerCase();
  if (input.kind === 'client-script') return `client-script:${input.host ?? ''}`.toLowerCase();
  return `${input.kind}:${input.host ?? ''}:${input.title}:${input.summary}`.toLowerCase();
}

function createId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}
