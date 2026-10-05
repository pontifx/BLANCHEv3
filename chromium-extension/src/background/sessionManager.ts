import type { CollectionSessionRecord, SessionManager } from '../shared/contracts';
import { createId } from '../shared/helpers';

export class PersistentSessionManager implements SessionManager {
  private readonly sessions: CollectionSessionRecord[];

  constructor(
    initialSessions: CollectionSessionRecord[],
    private readonly onChange: (sessions: CollectionSessionRecord[]) => Promise<void> | void
  ) {
    this.sessions = [...initialSessions];
  }

  begin(input: {
    moduleId: string;
    tabId: number;
    mode: CollectionSessionRecord['mode'];
    reloadTriggered: boolean;
    note?: string;
  }): CollectionSessionRecord {
    const session: CollectionSessionRecord = {
      sessionId: createId('session'),
      moduleId: input.moduleId,
      tabId: input.tabId,
      mode: input.mode,
      reloadTriggered: input.reloadTriggered,
      startedAt: new Date().toISOString(),
      status: 'running',
      note: input.note
    };

    this.sessions.unshift(session);
    this.trim();
    void this.onChange(this.list());
    return session;
  }

  complete(sessionId: string, note?: string): CollectionSessionRecord | undefined {
    const session = this.sessions.find((item) => item.sessionId === sessionId);
    if (!session) {
      return undefined;
    }

    session.status = 'completed';
    session.finishedAt = new Date().toISOString();
    if (note) {
      session.note = note;
    }

    void this.onChange(this.list());
    return session;
  }

  fail(sessionId: string, note?: string): CollectionSessionRecord | undefined {
    const session = this.sessions.find((item) => item.sessionId === sessionId);
    if (!session) {
      return undefined;
    }

    session.status = 'failed';
    session.finishedAt = new Date().toISOString();
    if (note) {
      session.note = note;
    }

    void this.onChange(this.list());
    return session;
  }

  list(): CollectionSessionRecord[] {
    return this.sessions.map((session) => ({ ...session }));
  }

  private trim(): void {
    if (this.sessions.length > 25) {
      this.sessions.length = 25;
    }
  }
}

