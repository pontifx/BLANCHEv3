import type { FeedEntry, FeedEntryInput, FeedManager } from '../shared/contracts';
import { createId } from '../shared/helpers';

const MAX_FEED_ENTRIES = 200;

export class PersistentFeedManager implements FeedManager {
  private readonly entries: FeedEntry[];

  constructor(
    initialEntries: FeedEntry[],
    private readonly onChange: (entries: FeedEntry[]) => Promise<void> | void
  ) {
    this.entries = [...initialEntries];
  }

  add(input: FeedEntryInput): FeedEntry {
    const entry: FeedEntry = {
      ...input,
      id: createId('feed'),
      createdAt: new Date().toISOString()
    };

    this.entries.unshift(entry);
    this.trim();
    void this.onChange(this.list());
    return entry;
  }

  list(): FeedEntry[] {
    return this.entries.map((entry) => ({ ...entry }));
  }

  private trim(): void {
    if (this.entries.length > MAX_FEED_ENTRIES) {
      this.entries.length = MAX_FEED_ENTRIES;
    }
  }
}
