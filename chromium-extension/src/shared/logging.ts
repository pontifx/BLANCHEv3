import type { JsonObject } from '../../../shared-schema/src';
import type { LogEntry, Logger } from './contracts';
import { createId } from './helpers';

export class LogBuffer {
  private readonly entries: LogEntry[] = [];

  constructor(private readonly capacity = 200) {}

  add(level: LogEntry['level'], source: string, message: string, context?: JsonObject): void {
    const entry: LogEntry = {
      id: createId('log'),
      timestamp: new Date().toISOString(),
      level,
      source,
      message,
      context
    };

    this.entries.unshift(entry);
    if (this.entries.length > this.capacity) {
      this.entries.length = this.capacity;
    }
  }

  getEntries(limit = 50): LogEntry[] {
    return this.entries.slice(0, limit);
  }
}

export function createLogger(buffer: LogBuffer, source: string): Logger {
  return {
    debug(message, context) {
      buffer.add('debug', source, message, context);
    },
    info(message, context) {
      buffer.add('info', source, message, context);
    },
    warn(message, context) {
      buffer.add('warn', source, message, context);
    },
    error(message, context) {
      buffer.add('error', source, message, context);
    },
    child(segment) {
      return createLogger(buffer, `${source}/${segment}`);
    }
  };
}

