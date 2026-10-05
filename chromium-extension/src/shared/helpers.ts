import type { JsonObject, JsonValue } from '../../../shared-schema/src';

export function createId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}

export function toErrorDetails(error: unknown): JsonObject {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack ?? null
    };
  }

  return {
    message: String(error)
  };
}

export function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function sanitizeJsonValue(value: unknown): JsonValue {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeJsonValue(item));
  }

  if (typeof value === 'object' && value !== null) {
    const output: JsonObject = {};

    for (const [key, entry] of Object.entries(value)) {
      output[key] = sanitizeJsonValue(entry);
    }

    return output;
  }

  return String(value);
}

export function tryGetOrigin(rawUrl?: string): string | undefined {
  if (!rawUrl) {
    return undefined;
  }

  try {
    return new URL(rawUrl).origin;
  } catch {
    return undefined;
  }
}

export function isInspectableUrl(rawUrl?: string): boolean {
  if (!rawUrl) {
    return false;
  }

  return /^(https?|file):/i.test(rawUrl);
}

