import type { OutboxEvent } from "./outbox.js";

export interface RedisStreamEntry {
  readonly id: string;
  readonly fieldValues: readonly string[];
}

export function redisFieldsToRecord(fieldValues: readonly string[]): Readonly<Record<string, string>> {
  if (fieldValues.length % 2 !== 0) {
    throw new Error("redis stream field/value array must have an even length");
  }

  const fields: Record<string, string> = {};
  for (let index = 0; index < fieldValues.length; index += 2) {
    const key = fieldValues[index];
    const value = fieldValues[index + 1];
    if (key === undefined || value === undefined) {
      throw new Error("redis stream field/value pair is incomplete");
    }
    fields[key] = value;
  }
  return fields;
}

export function outboxEventFromRedisStream(entry: RedisStreamEntry): OutboxEvent {
  const fields = redisFieldsToRecord(entry.fieldValues);
  const id = fields.id;
  const type = fields.type;
  const occurredAt = fields.occurred_at;
  const payload = fields.payload;

  if (id === undefined || type === undefined || occurredAt === undefined || payload === undefined) {
    throw new Error("redis stream entry is missing required outbox fields");
  }

  const parsedPayload = JSON.parse(payload);
  if (parsedPayload === null || typeof parsedPayload !== "object" || Array.isArray(parsedPayload)) {
    throw new Error("redis stream outbox payload must be an object");
  }

  return {
    id,
    type,
    occurredAt,
    payload: parsedPayload as Record<string, unknown>
  };
}
