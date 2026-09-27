export interface OutboxEvent<TPayload extends Record<string, unknown> = Record<string, unknown>> {
  readonly id: string;
  readonly type: string;
  readonly occurredAt: string;
  readonly payload: TPayload;
}

export interface StoredOutboxEvent<TPayload extends Record<string, unknown> = Record<string, unknown>> extends OutboxEvent<TPayload> {
  readonly attempts: number;
  readonly publishedAt?: string | undefined;
}

export interface OutboxStore {
  append(event: OutboxEvent): void;
  pending(limit?: number): readonly StoredOutboxEvent[];
  markPublished(id: string, publishedAt?: string): void;
}

export interface OutboxPublisher {
  publish(event: OutboxEvent): Promise<void>;
  publishAsync(event: OutboxEvent): void;
  flush(): Promise<void>;
}

export interface RedisStreamsClient {
  xadd(stream: string, id: "*", ...fieldValues: string[]): Promise<string>;
}

export function makeOutboxEvent<TPayload extends Record<string, unknown>>(
  id: string,
  type: string,
  payload: TPayload,
  occurredAt = new Date().toISOString()
): OutboxEvent<TPayload> {
  if (!id.trim()) {
    throw new Error("outbox event id is required");
  }
  if (!type.trim()) {
    throw new Error("outbox event type is required");
  }

  return { id, type, occurredAt, payload };
}

export class InMemoryOutboxStore implements OutboxStore {
  readonly #events = new Map<string, StoredOutboxEvent>();

  append(event: OutboxEvent): void {
    if (!this.#events.has(event.id)) {
      this.#events.set(event.id, { ...event, attempts: 0 });
    }
  }

  pending(limit = 100): readonly StoredOutboxEvent[] {
    return [...this.#events.values()].filter((event) => event.publishedAt === undefined).slice(0, limit);
  }

  markPublished(id: string, publishedAt = new Date().toISOString()): void {
    const event = this.#events.get(id);
    if (event !== undefined) {
      this.#events.set(id, { ...event, publishedAt, attempts: event.attempts + 1 });
    }
  }

  all(): readonly StoredOutboxEvent[] {
    return [...this.#events.values()];
  }
}

export class RedisStreamsOutboxPublisher {
  readonly #client: RedisStreamsClient;
  readonly #streamName: string;

  constructor(client: RedisStreamsClient, streamName = "aidenid:outbox") {
    this.#client = client;
    this.#streamName = streamName;
  }

  async publish(event: OutboxEvent): Promise<string> {
    return this.#client.xadd(
      this.#streamName,
      "*",
      "id",
      event.id,
      "type",
      event.type,
      "occurred_at",
      event.occurredAt,
      "payload",
      JSON.stringify(event.payload)
    );
  }
}

export class StoreBackedOutboxPublisher implements OutboxPublisher {
  readonly #store: OutboxStore;
  readonly #downstream: RedisStreamsOutboxPublisher | undefined;

  constructor(store: OutboxStore, downstream?: RedisStreamsOutboxPublisher | undefined) {
    this.#store = store;
    this.#downstream = downstream;
  }

  async publish(event: OutboxEvent): Promise<void> {
    this.#store.append(event);
    await this.flush();
  }

  publishAsync(event: OutboxEvent): void {
    this.#store.append(event);
    void this.flush().catch(() => undefined);
  }

  async flush(): Promise<void> {
    if (this.#downstream === undefined) {
      return;
    }
    const batch = this.#store.pending(100);
    for (const event of batch) {
      await this.#downstream.publish(event);
      this.#store.markPublished(event.id);
    }
  }
}
