import { createConnection, type Socket } from "node:net";
import { connect as connectTls, type TLSSocket } from "node:tls";

import type { RedisStreamsClient } from "@aidenid/eventing";

type RedisSocket = Socket | TLSSocket;
type RedisRespValue = string | number | null | readonly RedisRespValue[];

export interface ControlPlaneRedisStreamsClientOptions {
  readonly host: string;
  readonly port?: number | undefined;
  readonly tls?: boolean | undefined;
  readonly authToken?: string | undefined;
  readonly connectTimeoutMs?: number | undefined;
  readonly commandTimeoutMs?: number | undefined;
}

interface PendingCommand {
  readonly resolve: (value: RedisRespValue) => void;
  readonly reject: (error: Error) => void;
  readonly timer: NodeJS.Timeout;
}

interface ParsedFrame {
  readonly value: RedisRespValue | RedisCommandError;
  readonly nextOffset: number;
}

const DEFAULT_REDIS_PORT = 6379;
const DEFAULT_CONNECT_TIMEOUT_MS = 1_000;
const DEFAULT_COMMAND_TIMEOUT_MS = 1_000;

class RedisCommandError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RedisCommandError";
  }
}

function encodeCommand(parts: readonly string[]): Buffer {
  const buffers: Buffer[] = [Buffer.from(`*${parts.length}\r\n`, "utf8")];
  for (const part of parts) {
    const payload = Buffer.from(part, "utf8");
    buffers.push(Buffer.from(`$${payload.length}\r\n`, "utf8"), payload, Buffer.from("\r\n", "utf8"));
  }
  return Buffer.concat(buffers);
}

class RespParser {
  #buffer = Buffer.alloc(0);

  push(chunk: Buffer): readonly (RedisRespValue | RedisCommandError)[] {
    this.#buffer = Buffer.concat([this.#buffer, chunk]);
    const frames: (RedisRespValue | RedisCommandError)[] = [];
    while (this.#buffer.length > 0) {
      const parsed = this.parseFrame(0);
      if (parsed === undefined) {
        break;
      }
      frames.push(parsed.value);
      this.#buffer = this.#buffer.subarray(parsed.nextOffset);
    }
    return frames;
  }

  private parseFrame(offset: number): ParsedFrame | undefined {
    if (offset >= this.#buffer.length) {
      return undefined;
    }
    const byte = this.#buffer[offset];
    if (byte === undefined) {
      return undefined;
    }
    const prefix = String.fromCharCode(byte);
    if (prefix === "+" || prefix === "-" || prefix === ":") {
      const line = this.readLine(offset + 1);
      if (line === undefined) {
        return undefined;
      }
      if (prefix === "+") {
        return { value: line.text, nextOffset: line.nextOffset };
      }
      if (prefix === "-") {
        return { value: new RedisCommandError(line.text), nextOffset: line.nextOffset };
      }
      return { value: Number(line.text), nextOffset: line.nextOffset };
    }
    if (prefix === "$") {
      const line = this.readLine(offset + 1);
      if (line === undefined) {
        return undefined;
      }
      const length = Number(line.text);
      if (!Number.isInteger(length)) {
        throw new Error("Redis bulk string length is invalid");
      }
      if (length < 0) {
        return { value: null, nextOffset: line.nextOffset };
      }
      const payloadStart = line.nextOffset;
      const payloadEnd = payloadStart + length;
      const frameEnd = payloadEnd + 2;
      if (this.#buffer.length < frameEnd) {
        return undefined;
      }
      if (this.#buffer[payloadEnd] !== 13 || this.#buffer[payloadEnd + 1] !== 10) {
        throw new Error("Redis bulk string frame is malformed");
      }
      return {
        value: this.#buffer.toString("utf8", payloadStart, payloadEnd),
        nextOffset: frameEnd
      };
    }
    if (prefix === "*") {
      const line = this.readLine(offset + 1);
      if (line === undefined) {
        return undefined;
      }
      const count = Number(line.text);
      if (!Number.isInteger(count)) {
        throw new Error("Redis array length is invalid");
      }
      if (count < 0) {
        return { value: null, nextOffset: line.nextOffset };
      }
      const values: RedisRespValue[] = [];
      let nextOffset = line.nextOffset;
      for (let index = 0; index < count; index += 1) {
        const parsed = this.parseFrame(nextOffset);
        if (parsed === undefined) {
          return undefined;
        }
        if (parsed.value instanceof RedisCommandError) {
          return parsed;
        }
        values.push(parsed.value);
        nextOffset = parsed.nextOffset;
      }
      return { value: values, nextOffset };
    }
    throw new Error(`Unsupported Redis RESP frame prefix '${prefix}'`);
  }

  private readLine(offset: number): { readonly text: string; readonly nextOffset: number } | undefined {
    for (let index = offset; index < this.#buffer.length - 1; index += 1) {
      if (this.#buffer[index] === 13 && this.#buffer[index + 1] === 10) {
        return {
          text: this.#buffer.toString("utf8", offset, index),
          nextOffset: index + 2
        };
      }
    }
    return undefined;
  }
}

export class ControlPlaneRedisStreamsClient implements RedisStreamsClient {
  readonly #host: string;
  readonly #port: number;
  readonly #tls: boolean;
  readonly #authToken: string | undefined;
  readonly #connectTimeoutMs: number;
  readonly #commandTimeoutMs: number;
  readonly #parser = new RespParser();
  readonly #pending: PendingCommand[] = [];
  #socket: RedisSocket | undefined;
  #connectPromise: Promise<void> | undefined;
  #authenticated = false;

  constructor(options: ControlPlaneRedisStreamsClientOptions) {
    const host = options.host.trim();
    if (host.length === 0) {
      throw new Error("Redis host is required");
    }
    this.#host = host;
    this.#port = options.port ?? DEFAULT_REDIS_PORT;
    this.#tls = options.tls ?? false;
    this.#authToken = options.authToken?.trim() === "" ? undefined : options.authToken;
    this.#connectTimeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
    this.#commandTimeoutMs = options.commandTimeoutMs ?? DEFAULT_COMMAND_TIMEOUT_MS;
  }

  async ping(): Promise<void> {
    const result = await this.command(["PING"]);
    if (result !== "PONG") {
      throw new Error("Redis PING returned an unexpected response");
    }
  }

  async xadd(stream: string, id: "*", ...fieldValues: string[]): Promise<string> {
    if (stream.trim().length === 0) {
      throw new Error("Redis stream name is required");
    }
    if (id !== "*") {
      throw new Error("control-plane outbox only supports Redis XADD auto ids");
    }
    if (fieldValues.length === 0 || fieldValues.length % 2 !== 0) {
      throw new Error("Redis XADD field values must be non-empty key/value pairs");
    }
    const result = await this.command(["XADD", stream, id, ...fieldValues]);
    if (typeof result !== "string") {
      throw new Error("Redis XADD returned a non-string entry id");
    }
    return result;
  }

  async close(): Promise<void> {
    const socket = this.#socket;
    if (socket === undefined || socket.destroyed) {
      return;
    }
    await new Promise<void>((resolve) => {
      socket.once("close", () => resolve());
      socket.end();
    });
  }

  private async command(parts: readonly string[]): Promise<RedisRespValue> {
    await this.ensureConnected();
    return await this.send(parts);
  }

  private async ensureConnected(): Promise<void> {
    if (this.#socket !== undefined && !this.#socket.destroyed) {
      return;
    }
    if (this.#connectPromise !== undefined) {
      await this.#connectPromise;
      return;
    }
    this.#connectPromise = this.openSocket();
    try {
      await this.#connectPromise;
      if (this.#authToken !== undefined && !this.#authenticated) {
        await this.send(["AUTH", this.#authToken]);
        this.#authenticated = true;
      }
    } finally {
      this.#connectPromise = undefined;
    }
  }

  private async openSocket(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const onConnect = () => {
        clearTimeout(timer);
        resolve();
      };
      const socket = this.#tls
        ? connectTls({ host: this.#host, port: this.#port, servername: this.#host }, onConnect)
        : createConnection({ host: this.#host, port: this.#port }, onConnect);
      this.#socket = socket;
      socket.on("data", (chunk: Buffer) => this.handleData(chunk));
      socket.on("error", (error) => this.reset(error));
      socket.on("close", () => this.reset(new Error("Redis connection closed")));
      const timer = setTimeout(() => {
        socket.destroy(new Error("Redis connection timed out"));
      }, this.#connectTimeoutMs);
      timer.unref();
      socket.once("error", reject);
    });
  }

  private async send(parts: readonly string[]): Promise<RedisRespValue> {
    const socket = this.#socket;
    if (socket === undefined || socket.destroyed) {
      throw new Error("Redis connection is not open");
    }
    return await new Promise<RedisRespValue>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.reset(new Error("Redis command timed out"));
      }, this.#commandTimeoutMs);
      timer.unref();
      this.#pending.push({ resolve, reject, timer });
      socket.write(encodeCommand(parts));
    });
  }

  private handleData(chunk: Buffer): void {
    let frames: readonly (RedisRespValue | RedisCommandError)[];
    try {
      frames = this.#parser.push(chunk);
    } catch (error) {
      this.reset(error instanceof Error ? error : new Error(String(error)));
      return;
    }
    for (const frame of frames) {
      const pending = this.#pending.shift();
      if (pending === undefined) {
        this.reset(new Error("Redis returned an unsolicited response"));
        return;
      }
      clearTimeout(pending.timer);
      if (frame instanceof RedisCommandError) {
        pending.reject(frame);
      } else {
        pending.resolve(frame);
      }
    }
  }

  private reset(error: Error): void {
    const pending = this.#pending.splice(0);
    for (const command of pending) {
      clearTimeout(command.timer);
      command.reject(error);
    }
    this.#authenticated = false;
    const socket = this.#socket;
    this.#socket = undefined;
    if (socket !== undefined && !socket.destroyed) {
      socket.destroy();
    }
  }
}
