import { createHash } from "node:crypto";

export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

export function sha256Bytes(input: string | Uint8Array): Buffer {
  return createHash("sha256").update(input).digest();
}

export function base64Url(input: Uint8Array): string {
  return Buffer.from(input).toString("base64url");
}

export function base64UrlToBuffer(input: string): Buffer {
  return Buffer.from(input, "base64url");
}
