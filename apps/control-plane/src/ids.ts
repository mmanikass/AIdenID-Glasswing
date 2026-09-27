import { randomUUID } from "node:crypto";

export function prefixedId(prefix: string): string {
  return `${prefix}_${randomUUID().replaceAll("-", "")}`;
}
