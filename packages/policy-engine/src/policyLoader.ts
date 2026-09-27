import { readFileSync, watch, type FSWatcher } from "node:fs";
import { parse } from "yaml";

import { buildPolicyTrie, type PolicyTrie } from "./routeTrie.js";
import { compilePolicyDocument } from "./schema.js";
import type { CompiledPolicyBundle } from "./types.js";

export interface LoadedPolicy {
  readonly bundle: CompiledPolicyBundle;
  readonly trie: PolicyTrie;
}

export interface PolicyWatcher {
  current(): LoadedPolicy;
  close(): void;
}

export function parsePolicyYaml(source: string): LoadedPolicy {
  const parsed = parse(source);
  const bundle = compilePolicyDocument(parsed);
  return {
    bundle,
    trie: buildPolicyTrie(bundle)
  };
}

export function loadPolicyYamlFile(filePath: string): LoadedPolicy {
  return parsePolicyYaml(readFileSync(filePath, "utf8"));
}

export function watchPolicyYamlFile(filePath: string, onReload: (policy: LoadedPolicy) => void, onError?: (error: unknown) => void): PolicyWatcher {
  let current = loadPolicyYamlFile(filePath);
  let debounce: NodeJS.Timeout | undefined;

  const reload = (): void => {
    try {
      const next = loadPolicyYamlFile(filePath);
      current = next;
      onReload(next);
    } catch (error) {
      onError?.(error);
    }
  };

  const watcher: FSWatcher = watch(filePath, { persistent: false }, () => {
    if (debounce !== undefined) {
      clearTimeout(debounce);
    }
    debounce = setTimeout(reload, 25);
  });

  return {
    current: () => current,
    close: () => {
      if (debounce !== undefined) {
        clearTimeout(debounce);
      }
      watcher.close();
    }
  };
}
