import type { ActorClass, ActorRoutePolicy, CompiledPolicyBundle, CompiledRoutePolicy, MatchedPolicy } from "./types.js";

interface ParamChild {
  readonly name: string;
  readonly node: TrieNode;
}

interface MatchCandidate {
  readonly routePolicy: CompiledRoutePolicy;
  readonly routeTemplate: string;
  readonly params: Readonly<Record<string, string>>;
  readonly specificity: number;
  readonly depth: number;
  readonly methodExact: boolean;
}

class TrieNode {
  readonly staticChildren = new Map<string, TrieNode>();
  readonly paramChildren: ParamChild[] = [];
  wildcardChild: TrieNode | undefined;
  readonly routePolicies = new Map<string, CompiledRoutePolicy>();
}

function pathSegments(path: string): string[] {
  return path
    .split("/")
    .map((segment) => segment.trim())
    .filter(Boolean);
}

function childForParam(node: TrieNode, name: string): TrieNode {
  const existing = node.paramChildren.find((child) => child.name === name);
  if (existing !== undefined) {
    return existing.node;
  }
  const child = new TrieNode();
  node.paramChildren.push({ name, node: child });
  return child;
}

function methodPolicy(node: TrieNode, method: string): { policy: CompiledRoutePolicy; exact: boolean } | undefined {
  const exact = node.routePolicies.get(method);
  if (exact !== undefined) {
    return { policy: exact, exact: true };
  }
  const wildcard = node.routePolicies.get("*");
  return wildcard === undefined ? undefined : { policy: wildcard, exact: false };
}

function selectActorPolicy(routePolicy: CompiledRoutePolicy, actorClass: ActorClass): ActorRoutePolicy {
  return routePolicy.perActorClass.get(actorClass) ?? routePolicy.defaultActorPolicy;
}

function defaultMatchedPolicy(policy: CompiledPolicyBundle, actorClass: ActorClass): MatchedPolicy {
  const defaultActorPolicy: ActorRoutePolicy = {
    actorClass: "*",
    decision: null,
    rate: policy.defaults.rate,
    strict: policy.defaults.strict,
    signatureRequired: [],
    queueRetrySeconds: 30,
    retryAfterSeconds: 30,
    sandboxOrigin: policy.defaults.sandboxOrigin,
    ruleId: "default:*"
  };
  const routePolicy: CompiledRoutePolicy = {
    ruleId: "default",
    routeTemplate: "/**",
    method: "*",
    routeBucket: "default",
    mode: policy.mode,
    strict: policy.defaults.strict,
    onDegraded: policy.defaults.onDegraded,
    signatureRequired: [],
    rate: policy.defaults.rate,
    queueRetrySeconds: 30,
    retryAfterSeconds: 30,
    sandboxOrigin: policy.defaults.sandboxOrigin,
    defaultActorPolicy,
    perActorClass: new Map()
  };
  return {
    routePolicy,
    actorPolicy: selectActorPolicy(routePolicy, actorClass),
    routeTemplate: "/**",
    params: {},
    matched: false
  };
}

export class PolicyTrie {
  readonly #root = new TrieNode();
  readonly #policy: CompiledPolicyBundle;

  constructor(policy: CompiledPolicyBundle) {
    this.#policy = policy;
    for (const route of policy.routes) {
      this.insert(route);
    }
  }

  insert(route: CompiledRoutePolicy): void {
    let node = this.#root;
    for (const segment of pathSegments(route.routeTemplate)) {
      if (segment === "*" || segment === "**") {
        if (node.wildcardChild === undefined) {
          node.wildcardChild = new TrieNode();
        }
        node = node.wildcardChild;
        break;
      }
      if (segment.startsWith(":")) {
        node = childForParam(node, segment.slice(1));
        continue;
      }
      let child = node.staticChildren.get(segment);
      if (child === undefined) {
        child = new TrieNode();
        node.staticChildren.set(segment, child);
      }
      node = child;
    }
    node.routePolicies.set(route.method, route);
  }

  match(methodInput: string, pathInput: string, actorClass: ActorClass): MatchedPolicy {
    const method = methodInput.toUpperCase();
    const segments = pathSegments(pathInput);
    const candidates: MatchCandidate[] = [];

    const visit = (node: TrieNode, depth: number, matched: string[], params: Record<string, string>, specificity: number): void => {
      if (depth === segments.length) {
        const found = methodPolicy(node, method);
        if (found !== undefined) {
          candidates.push({
            routePolicy: found.policy,
            routeTemplate: `/${matched.join("/")}`,
            params: { ...params },
            specificity,
            depth,
            methodExact: found.exact
          });
        }
      }

      const segment = segments[depth];
      if (segment !== undefined) {
        const staticChild = node.staticChildren.get(segment);
        if (staticChild !== undefined) {
          visit(staticChild, depth + 1, [...matched, segment], params, specificity + 4);
        }

        for (const paramChild of node.paramChildren) {
          visit(paramChild.node, depth + 1, [...matched, `:${paramChild.name}`], { ...params, [paramChild.name]: segment }, specificity + 2);
        }
      }

      if (node.wildcardChild !== undefined) {
        const rest = segments.slice(depth).join("/");
        const wildcardParams = rest.length === 0 ? params : { ...params, "*": rest };
        visit(node.wildcardChild, segments.length, [...matched, "*"], wildcardParams, specificity + 1);
      }
    };

    visit(this.#root, 0, [], {}, 0);

    candidates.sort((a, b) => {
      if (a.depth !== b.depth) {
        return b.depth - a.depth;
      }
      if (a.specificity !== b.specificity) {
        return b.specificity - a.specificity;
      }
      return Number(b.methodExact) - Number(a.methodExact);
    });

    const winner = candidates[0];
    if (winner === undefined) {
      return defaultMatchedPolicy(this.#policy, actorClass);
    }

    return {
      routePolicy: winner.routePolicy,
      actorPolicy: selectActorPolicy(winner.routePolicy, actorClass),
      routeTemplate: winner.routeTemplate,
      params: winner.params,
      matched: true
    };
  }
}

export function buildPolicyTrie(policy: CompiledPolicyBundle): PolicyTrie {
  return new PolicyTrie(policy);
}
