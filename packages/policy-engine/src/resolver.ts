import type { ActorClass, DecisionAction, VerifierMode } from "./types.js";

export interface RouteRule {
  readonly methodPattern: string;
  readonly routeTemplate: string;
  readonly actorClass: ActorClass | "*";
  readonly behavior: DecisionAction;
  readonly ruleId: string;
  readonly priceUsd?: number | undefined;
}

export interface PermissionResolution {
  readonly decision: DecisionAction;
  readonly recommendedDecision: DecisionAction;
  readonly ruleId?: string | undefined;
  readonly observedOnly: boolean;
}

function splitTemplate(template: string): string[] {
  return template.split("/").filter(Boolean);
}

function routeMatches(template: string, route: string): boolean {
  const templateSegments = splitTemplate(template);
  const routeSegments = splitTemplate(route);

  for (let index = 0; index < templateSegments.length; index += 1) {
    const templateSegment = templateSegments[index];
    const routeSegment = routeSegments[index];
    if (templateSegment === "*" || templateSegment === "**") {
      return true;
    }
    if (routeSegment === undefined) {
      return false;
    }
    if (templateSegment?.startsWith(":")) {
      continue;
    }
    if (templateSegment !== routeSegment) {
      return false;
    }
  }

  return templateSegments.length === routeSegments.length;
}

function specificity(rule: RouteRule, actorClass: ActorClass): number {
  const routeScore = splitTemplate(rule.routeTemplate).reduce((score, segment) => {
    if (segment === "*" || segment === "**") {
      return score + 1;
    }
    if (segment.startsWith(":")) {
      return score + 2;
    }
    return score + 4;
  }, 0);
  return routeScore + (rule.actorClass === actorClass ? 8 : 0) + (rule.methodPattern === "*" ? 0 : 4);
}

function matches(rule: RouteRule, method: string, route: string, actorClass: ActorClass): boolean {
  const methodMatches = rule.methodPattern === "*" || rule.methodPattern.toUpperCase() === method.toUpperCase();
  const actorMatches = rule.actorClass === "*" || rule.actorClass === actorClass;
  return methodMatches && actorMatches && routeMatches(rule.routeTemplate, route);
}

function fallbackForMode(mode: VerifierMode): DecisionAction {
  return mode === "enforce" ? "deny" : "allow";
}

export function resolveDecision(
  rules: readonly RouteRule[],
  method: string,
  route: string,
  actorClass: ActorClass,
  mode: VerifierMode
): PermissionResolution {
  const denyRule = rules.find((rule) => rule.behavior === "deny" && matches(rule, method, route, actorClass));
  if (denyRule !== undefined) {
    return {
      decision: mode === "enforce" ? "deny" : "allow",
      recommendedDecision: "deny",
      ruleId: denyRule.ruleId,
      observedOnly: mode !== "enforce"
    };
  }

  const winner = rules
    .filter((rule) => matches(rule, method, route, actorClass))
    .sort((a, b) => specificity(b, actorClass) - specificity(a, actorClass))[0];

  if (winner === undefined) {
    const fallback = fallbackForMode(mode);
    return {
      decision: fallback,
      recommendedDecision: fallback,
      observedOnly: mode !== "enforce"
    };
  }

  if (mode === "observe" || mode === "recommend") {
    return {
      decision: "allow",
      recommendedDecision: winner.behavior,
      ruleId: winner.ruleId,
      observedOnly: true
    };
  }

  return {
    decision: winner.behavior,
    recommendedDecision: winner.behavior,
    ruleId: winner.ruleId,
    observedOnly: false
  };
}
