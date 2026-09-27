import { z } from "zod";
import type { FastifyInstance } from "fastify";

import { requireOperatorRole } from "../plugins/operatorAuth.js";
import type { ControlPlaneServices, KillSwitchState } from "../types.js";

const VerifierModeSchema = z.enum(["observe", "recommend", "enforce"]);

const KillSwitchUpdateRequestSchema = z
  .object({
    active: z.boolean(),
    reason: z.string().min(1),
    actor_id: z.string().min(1),
    deny_new_sessions: z.boolean().optional(),
    global_enforcement_pause: z.boolean().optional(),
    route_mode_overrides: z.record(z.string().regex(/^\//), VerifierModeSchema).optional(),
    crypto_path_rollout: z.enum(["disabled", "shadow", "enforce"]).optional(),
    min_revocation_epoch: z.number().int().nonnegative().optional()
  })
  .strict();

const KillSwitchClearRequestSchema = z
  .object({
    reason: z.string().min(1),
    actor_id: z.string().min(1)
  })
  .strict();

function serializeState(state: KillSwitchState) {
  return {
    active: state.active,
    deny_new_sessions: state.denyNewSessions,
    global_enforcement_pause: state.globalEnforcementPause,
    route_mode_overrides: state.routeModeOverrides,
    crypto_path_rollout: state.cryptoPathRollout,
    ...(state.minRevocationEpoch === undefined ? {} : { min_revocation_epoch: state.minRevocationEpoch }),
    ...(state.reason === undefined ? {} : { reason: state.reason }),
    ...(state.actorId === undefined ? {} : { actor_id: state.actorId }),
    ...(state.updatedAt === undefined ? {} : { updated_at: state.updatedAt })
  };
}

export async function registerKillSwitchRoutes(app: FastifyInstance, services: ControlPlaneServices): Promise<void> {
  // Read-gated: the state discloses the enforcement posture — which routes are downgraded to
  // observe, whether the crypto path is disabled, the current revocation epoch. That is a map of
  // where enforcement is weakest, so it is not public.
  app.get("/v1/kill-switch", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "decision_search");
    if (operator === undefined) {
      return;
    }
    return serializeState(services.killSwitch.current());
  });

  // Admin-gated: this is the control that exists to stop an incident, and ungated it could be
  // switched off BY one. An anonymous caller could set global_enforcement_pause, downgrade chosen
  // routes to observe, disable the crypto path, or move min_revocation_epoch.
  app.post("/v1/kill-switch", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "admin");
    if (operator === undefined) {
      return;
    }
    const parsed = KillSwitchUpdateRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_kill_switch_update", details: parsed.error.issues });
    }
    // The actor recorded against an enforcement change is bound to the authenticated principal.
    // A disagreeing body value is rejected rather than discarded, so the caller never believes it
    // attributed the change to someone else.
    if (parsed.data.actor_id !== operator.actorId) {
      return reply.code(400).send({ error: "actor_id_mismatch", expected_actor_id: operator.actorId });
    }

    const state = services.killSwitch.update({
      active: parsed.data.active,
      reason: parsed.data.reason,
      actorId: operator.actorId,
      denyNewSessions: parsed.data.deny_new_sessions,
      globalEnforcementPause: parsed.data.global_enforcement_pause,
      routeModeOverrides: parsed.data.route_mode_overrides,
      cryptoPathRollout: parsed.data.crypto_path_rollout,
      minRevocationEpoch: parsed.data.min_revocation_epoch
    });

    return reply.code(200).send(serializeState(state));
  });

  // Admin-gated: clearing the kill switch re-enables whatever it was suppressing.
  app.delete("/v1/kill-switch", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "admin");
    if (operator === undefined) {
      return;
    }
    const parsed = KillSwitchClearRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_kill_switch_clear", details: parsed.error.issues });
    }
    if (parsed.data.actor_id !== operator.actorId) {
      return reply.code(400).send({ error: "actor_id_mismatch", expected_actor_id: operator.actorId });
    }

    return reply.code(200).send(
      serializeState(
        services.killSwitch.clear({
          reason: parsed.data.reason,
          actorId: operator.actorId
        })
      )
    );
  });
}
