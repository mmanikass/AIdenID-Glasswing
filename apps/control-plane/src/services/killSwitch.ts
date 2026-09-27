import type { KillSwitchController, KillSwitchState, KillSwitchUpdate } from "../types.js";

const DEFAULT_STATE: KillSwitchState = {
  active: false,
  denyNewSessions: false,
  globalEnforcementPause: false,
  routeModeOverrides: {},
  cryptoPathRollout: "enforce"
};

function cloneState(state: KillSwitchState): KillSwitchState {
  return {
    ...state,
    routeModeOverrides: { ...state.routeModeOverrides }
  };
}

export class InMemoryKillSwitchController implements KillSwitchController {
  private state: KillSwitchState = DEFAULT_STATE;

  current(): KillSwitchState {
    return cloneState(this.state);
  }

  update(input: KillSwitchUpdate): KillSwitchState {
    this.state = {
      active: input.active,
      denyNewSessions: input.denyNewSessions ?? input.active,
      globalEnforcementPause: input.globalEnforcementPause ?? input.active,
      routeModeOverrides: { ...(input.routeModeOverrides ?? {}) },
      cryptoPathRollout: input.cryptoPathRollout ?? (input.active ? "shadow" : "enforce"),
      ...(input.minRevocationEpoch === undefined ? {} : { minRevocationEpoch: input.minRevocationEpoch }),
      reason: input.reason,
      actorId: input.actorId,
      updatedAt: input.updatedAt ?? new Date().toISOString()
    };
    return this.current();
  }

  clear(input: { readonly reason: string; readonly actorId: string; readonly updatedAt?: string | undefined }): KillSwitchState {
    this.state = {
      ...DEFAULT_STATE,
      reason: input.reason,
      actorId: input.actorId,
      updatedAt: input.updatedAt ?? new Date().toISOString()
    };
    return this.current();
  }
}
