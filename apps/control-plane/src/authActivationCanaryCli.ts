import { runControlPlaneAuthActivationCanary } from "./canaries/authActivation.js";

const usage =
  "usage: node dist/authActivationCanaryCli.js --request-id <id> --site-id <sit_...> --service-actor-id <actor> [--timeout-ms <1000-120000>]";

function parseArguments(args: readonly string[]): {
  readonly requestId: string;
  readonly siteId: string;
  readonly serviceActorId: string;
  readonly timeoutMs?: number | undefined;
} {
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (
      name === undefined ||
      !name.startsWith("--") ||
      value === undefined ||
      value.startsWith("--")
    ) {
      throw new Error(usage);
    }
    if (values.has(name)) {
      throw new Error(`duplicate option: ${name}`);
    }
    values.set(name, value);
  }
  for (const name of values.keys()) {
    if (
      ![
        "--request-id",
        "--site-id",
        "--service-actor-id",
        "--timeout-ms",
      ].includes(name)
    ) {
      throw new Error(`unknown option: ${name}`);
    }
  }
  const requestId = values.get("--request-id");
  const siteId = values.get("--site-id");
  const serviceActorId = values.get("--service-actor-id");
  if (
    requestId === undefined ||
    siteId === undefined ||
    serviceActorId === undefined
  ) {
    throw new Error(usage);
  }
  const timeoutRaw = values.get("--timeout-ms");
  const timeoutMs = timeoutRaw === undefined ? undefined : Number(timeoutRaw);
  return { requestId, siteId, serviceActorId, timeoutMs };
}

try {
  const result = await runControlPlaneAuthActivationCanary(
    parseArguments(process.argv.slice(2)),
  );
  console.log(JSON.stringify(result));
} catch (error) {
  console.error(
    JSON.stringify({
      event: "control_plane_auth_activation_canary_failed",
      error: error instanceof Error ? error.message : String(error),
    }),
  );
  process.exitCode = 1;
}
