import { dashboardRuntimeStatusFromEnv } from "../../../dashboardStatus.js";

export const dynamic = "force-dynamic";

export function GET(): Response {
  return Response.json(dashboardRuntimeStatusFromEnv(process.env), {
    headers: {
      "Cache-Control": "no-store",
    },
  });
}
