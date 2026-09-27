import { checkControlPlaneHealth } from "../../../../controlPlaneHealth.js";

export const dynamic = "force-dynamic";

export async function GET(): Promise<Response> {
  const state = await checkControlPlaneHealth({
    AIDENID_CONTROL_PLANE_URL: process.env.AIDENID_CONTROL_PLANE_URL,
  });
  return Response.json(
    { state },
    {
      headers: {
        "Cache-Control": "no-store",
      },
    },
  );
}
