import { createProtectedSiteRuntime } from "./index.js";

const host = process.env.HOST ?? "127.0.0.1";
const port = Number.parseInt(process.env.PORT ?? "4100", 10);
const controlPlanePort = Number.parseInt(process.env.AIDENID_CONTROL_PLANE_PORT ?? "4000", 10);
const operatorToken = process.env.GLASSWING_OPERATOR_TOKEN;
if (host !== "127.0.0.1" && host !== "::1") {
  throw new Error("the protected-site demo must bind to a loopback address");
}
if (!Number.isInteger(port) || port <= 0 || port > 65_535) {
  throw new Error("PORT must be a valid TCP port");
}
if (!Number.isInteger(controlPlanePort) || controlPlanePort <= 0 || controlPlanePort > 65_535 || controlPlanePort === port) {
  throw new Error("AIDENID_CONTROL_PLANE_PORT must be a valid TCP port distinct from PORT");
}
if (operatorToken === undefined || Buffer.byteLength(operatorToken, "utf8") < 32) {
  throw new Error("GLASSWING_OPERATOR_TOKEN must contain at least 32 bytes and stay server-side");
}

const runtime = await createProtectedSiteRuntime({ logger: true, operatorToken });
try {
  await runtime.controlPlane.app.listen({ host, port: controlPlanePort });
  await runtime.app.listen({ host, port });
} catch (error) {
  await runtime.close();
  throw error;
}
console.log(JSON.stringify({ event: "protected_site_listening", host, port, control_plane_port: controlPlanePort, site_id: runtime.siteId }));

const close = async () => {
  await runtime.close();
};
process.once("SIGINT", () => void close().then(() => process.exit(0)));
process.once("SIGTERM", () => void close().then(() => process.exit(0)));
