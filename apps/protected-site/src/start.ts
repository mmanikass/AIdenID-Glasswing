import { createProtectedSiteRuntime } from "./index.js";

const host = process.env.HOST ?? "127.0.0.1";
const port = Number.parseInt(process.env.PORT ?? "3101", 10);
if (!Number.isInteger(port) || port <= 0 || port > 65_535) {
  throw new Error("PORT must be a valid TCP port");
}

const runtime = await createProtectedSiteRuntime({ logger: true });
await runtime.app.listen({ host, port });
console.log(JSON.stringify({ event: "protected_site_listening", host, port, site_id: runtime.siteId }));

const close = async () => {
  await runtime.close();
};
process.once("SIGINT", () => void close().then(() => process.exit(0)));
process.once("SIGTERM", () => void close().then(() => process.exit(0)));
