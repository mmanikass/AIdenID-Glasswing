import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath, URL } from "node:url";

import { buildOpenApiDocument } from "../dist/openapi.js";

const outUrl = new URL("../../../docs/api/openapi.json", import.meta.url);
const outPath = fileURLToPath(outUrl);

await mkdir(dirname(outPath), { recursive: true });
await writeFile(outPath, `${JSON.stringify(buildOpenApiDocument(), null, 2)}\n`, "utf8");
