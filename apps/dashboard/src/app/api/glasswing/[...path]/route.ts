import { proxyGlasswingRequest } from "../../../../glasswing/proxy.js";

export const dynamic = "force-dynamic";

type RouteContext = { readonly params: Promise<{ readonly path?: readonly string[] | undefined }> };

async function handle(request: Request, context: RouteContext): Promise<Response> {
  const { path } = await context.params;
  return proxyGlasswingRequest({ request, segments: path ?? [], env: process.env });
}

export async function GET(request: Request, context: RouteContext): Promise<Response> {
  return handle(request, context);
}

export async function POST(request: Request, context: RouteContext): Promise<Response> {
  return handle(request, context);
}
