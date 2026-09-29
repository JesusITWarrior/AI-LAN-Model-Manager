import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

export function handleRequest(request: IncomingMessage, response: ServerResponse): void {
  response.setHeader("content-type", "application/json; charset=utf-8");
  if (request.method === "GET" && request.url === "/health") {
    response.writeHead(200);
    response.end(JSON.stringify({ status: "ok", exposure: "development-loopback-only" }));
    return;
  }
  response.writeHead(404);
  response.end(JSON.stringify({ error: "not_found" }));
}

export type ControllerRequestHandler = (request: IncomingMessage, response: ServerResponse) => void;

/** Create the HTTP server without listening; the static handler is always the final route. */
export function createControllerServer(
  management?: ControllerRequestHandler,
  inference?: ControllerRequestHandler,
  auth?: ControllerRequestHandler,
  staticContent?: ControllerRequestHandler,
  enrollment?: ControllerRequestHandler,
) {
  return createServer((request, response) => {
    const path = request.url?.split("?", 1)[0] ?? "";
    if (path === "/health") { handleRequest(request, response); return; }
    if (auth && (path === "/auth/v1" || path.startsWith("/auth/v1/"))) { auth(request, response); return; }
    if (management && (path === "/api/v1" || path.startsWith("/api/v1/"))) { management(request, response); return; }
    if (enrollment && (path === "/agent/v1/enrollment" || path.startsWith("/agent/v1/enrollment/"))) { enrollment(request, response); return; }
    if (inference && (path === "/v1" || path.startsWith("/v1/"))) { inference(request, response); return; }
    if (staticContent) { staticContent(request, response); return; }
    handleRequest(request, response);
  });
}
