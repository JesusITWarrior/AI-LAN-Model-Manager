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

/** Create the HTTP server without listening. An injected management handler owns /api/v1. */
export function createControllerServer(management?: ControllerRequestHandler) {
  return createServer((request, response) => {
    const path = request.url?.split("?", 1)[0] ?? "";
    if (management && (path === "/api/v1" || path.startsWith("/api/v1/"))) {
      management(request, response);
      return;
    }
    handleRequest(request, response);
  });
}
