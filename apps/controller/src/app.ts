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

export function createControllerServer() {
  return createServer(handleRequest);
}
