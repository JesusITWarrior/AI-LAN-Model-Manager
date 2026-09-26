import { createControllerServer } from "./app.js";

const host = process.env.LMM_BIND_HOST ?? "127.0.0.1";
const port = Number.parseInt(process.env.LMM_PORT ?? "7340", 10);
if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
  throw new Error("LMM_PORT must be an integer from 1 through 65535");
}
createControllerServer().listen(port, host, () => {
  console.log(`LAN Model Manager development controller listening on http://${host}:${port}`);
});
