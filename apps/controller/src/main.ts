import { resolve } from "node:path";
import { createControllerServer } from "./app.js";
import { createControllerPathPlan, parseControllerEnvironment } from "./config.js";

// Ambient process state is confined to this production boundary. The parser is
// deterministic: it receives the state-root default and path flavor explicitly,
// and neither configuration parsing nor path planning performs file-system I/O.
const pathFlavor = process.platform === "win32" ? "win32" : "posix";
const parsed = parseControllerEnvironment(
  { ...process.env },
  { defaultDataRoot: resolve(process.cwd(), "data"), pathFlavor },
);
if (!parsed.ok) throw new Error(`Controller configuration rejected: ${parsed.error}`);
const pathPlan = createControllerPathPlan(parsed.value.dataDir, pathFlavor);
if (!pathPlan.ok) throw new Error(`Controller state path rejected: ${pathPlan.error}`);

createControllerServer().listen(parsed.value.port, parsed.value.bindHost, () => {
  console.log("LAN Model Manager development controller listening on loopback");
});
