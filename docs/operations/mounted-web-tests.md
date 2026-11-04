# Mounted lifecycle UI regression

Run `npm test -w @lan-model-manager/web` from the repository root after installing the project's locked dependencies. The web suite includes a real mounted React lifecycle test, not only server-rendered markup or action helpers.

## Browser prerequisite

An existing Chromium-compatible executable is required. The default executable is `/usr/bin/chromium-browser`; set `CHROMIUM_PATH` to an appropriate existing executable on another host. The test does not install a browser and deliberately fails rather than silently skipping mounted coverage when the executable is missing. Its process-group cleanup harness is qualified on Linux; passing this test does not establish Windows or macOS browser-harness qualification.

The fixture uses esbuild from the existing dependency tree, an isolated temporary browser profile, synthetic inventory and credentials, and loopback HTTP listeners. It starts and restarts a disposable production controller against a temporary database. It never uses an operator's browser profile, installed controller, provider, or model. Browser processes, listeners, and temporary state are cleaned when the test finishes or an assertion fails.

The regression drives actual rendered controls through prepared and approved reviews lost after controller restart. It verifies explicit local forgetting, distinct server-generated proposal IDs on reprepare, no implicit execution or cancellation, active-job tracking, stale-response rejection, and model isolation. Waits synchronize on rendered **enabled controls**, not storage writes that may precede React's commit.

Run full backend/Go gates with `make check`, then the web suite sequentially when collecting acceptance evidence. A mounted fixture pass is not live installed-service, multi-host, or real-provider qualification.
