# Codex Task Prompt: Add CAC + SAML SSO support end-to-end (Ubuntu 22.04 + 24.04) starting from Rybar/GlobalProtect-openconnect

You are working in this repo as the integration surface:
- https://github.com/Rybar/GlobalProtect-openconnect (fork of yuezk/GlobalProtect-openconnect)
Goal: make GlobalProtect connections succeed when the portal requires **SAML REDIRECT SSO** and the user authenticates with a **CAC via PKCS#11**, and ensure **HIP report submission** works. The result must run cleanly on **Ubuntu 22.04 and Ubuntu 24.04**.

## What is broken today (symptoms to reproduce)
1) OpenConnect GP fails after prelogin shows `SAML REDIRECT authentication is required...` and then errors like:
- “Failed to parse XML server response”
- “Failed to complete authentication”
2) globalprotect-openconnect (gpclient/gpservice) can obtain portal config but fails later at `/ssl-vpn/getconfig.esp` with non-XML error: `errors getting SSL/VPN config` or similar.
3) CAC can work via OpenConnect CLI if the PKCS#11 object URL is correct, but gpclient `--certificate` currently expects a file and does not support PKCS#11 URIs.

## High-level target behavior
- User can run ONE of these successfully:
  A) `gpclient connect --os Windows --hip --browser firefox --certificate <CAC_PKCS11_URI> <PORTAL>`
  B) GUI can connect using the same backend path (gpservice) and no manual cookie copying.
- If portal requires SAML redirect, the client launches an external browser (or headless remote mode), captures the SAML result, completes portal auth, then proceeds to gateway login and the `getconfig.esp` stage without XML parse failures.
- HIP report is generated and submitted (CSD wrapper path) before tunnel establishment if required by policy.
- Works on Ubuntu 22.04 and 24.04, both in local builds and CI.

## Deliverables
1) Code changes in Rybar/GlobalProtect-openconnect:
   - gpclient supports PKCS#11 certificate URIs (CAC) and passes them through properly.
   - SAML REDIRECT auth works reliably.
   - HIP submission works with a single flag (`--hip`), with good logs and error messages.
2) A minimal test matrix:
   - CI builds on ubuntu-22.04 and ubuntu-24.04
   - Unit tests for URL parsing, redirect handling, cookie extraction, config XML parsing
   - Integration test harness that mocks portal endpoints (HTTP test server) to simulate:
     - prelogin XML with SAML REDIRECT fields
     - SAML login finalization returning portal-userauthcookie
     - gateway login returning jnlp args
     - getconfig.esp returning valid XML
3) Documentation updates in README:
   - CAC usage examples (PKCS#11)
   - SAML SSO flow explanation (browser and remote mode)
   - HIP usage examples, plus troubleshooting steps and common failure modes

## Constraints and non-goals
- Do not require the proprietary Palo Alto client.
- Do not hardcode organization-specific URLs.
- Do not disable TLS verification by default; keep `--ignore-tls-errors` explicit and loudly warned.
- Prefer using system OpenConnect libraries where possible, but we are allowed to patch OpenConnect behavior if needed.
- Avoid distro-specific hacks that only work on 24.04.

## Implementation plan (do this in phases, commit per phase)

### Phase 0: Repo reconnaissance and build baseline
- Identify how Rybar fork currently integrates OpenConnect:
  - Is it linking system libopenconnect via FFI, vendoring code, or shelling out?
  - Find crates responsible: likely `crates/openconnect-*`, `crates/gpapi`, `apps/gpclient`, `crates/gpauth`.
- Make `just` or `make` build work on ubuntu-22.04 and ubuntu-24.04 in CI.
- Add a “developer smoke test” command to build gpclient and run `gpclient --version`.

### Phase 1: Fix CAC certificate handling in gpclient
Problem: gpclient `--certificate` currently tries to read a file and fails when user passes `pkcs11:...`.

Implement:
- Treat `--certificate` as either:
  1) a filesystem path (.pem/.p12/.pfx)
  2) a PKCS#11 URI (starts with `pkcs11:`) to be passed through untouched
- Add a new option if needed (only if you cannot do it cleanly without ambiguity):
  - `--pkcs11-certificate <PKCS11_URI>` as an alias, but keep `--certificate` working.

Where to wire it:
- Locate the layer that translates gpclient options to OpenConnect options / FFI struct fields.
- If OpenConnect is invoked through a library call:
  - ensure the certificate string is passed as-is to the OpenConnect API that accepts `--certificate`.
- If OpenConnect is executed as a process:
  - pass `--certificate=<PKCS11_URI>` literally.
- Add helpful error output:
  - if a string contains `pkcs11:` but code tries to open it as a file, that is a bug, fix it.

Tests:
- Unit tests for detecting PKCS#11 URIs.
- Unit tests for file path handling remains unchanged.

Docs:
- Add examples for OpenSC provider usage:
  - show how to find the object with `p11tool --list-all --provider /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`
  - example PKCS#11 URL pattern including `object=Certificate for PIV Authentication;type=cert;id=%01`
  - note that exact object names vary.

### Phase 2: Implement SAML REDIRECT auth completion (SSO)
This is the core. OpenConnect GP currently prints:
- “SAML REDIRECT authentication is required via <URL>”
and then fails because it never completes the SAML flow and never obtains a valid auth cookie / config XML.

We will implement an automated SAML flow in the Rybar project, not in the user’s shell script.
Design:
- Add a SAML handler module in Rust (preferably in `crates/gpauth` or `crates/gpapi`) that:
  1) Calls portal prelogin endpoint and parses XML.
  2) Detects `saml-auth-method=REDIRECT` and extracts:
     - `saml-request` (base64)
     - the IdP redirect URL (often Keycloak/Okta/Azure)
     - relay state if present
     - any request timeout
  3) Launches external browser (existing gpauth behavior likely already does this) and runs a local callback listener:
     - Support modes: `--browser firefox|chrome|chromium|default|remote`
     - In remote mode: print URL to open elsewhere, and keep waiting for callback.
  4) Captures the final SAML response payload needed by the portal:
     - This usually ends with a POST containing `SAMLResponse` + `RelayState`, or a redirect that results in portal setting cookies.
  5) Completes portal authentication by POSTing back to the GlobalProtect portal endpoint that exchanges SAML for `portal-userauthcookie`.
  6) Returns the cookie string to gpclient so the connect step uses `--cookie-on-stdin` equivalent internally.

Key requirement:
- The connect pipeline must become:
  - prelogin -> (SSO if needed) -> portal config -> gateway login -> getconfig.esp -> tunnel

Implementation specifics:
- Reuse existing browser auth server approach already in this project (gpauth logs show it listens on 127.0.0.1 and receives data).
- Make sure cookies are stored and reused unless `--clean` is set.
- Improve logging:
  - clearly distinguish “portal prelogin”, “SSO browser started”, “SSO completed”, “portal cookie obtained”, “gateway login started”.

Tests:
- Add a mocked HTTP server test that simulates:
  - prelogin XML requiring SAML REDIRECT with a fake IdP URL
  - fake IdP redirects back to local callback with fake payload
  - portal “exchange SAML for cookie” returns a deterministic cookie
  - portal config returns XML including gateway list
- Ensure the test never launches a real browser: use “remote” mode and directly call the callback endpoint.

### Phase 3: Ensure OpenConnect consumes the cookie and does not try to redo SAML
Once the cookie exists, OpenConnect should not attempt to parse SAML XML again. It should proceed with the GP protocol.

Implement:
- In the integration layer, pass the cookie to OpenConnect using its cookie mechanism:
  - If using OpenConnect library API: set the cookie appropriately (equivalent to `-C/--cookie`).
  - If shelling out: pass `--cookie <cookie>` or pipe via stdin.
- Verify that the subsequent GP endpoints return XML and are parsed successfully.
- If OpenConnect still fails parsing non-XML at `getconfig.esp`, capture the HTTP body and status code at debug level and surface it cleanly. Non-XML often indicates “not authenticated” or “missing HIP” or “policy denies this OS string”.

### Phase 4: HIP report integration (CSD wrapper)
We want:
- `gpclient connect --hip` to reliably generate and send HIP report.

Implement:
- Ensure `--hip` triggers the same behavior as `--csd-wrapper=/usr/libexec/gpclient/hipreport.sh` and uses the correct `--csd-user`.
- Verify the script exists in packaging and runtime paths on both Ubuntu versions.
- If the portal requires HIP before getconfig, ensure HIP happens at the right time. If needed, force trojan run earlier in the state machine (before getconfig).
- Add structured logs: “HIP report generated”, “HIP upload success/failure”.

Tests:
- Mock OpenConnect CSD invocation if possible; otherwise, add a unit test for selecting the wrapper path and arguments.
- Integration test should simulate a portal response that rejects getconfig until HIP is present, then accepts once HIP is sent.

### Phase 5: Ubuntu 22.04 and 24.04 packaging and dependency sanity
- Add GitHub Actions workflow:
  - matrix: ubuntu-22.04, ubuntu-24.04
  - build Rust workspace
  - run unit tests
  - run mocked integration tests
- Document runtime dependencies:
  - openconnect (or libopenconnect), gnutls, opensc, p11-kit, webkit/tauri deps if needed for GUI, vpnc-script.
- Ensure paths used are correct on both Ubuntu versions:
  - `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`
  - `/usr/share/vpnc-scripts/vpnc-script`
  - `/usr/libexec/gpclient/hipreport.sh` (confirm packaging places it here, otherwise adjust to a robust search strategy)

### Phase 6: CLI ergonomics and troubleshooting outputs
- Add a `gpclient diagnose` command (optional if quick), or enhance verbose output to print:
  - detected OpenConnect version/features (PKCS#11 supported)
  - selected certificate mode (file vs pkcs11)
  - portal version, selected gateway
  - where HIP wrapper was found
- Add a “common errors” section in README:
  - “Failed to parse XML server response” after SAML indicates missing cookie exchange, show how to enable trace logs.
  - “errors getting SSL/VPN config” indicates auth/HIP/policy denial, instruct how to dump HTTP body in trace mode.
  - CAC object not found: show `p11tool` and how to construct URI.

## Acceptance criteria
- On Ubuntu 22.04 and 24.04, a user with CAC can connect to a portal that requires SAML REDIRECT by running:
  - `gpclient connect --os Windows --hip --browser firefox --certificate 'pkcs11:...;type=cert' <portal>`
- The connection no longer fails with “Failed to parse XML server response” at the SAML step.
- HIP report is generated and sent when `--hip` is provided, and disabling it reproduces the expected policy failure on portals that require HIP.
- CI passes for both Ubuntu versions.

## Output format requested
- Implement the changes with clear commits.
- Provide a short final summary of what was changed, how to use it, and where to look in logs.
- Update README with examples and troubleshooting.

Start by implementing Phase 0 and Phase 1 first, then proceed sequentially.
