# proxmox-axi

AXI-standard agent-facing CLI for Proxmox VE.
This build provides the standalone portion of S1.1: an authenticated version read through the installed package.
Actual Artium client/server admission is pending and full S1.1 has not passed.
Other API operations, session authentication and writes are not admitted in this build.

Use Node 24.14.0 and pnpm 10.22.0.
Node's supported minimum is 24.11.0; `.node-version` pins the tested runtime.
TypeScript 5.9.3, Node types 22.20.5, TOON 2.3.1 and Ajv 8.20.0 align with the checked Artium toolchain.
The lockfile pins every transitive dependency and its integrity.
The fast-uri override retains the checked host's exact 3.1.8 version.

```sh
pnpm install --offline --frozen-lockfile
pnpm build
node bin/proxmox-axi.mjs get --help
node bin/proxmox-axi.mjs --version
pnpm lint
pnpm test
```

`get /version` uses trusted HTTPS, a five-second total deadline and a 64 KiB response bound.
It rejects redirects and validates the version response before formatting it as TOON or JSON.
HTTP 401 returns a nonzero `AUTH_REQUIRED` result; malformed successful responses return `INVALID_RESPONSE`.
Errors are structured on stdout and never include raw vendor bodies or transport diagnostics.

API token profiles use `auth: "api-token"`, an HTTPS `origin`, a full `tokenId` and an optional token SecretRef.
The shipped `axi-credential.schema.json` rejects unknown fields and inline secrets.
The default environment profile reads `PROXMOX_AXI_ORIGIN`, `PROXMOX_AXI_TOKEN_ID` and `PROXMOX_AXI_TOKEN`.
`PROXMOX_AXI_AUTH`, when supplied, must be `api-token`.
`PROXMOX_AXI_CA_BUNDLE` names an absolute trusted PEM file.
Token values never arrive through command arguments.

File configuration is selected by `--config`, `PROXMOX_AXI_CONFIG`, or the OS configuration directory's `proxmox-axi/config.json`.
On Linux, an absolute `XDG_CONFIG_HOME` overrides `~/.config`.
On Windows the configuration directory is `%APPDATA%`, with an OS home-directory fallback.
The file shape is `{ "version": 1, "defaultProfile": "lab", "profiles": { "lab": { ... } } }`.
Select a file profile with `--profile` or `PROXMOX_AXI_PROFILE` to ignore competing environment-profile fields.
Otherwise a complete environment profile takes precedence over file defaults; partial environment profiles fail.
A token reference is exactly `{ "env": "VARIABLE_NAME" }` or `{ "file": "/absolute/protected/path" }`.
An omitted reference defaults to `{ "env": "PROXMOX_AXI_TOKEN" }`.
`auth status` reports the selected sources without their secret values and sends no request.
The tool never reads baseline clients' configuration or writes credential files.
Native Windows proof and the remaining credential cases belong to later plan tasks.

`src/operations.json` owns the admitted route and response fields.
`src/profile-schema.json` owns the current profile contract and runtime validation.
`pnpm generate` generates inventory, help metadata and the shipped credential schema; `pnpm lint` rejects stale output.
Never edit generated files by hand.

The public acceptance entry installs a packed tarball into an isolated consumer and executes its exact binary, alongside a competing same-name executable.
It uses real loopback HTTPS and synthetic credentials inside a Linux user/network namespace containing only loopback.
An external connection must fail with `ENETUNREACH` before any product journey runs.
Linux user/network namespaces, iproute2 and OpenSSL are required; missing isolation fails the check.
Dependencies must already be available in the pnpm store; acceptance installs are offline.

```sh
pnpm verify:acceptance -- --task S1.1 --pack /absolute/path/to/pack --out /absolute/new/run/S1.1 --network fake-only --through standalone
```

Use this repository's `evidence` directory or the complete approved evidence pack for `--pack`.
Create the parent run directory first; the task output directory must be new and outside the checkout.
The driver verifies retained fixture hashes and records package integrity, fixture identity, sanitized public transcripts, case outcomes and the fake request ledger.
Private scratch state and canary values are removed before it returns.
Transport diagnostics observe Node's error channel without replacing HTTP or TLS behavior and retain only error codes and timings.
Set `PROXMOX_AXI_TEST_FAILURE_DIR` to an external directory to preserve sanitized evidence when a test fails.
The two sanitized captures under `evidence/` are byte-preserved; their provenance and hashes are listed in `evidence/README.md`.

`--through both` runs the standalone checks and then fails explicitly because actual Artium admission is pending.
An adapter substitute cannot satisfy that selection.
The approved host baseline is Artium revision `4fc023c9ff7605980b8d34339b36528aa015c1f1`; the host owner must supply a reviewed admission revision before hosted verification can pass.
No live Proxmox, deployment, publication or hosted CI is part of these checks.
