# proxmox-axi

AXI-standard agent-facing CLI for Proxmox VE.
This build provides S1.1: an authenticated version read through the installed package, standalone and through an actual local Artium client/server/runner.
Hosted verification uses an explicitly approved, unmerged temporary admission fixture; stock Artium remains unsupported.
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
# Select the externally prepared, pinned local admission fixture before tests.
export PROXMOX_AXI_ARTIUM_FIXTURE=/absolute/path/to/prepared/artium
export PROXMOX_AXI_ARTIUM_MANIFEST=/absolute/path/to/captured/manifest.json
pnpm test
```

`get /version` uses trusted HTTPS, a five-second total deadline and a 64 KiB response bound.
It rejects redirects and validates the version response before formatting it as TOON or JSON.
HTTP 401 returns a nonzero `AUTH_REQUIRED` result; malformed successful responses return `INVALID_RESPONSE`.
Errors are structured on stdout and never include raw vendor bodies or transport diagnostics.
An interrupted HTTPS response returns `CONNECTION_FAILED`; the total deadline and response bound retain `TIMEOUT` and `OUTPUT_LIMIT`.

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

`--through both` requires the two external fixture inputs above and fails if either is missing or its pinned identity differs.
The selected temporary admission revision is `6d1e406705803a657241295ddf322b4c21fb4ef9`, recorded with the captured manifest digest in `test/artium-fixture.json`.
Prepare it from an exact `git archive` export, install its frozen dependencies offline, and follow its fixture startup guide in task-owned scratch space.
For a Git-free export, invoke the host compiler, copy its store migrations into `dist/src/server/store/migrations`, and run `scripts/build-cli.mjs`; its aggregate build wrapper requires Git metadata.
The retained `runtimeHashes` in `test/artium-fixture.json` pin the compiled runtime files from that build, including the fixture builder, session module and bundled public client.
The driver checks those SHA-256 digests before loading the host, importing the session module or invoking the client, and retains them in the host identity evidence.
Missing or substituted runtime files fail the check even when the TypeScript source is unchanged.
Keep the manifest snapshot and its original tarballs together outside this repository.
The manifest's Proxmox archive is used for both journeys, and its executable, admitted runtime sources and runtime package metadata must match the current build.
The response-stream error correction changes the shipped transport runtime, so the previously admitted archive cannot validate this build.
Before `--through both` can pass, the outer executor needs a newly approved package archive and admission inventory/manifest with corresponding reviewed pins.
The existing archive, manifest and host-runtime pins remain enforced until that fixture refresh is approved.
The host runs the existing credential store, profile writer, adapter and runner with a synthetic user from its own fixture builder.
The actual public client authenticates against the listening server and executes the version read over loopback HTTP; the vendor boundary remains trusted HTTPS.
Evidence includes the host revision, manifest and client digests, startup record, client invocation, real audit outcomes, injected credential-source diagnostics and runner cleanup.
The hosted canary differs from the standalone token, while a competing developer profile and environment remain present.
An adapter substitute cannot satisfy this selection.
Run the full S1.1 check with the same acceptance command above and `--through both`.
No live Proxmox, deployment, publication or hosted CI is part of these checks.
