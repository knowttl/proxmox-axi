# proxmox-axi

AXI-standard agent-facing CLI for Proxmox VE.
This build provides canonical API-token credentials, bounded trusted HTTPS, and versioned invocation discovery for the 681-route Proxmox API union.
Hosted verification uses an explicitly approved, unmerged temporary admission fixture; stock Artium remains unsupported.
Nine ordinary read routes have reviewed admission policy.
Other operations remain discoverable but uncallable until their effects, transport and secret handling are reviewed.
Session authentication, writes, downloads and duplex transports remain deferred.

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

All admitted reads use trusted HTTPS, a five-second total deadline and a 64 KiB response bound, and reject redirects.
`get /version` validates the version response before formatting it as TOON or JSON.
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
`config path` reports the canonical configuration path, and `profile list` lists profile names without resolving secrets.
`doctor` verifies file protection and performs one bounded version read.
The tool never reads baseline clients' configuration or writes credential files.
Private files use one bounded reader and atomic replacement module.
Linux checks ownership and modes before reading through a checked file descriptor.
Windows rejects reparse points, applies protected DACLs on writes, verifies DACLs for `auth status` and `doctor`, and bounds rename retries to about one second.
Native Windows proof remains assigned to S6.1.

A file profile may use `certificatePin: { "origin": "https://pve.example.test:8006", "sha256": "<64 hex characters>" }` instead of `caBundle`.
The pin is bound to the exact origin and leaf certificate, including its validity dates.
DNS-name validation remains enabled unless that pin explicitly sets `replaceHostname: true`.
The TLS connection is checked before the HTTP executor receives the socket or sends credentials.
No insecure-TLS flag or automatic trust update exists.

`vendor/` retains the unchanged vendor captures with checked SHA-256 hashes.
They contain 605 legacy 8.2.7 routes and 680 published-current routes, with a 681-route union.
The current documentation capture is bound to documentation version 9.2.13, rather than a live-tested server patch.
`src/operation-policy.json` owns admission decisions and binds them to those exact capture hashes.
Unresolved policy fields deny invocation, and changing a capture never admits new operations automatically.
`src/operations.json` owns the version output projection.
`src/profile-schema.json` owns the current profile contract and runtime validation.
`pnpm generate` replays both captures and generates inventory, help, invocation schemas, a release diff and the shipped credential schema.
`pnpm lint` rejects stale output.
Never edit generated files by hand.

```sh
proxmox-axi inventory --catalogue legacy-8.2.7 --format json
proxmox-axi schema get '/nodes/{node}/tasks' --catalogue published-current --format json
proxmox-axi get '/nodes/{node}/tasks' --api-node pve-test --api-limit 10
```

Invocation paths use catalogue templates and exactly-once parameter encoding.
Vendor parameters have their own `--api-` namespace, so `--api-format` is distinct from the CLI's output `--format`.
`--body-file /absolute/file.json` or `--body-file -` supplies one JSON parameter object, bounded to 64 KiB and five seconds.
Duplicate API parameters, unknown flags, unknown routes, traversal and alternate origins fail before credential resolution or network access.
Vendor property strings, alternative branches, numbered parameters, named formats and Perl patterns remain intact in discovery.
Supplied constraints without a reviewed local validator return `CONTRACT_UNRESOLVED` rather than being silently weakened.
The generated `artium-invocations.json` contains the callable command and flag contracts for a host inventory generator.
It does not update or authorize an existing host fixture by itself.

The public acceptance entry installs a packed tarball into an isolated consumer and executes its exact binary, alongside a competing same-name executable.
It uses real loopback HTTPS and synthetic credentials inside a Linux user/network namespace containing only loopback.
An external connection must fail with `ENETUNREACH` before any product journey runs.
Linux user/network namespaces, iproute2 and OpenSSL are required; missing isolation fails the check.
Dependencies must already be available in the pnpm store; acceptance installs are offline.

```sh
pnpm verify:acceptance -- --task S1.1 --pack /absolute/path/to/pack --out /absolute/new/run/S1.1 --network fake-only --through standalone
pnpm verify:acceptance -- --task S1.2 --pack /absolute/path/to/pack --out /absolute/new/run/S1.2 --network fake-only --through both --repeat-through S1
pnpm verify:acceptance -- --task S2.1 --pack /absolute/path/to/pack --out /absolute/new/run/S2.1 --network fake-only --through both --all-route-variants --available-through S2 --repeat-through S1
```

Use this repository's `evidence` directory or the complete approved evidence pack for `--pack`.
Create the parent run directory first; the task output directory must be new and outside the checkout.
The driver verifies retained fixture hashes and records package integrity, fixture identity, sanitized public transcripts, case outcomes and the fake request ledger.
Private scratch state and canary values are removed before it returns.
Transport diagnostics observe Node's error channel without replacing HTTP or TLS behavior and retain only error codes and timings.
Set `PROXMOX_AXI_TEST_FAILURE_DIR` to an external directory to preserve sanitized evidence when a test fails.
The two sanitized captures under `evidence/` are byte-preserved; their provenance and hashes are listed in `evidence/README.md`.

`pnpm test` always runs native and offline tests, including rejection of an explicitly requested hosted journey with missing fixture inputs.
Actual Artium tests are opt-in: without `PROXMOX_AXI_ARTIUM_FIXTURE`, they skip with the reason `Artium fixture not supplied`.
To include them, select the externally prepared, pinned local admission fixture:

```sh
export PROXMOX_AXI_ARTIUM_FIXTURE=/absolute/path/to/prepared/artium
export PROXMOX_AXI_ARTIUM_MANIFEST=/absolute/path/to/captured/manifest.json
pnpm test
```

Explicit acceptance with `--through both` requires both external fixture inputs and fails if either is missing or its pinned identity differs.
The selected temporary admission revision and captured manifest digest are recorded in `test/artium-fixture.json`.
Prepare it from an exact `git archive` export, install its frozen dependencies offline, and follow its fixture startup guide in task-owned scratch space.
For a Git-free export, invoke the host compiler, copy its store migrations into `dist/src/server/store/migrations`, and run `scripts/build-cli.mjs`; its aggregate build wrapper requires Git metadata.
The retained `runtimeHashes` in `test/artium-fixture.json` pin the compiled runtime files from that build, including the fixture builder, session module and bundled public client.
The driver checks those SHA-256 digests before loading the host, importing the session module or invoking the client, and retains them in the host identity evidence.
Missing or substituted runtime files fail the check even when the TypeScript source is unchanged.
Keep the manifest snapshot and its original tarballs together outside this repository.
The manifest's Proxmox archive is used for both journeys, and its executable, admitted runtime sources and runtime package metadata must match the current build.
Each fixture refresh pins the archive's SHA-256 and SHA-512 integrity alongside its manifest digest and reviewed source and compiled-runtime digests.
The host runs the existing credential store, profile writer, adapter and runner with a synthetic user from its own fixture builder.
The actual public client authenticates against the listening server and executes admitted reads over loopback HTTP; the vendor boundary remains trusted HTTPS.
Evidence includes the host revision, manifest and client digests, startup record, client invocation, real audit outcomes, injected credential-source diagnostics and runner cleanup.
The hosted canary differs from the standalone token, while a competing developer profile and environment remain present.
An adapter substitute cannot satisfy this selection.
Run the full S1.1 check with the same acceptance command above and `--through both`.
No live Proxmox, deployment, publication or hosted CI is part of these checks.
