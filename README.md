# proxmox-axi

AXI-standard agent-facing CLI for Proxmox VE.
This build provides canonical API-token credentials, bounded trusted HTTPS, and versioned invocation discovery for the 681-route Proxmox API union.
Hosted verification uses an explicitly approved, unmerged temporary admission fixture; stock Artium remains unsupported.
Eleven ordinary read routes and 22 mutation routes have reviewed admission policy.
Other operations remain discoverable but uncallable until their effects, transport and secret handling are reviewed.
Writes are disabled by default and require named operation permissions plus an exact, single-use confirmation.
Session authentication, downloads and duplex transports remain deferred.

Install the npm package with Node 24.11.0 or later:

```sh
npm install -g @knowttl/proxmox-axi
proxmox-axi --version
proxmox-axi get --help
```

The executable is `proxmox-axi`.
For development from source:

Use Node 24.14.0 and pnpm 10.22.0.
Node's supported minimum is 24.11.0; `.node-version` pins the tested runtime.
TypeScript 5.9.3, Node types 22.20.5, TOON 2.3.1 and Ajv 8.20.0 align with the checked Artium toolchain.
The lockfile pins every transitive dependency and its integrity.
The fast-uri override retains the checked host's exact 3.1.8 version.

```sh
pnpm install --frozen-lockfile
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
`doctor` verifies file protection and checks the entry version, permissions and node inventory, then checks the first returned node's version, VMs, containers, stores, tasks and one task status when available, in at most nine bounded reads.
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
`src/operation-policy.json` owns read admission and capture bindings.
`scripts/write-policy.ts` positively classifies the reviewed mutation routes and parameter branches.
The generated `write-policy.json` records each other route as refused, alongside its vendor privileges, input classification and contract reference.
Unresolved policy fields deny invocation, and changing a capture never admits new operations automatically.
`src/operations.json` owns required version fields and version help metadata.
`src/profile-schema.json` owns the current profile contract and runtime validation.
`pnpm generate` replays both captures and generates inventory, help, invocation schemas, a release diff and the shipped credential schema.
`pnpm lint` rejects stale output.
Never edit generated files by hand.

```sh
proxmox-axi inventory --catalogue legacy-8.2.7 --format json
proxmox-axi schema get '/nodes/{node}/tasks' --catalogue published-current --format json
proxmox-axi get '/nodes/{node}/tasks' --api-node pve-test --api-limit 10
proxmox-axi ls '/nodes/{node}/qemu' --api-node pve-test --fields vmid,name,status --limit 20
proxmox-axi doctor --format json
```

Ordinary reads other than `/version` detect the entry version and, for node-specific routes, the selected node version before choosing a catalogue.
The published 9.2 schema is supported at the contract level; live commissioning remains pending.
Versions outside 9.2 are labelled unverified.
Writes require a detected major of 8 or 9, including when an explicit catalogue was supplied.
An explicit `--catalogue` selects a replay contract without version detection; inventory visibility remains unknown.
Before admitting a new schema, compare captures offline with `node scripts/compare-capture.mjs /absolute/previous.txt /absolute/candidate.txt`.
The comparison parses the JSON schema without executing JavaScript, reports changed contracts and capture hashes, and never updates admission policy or pins.
Automatic inventory reads check effective root audit permissions and report `complete` or `permission-filtered` visibility.
Scoped privileges may provide useful rows but do not establish complete inventory.
An empty filtered or unverified result never establishes that no resources exist.

TOON is the default; `--format json` preserves the same structured result.
`ls` is an alias for `get` and defaults to `/nodes` when no path is supplied.
Lists default to 100 compact rows; `--limit <1-1000>` changes the display limit, `--fields` chooses fields and `--full` includes all received rows and, unless `--fields` is supplied, all received fields.
Provider totals and pagination remain separate from received counts and display truncation.
Rendered output has a 65536-byte cap, including full output.
HTTP 404 reports `NOT_FOUND_OR_HIDDEN`, since absence and hidden resources cannot be distinguished safely.
Offline `help`, `inventory`, `schema`, `profile list` and `config path` require no credential values.

Invocation paths use catalogue templates and exactly-once parameter encoding.
Vendor parameters have their own `--api-` namespace, so `--api-format` is distinct from the CLI's output `--format`.
`--body-file /absolute/file.json` or `--body-file -` supplies one JSON parameter object, bounded to 64 KiB and five seconds.
Duplicate API parameters, unknown flags, unknown routes, traversal and alternate origins fail before credential resolution or network access.
Vendor property strings, alternative branches, numbered parameters, named formats and Perl patterns remain intact in discovery.
Supplied constraints without a reviewed local validator return `CONTRACT_UNRESOLVED` rather than being silently weakened.
The generated `artium-invocations.json` contains the callable command and flag contracts for a host inventory generator.
It does not update or authorize an existing host fixture by itself.

Writes cover guest power operations, guest destruction, selected scalar configuration branches, pool management, task cancellation and node execute batches.
Inspect `schema create|set|delete <template>` and the generated policy table before enabling an operation.
Add only the required IDs to the selected file profile's `writes: { "operations": ["<operation-id>"] }`.
Environment-only profiles cannot enable writes.
Artium additionally needs its independent `hostWrites` policy with `allowWrites: true` and the exact operation IDs.
Host policy never replaces the profile's own permissions.
The host supplies its authenticated caller and credential revision; callers cannot override those bindings or the persistent journal path.

```sh
proxmox-axi create '/nodes/{node}/qemu/{vmid}/status/start' --api-node pve-test --api-vmid 100 --profile lab --preview
proxmox-axi create '/nodes/{node}/qemu/{vmid}/status/start' --api-node pve-test --api-vmid 100 --profile lab --confirm '<confirmation>'
proxmox-axi task status --api-node pve-test --api-upid '<UPID>' --journal '<intent-id>' --profile lab
proxmox-axi task wait --api-node pve-test --api-upid '<UPID>' --wait-ms 5000 --journal '<intent-id>' --profile lab
proxmox-axi journal reconcile '<intent-id>' --profile lab
```

Preview may perform bounded version reads but sends no business mutation.
Confirmations expire after five minutes and bind origin, identity, caller, selected contract, policy, target, complete ordered inputs, trust and secret-source revisions.
Sensitive configuration inputs require env/file SecretRefs in a body file; literal secret arguments are refused.
An execute batch resolves every ordered node-relative child to its reviewed operation and schema before any wrapper transmission.
Every child requires tool and host permission, including nested batches.
Limits are 64 total operations, four nesting levels and 32768 bytes per commands string.
Any failed child makes the batch fail, with partial outcomes retained and no assumed rollback.

The native journal lives beside the OS state path as `proxmox-axi/writes.log.d`, or beside the host-owned `PROXMOX_AXI_WRITE_LOG` path with `.d` appended.
It uses protected per-intent records, flushed replacements and exclusive single-use confirmation claims outside disposable hosted call directories.
Journal failure prevents transmission.
Records contain request fingerprints and safe metadata rather than credentials or input values.
An accepted UPID means the action is pending; matching task status distinguishes running, success and failure.
`task log` retains numbered lines, and `task wait` has a 1-30000 ms elapsed budget.
Use `--journal` to retain explicit task observations in the associated intent, including batch children.
Lost responses and crashes remain uncertain, with no automatic mutation retry.
Reconciliation can observe reviewed direct configuration/status fields or inspect retained UPIDs.
Observation does not attribute an uncertain mutation, and missing or filtered data never proves failure.
Variants without a safe reconciliation read say so explicitly.

The public acceptance entry installs a packed tarball into an isolated consumer and executes its exact binary, alongside a competing same-name executable.
It uses real loopback HTTPS and synthetic credentials inside a Linux user/network namespace containing only loopback.
An external connection must fail with `ENETUNREACH` before any product journey runs.
Linux user/network namespaces, iproute2 and OpenSSL are required; missing isolation fails the check.
Package installation can fetch dependencies before the isolated product journeys start.

```sh
pnpm verify:acceptance -- --task S1.1 --pack /absolute/path/to/pack --out /absolute/new/run/S1.1 --network fake-only --through standalone
pnpm verify:acceptance -- --task S1.2 --pack /absolute/path/to/pack --out /absolute/new/run/S1.2 --network fake-only --through both --repeat-through S1
pnpm verify:acceptance -- --task S2.1 --pack /absolute/path/to/pack --out /absolute/new/run/S2.1 --network fake-only --through both --all-route-variants --available-through S2 --repeat-through S1
pnpm verify:acceptance -- --task S2.2 --pack /absolute/path/to/pack --out /absolute/new/run/S2.2 --network fake-only --through both --repeat-through S2
pnpm verify:acceptance -- --task S2.3 --pack /absolute/path/to/pack --out /absolute/new/run/S2.3 --network fake-only --through both --repeat-through S2
pnpm verify:acceptance -- --task S3.1 --pack /absolute/path/to/pack --out /absolute/new/run/S3.1 --network fake-only --through both --repeat-through S3
pnpm verify:acceptance -- --task S3.2 --pack /absolute/path/to/pack --out /absolute/new/run/S3.2 --network fake-only --through both --repeat-through S3
```

Use this repository's `evidence` directory for `--pack`; the normalized read captures are bound by the retained manifest.
Create the parent run directory first; the task output directory must be new and outside the checkout.
The driver verifies retained fixture hashes and records package integrity, fixture identity, sanitized public transcripts, case outcomes and the fake request ledger.
Private scratch state and canary values are removed before it returns.
Transport diagnostics observe Node's error channel without replacing HTTP or TLS behavior and retain only error codes and timings.
Set `PROXMOX_AXI_TEST_FAILURE_DIR` to an external directory to preserve sanitized evidence when a test fails.
The retained sanitized captures and their formatting provenance are described in `evidence/README.md`.

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
