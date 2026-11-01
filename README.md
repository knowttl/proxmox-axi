# proxmox-axi

Agent-facing Proxmox VE CLI, read-only by default.
It covers the 681-route Proxmox API union through versioned invocation discovery, with reviewed admission policy for each callable operation.
This build provides canonical API-token, supplied-ticket and password credentials, protected results, and bounded trusted HTTPS.

[Why this exists](#why-this-exists) | [Quickstart](#quickstart) | [Commands](#commands) | [Safety](#safety) | [Configuration](#configuration) | [Output and exit codes](#output-and-exit-codes) | [Limitations](#limitations) | [Development](#development)

## Why this exists

The Proxmox API is large, and most of its routes change state or handle secrets.
Agents need a bounded, predictable way to inspect a cluster without scraping vendor output.
`proxmox-axi` returns compact TOON (or JSON) with structured errors and next-step hints, and never includes raw vendor bodies or transport diagnostics.
Only reviewed operations are callable.
Ordinary inventory reads, controlled mutations and selected credential/session setup routes have reviewed admission policy.
Other operations remain discoverable but uncallable until their effects, transport and secret handling are reviewed.
Writes are disabled by default and need a named operation permission plus an exact, single-use confirmation.
Hosted verification uses an explicitly approved, unmerged temporary admission fixture; stock Artium remains unsupported.
Managed transfers and console/migration duplex transports use private inherited byte channels, with metadata-only ordinary output.
The [S4 contract](docs/s4-contract.md) defines private results and caller-managed memory sessions.
The [S5 contract](docs/s5-contract.md) defines formatters, transfer limits and binary framing.

## Quickstart

Requires Node 24.11.0 or later.

```sh
npm install --global @knowttl/proxmox-axi
proxmox-axi --version
proxmox-axi get --help
```

With no profile configured, a read returns a structured error and exits nonzero:

```sh
proxmox-axi get /version
```

```text
error:
  code: AUTH_REQUIRED
  message: No API token profile is configured.
help[1]: "Configure PROXMOX_AXI_ORIGIN, PROXMOX_AXI_TOKEN_ID and PROXMOX_AXI_TOKEN."
```

See [Safety](#safety) for ordinary JSON read bounds and the [S5 contract](docs/s5-contract.md) for managed transfer limits.
`get /version` validates the version response before formatting it as TOON or JSON.
HTTP 401 returns a nonzero `AUTH_REQUIRED` result; malformed successful responses return `INVALID_RESPONSE`.
Errors are structured on stdout and never include raw vendor bodies or transport diagnostics.
An interrupted HTTPS response returns `CONNECTION_FAILED`; the total deadline and response bound retain `TIMEOUT` and `OUTPUT_LIMIT`.

Configure an API token profile, then make the first authenticated read:

```sh
export PROXMOX_AXI_ORIGIN=https://pve.example.test:8006
export PROXMOX_AXI_TOKEN_ID='user@pam!tokenname'
export PROXMOX_AXI_TOKEN=...   # supplied by your secret store, never as a command argument
proxmox-axi get /version
proxmox-axi doctor
```

## Use with your agent

No session hooks or agent skill ship with this package yet; this is pending.
Agents call the CLI directly.
`proxmox-axi get --help`, `proxmox-axi inventory` and `proxmox-axi schema <method> <template>` are offline and describe what is callable.
The generated `artium-invocations.json` holds the callable command and flag contracts for a host inventory generator.
It does not update or authorize an existing host fixture by itself.

## Commands

Run `proxmox-axi <command> --help` for flags.
The generated `help.json` and `inventory.json` in this repository are the full reference.

Reads:

```sh
proxmox-axi get <template> [--api-<parameter> <value>] [--catalogue legacy-8.2.7|published-current] [--limit <1-1000>] [--fields <names>] [--full] [--body-file <path|->]
proxmox-axi ls [<template>]          # alias for get, defaults to /nodes
proxmox-axi doctor
proxmox-axi auth status
proxmox-axi config path
proxmox-axi profile list
```

Offline discovery (no credential values required):

```sh
proxmox-axi inventory [--catalogue <release>]
proxmox-axi schema <method> <template> [--catalogue <release>]
```

Writes (see [Safety](#safety)):

```sh
proxmox-axi create|set|delete <template> [--api-<parameter> <value>] --preview|--confirm <confirmation>
proxmox-axi task status|log|wait|cancel --api-node <node> --api-upid <UPID> [--journal <id>] [--wait-ms <1-30000>]
proxmox-axi journal show|reconcile <id>
```

Managed byte transports (see the [S5 contract](docs/s5-contract.md) for required private channels, formatters and framing):

```sh
proxmox-axi transfer get|create <template> --response-format <formatter> [--api-<parameter> <value>]
proxmox-axi duplex create <setup-template> [--api-<parameter> <value>] --preview|--confirm <confirmation>
```

Common flags are `--config <absolute-path>`, `--profile <name>`, `--session <id>` and `--format toon|json`.

```sh
proxmox-axi inventory --catalogue legacy-8.2.7 --format json
proxmox-axi schema get '/nodes/{node}/tasks' --catalogue published-current --format json
proxmox-axi get '/nodes/{node}/tasks' --api-node pve-test --api-limit 10
proxmox-axi ls '/nodes/{node}/qemu' --api-node pve-test --fields vmid,name,status --limit 20
proxmox-axi doctor --format json
```

Notes:

- Invocation paths use catalogue templates and exactly-once parameter encoding.
- Vendor parameters use the `--api-` namespace, so `--api-format` is distinct from the CLI's output `--format`.
- `--body-file /absolute/file.json` or `--body-file -` supplies one JSON parameter object, bounded to 64 KiB and five seconds.
- Duplicate API parameters, unknown flags and unknown routes fail before credential resolution or network access.
- `doctor` verifies file protection and checks the entry version, permissions and node inventory.
  It then checks the first returned node's version, VMs, containers, stores, tasks and one task status when available, in at most nine bounded reads.
- `auth status` reports the selected credential sources without secret values and sends no request.
- `profile list` lists profile names without resolving secrets.

### Version handling and inventory

Ordinary JSON reads other than `/version` detect the entry version and, for node-specific routes, the selected node version before choosing a catalogue.
For ordinary JSON reads, an explicit `--catalogue` selects a replay contract without version detection, and inventory visibility remains unknown.
Managed read transfers always detect the selected node version and choose its contract, even when `--catalogue` is supplied.
Writes require a detected major of 8 or 9 and select the corresponding contract, including when an explicit catalogue was supplied.
Automatic inventory reads check effective root audit permissions and report `complete` or `permission-filtered` visibility.
Scoped privileges may provide useful rows but do not establish complete inventory.
An empty filtered or unverified result never establishes that no resources exist.

## Safety

- Ordinary JSON reads use trusted HTTPS, a five-second total deadline and a 64 KiB response bound, and reject redirects.
  Managed transfers have separate administrator-controlled byte and elapsed limits.
- Operations whose effects, transport or secret handling are not reviewed remain discoverable but uncallable.
  Unresolved policy fields deny invocation, and changing a capture never admits new operations automatically.
- Writes cover guest power operations, guest destruction, selected scalar configuration branches, pool management, task cancellation, node execute batches, storage uploads and the reviewed credential/session setup operations.
  Effectful CIFS/PBS scans use the same preview and confirmation policy even though their vendor method is GET.
- Inspect `schema create|set|delete <template>` and the generated `write-policy.json` before enabling an operation.
- Enable an operation by adding its ID to the selected file profile: `writes: { "operations": ["<operation-id>"] }`.
  Environment-only profiles cannot enable writes.
- Hosted use needs the host's independent `hostWrites` policy with `allowWrites: true` and the exact operation IDs.
  Host policy never replaces the profile's own permissions.
  The host supplies its authenticated caller and credential revision, and callers cannot override those bindings or the persistent journal path.
- `--preview` may perform bounded version reads but sends no business mutation.
- A confirmation expires after five minutes and binds origin, identity, caller, selected contract, policy, target, complete ordered inputs, trust and secret-source revisions.
- Sensitive operation inputs require env/file SecretRefs in a body file, and literal secret arguments are refused.

```sh
proxmox-axi create '/nodes/{node}/qemu/{vmid}/status/start' --api-node pve-test --api-vmid 100 --profile lab --preview
proxmox-axi create '/nodes/{node}/qemu/{vmid}/status/start' --api-node pve-test --api-vmid 100 --profile lab --confirm '<confirmation>'
proxmox-axi task status --api-node pve-test --api-upid '<UPID>' --journal '<intent-id>' --profile lab
proxmox-axi task wait --api-node pve-test --api-upid '<UPID>' --wait-ms 5000 --journal '<intent-id>' --profile lab
proxmox-axi journal show '<intent-id>' --profile lab
proxmox-axi journal reconcile '<intent-id>' --profile lab
```

### Execute batches

An execute batch resolves every ordered node-relative child to its reviewed operation and schema before any wrapper transmission.
Every child requires tool and host permission, including nested batches.
Limits are 64 total operations, four nesting levels and 32768 bytes per commands string.
Any failed child makes the batch fail, with partial outcomes retained and no assumed rollback.

### Journal and unknown outcomes

- The native journal lives beside the OS state path as `proxmox-axi/writes.log.d`, or beside the host-owned `PROXMOX_AXI_WRITE_LOG` path with `.d` appended.
- It uses protected per-intent records, flushed replacements and exclusive single-use confirmation claims.
  Records hold request fingerprints and safe metadata, never credentials or input values.
- Journal failure prevents transmission.
- An accepted UPID means the action is pending, and matching task status distinguishes running, success and failure.
- `task log` returns numbered lines without storing them in the journal.
- `task wait` has a 1-30000 ms elapsed budget, defaulting to 5000 ms.
- `task cancel` requires its own preview and exact confirmation, using the same operation permission as deleting the task route.
- Lost responses and crashes remain uncertain, with no automatic mutation retry.
- `journal reconcile` can observe reviewed direct configuration or status fields, or inspect retained UPIDs.
  Observation does not attribute an uncertain mutation, and missing or filtered data never proves failure.
  Variants without a safe reconciliation read say so explicitly.

### Redaction

Errors are structured on stdout and never include raw vendor bodies or transport diagnostics.
Token values never arrive through command arguments.
`axi-credential.schema.json` rejects unknown fields and inline secrets.
The tool never reads other clients' configuration or writes credential files.
Protected values remain in private result and byte channels and never enter ordinary output.
Only provider free text is scanned; generated metadata and binary messages retain their reviewed channels.

## Configuration

### Credentials and profiles

The default environment profile reads:

| Variable | Purpose |
| --- | --- |
| `PROXMOX_AXI_ORIGIN` | HTTPS origin of the server |
| `PROXMOX_AXI_TOKEN_ID` | Full API token ID |
| `PROXMOX_AXI_TOKEN` | Token secret |
| `PROXMOX_AXI_AUTH` | `api-token`, `ticket` or `password`; see the [S4 contract](docs/s4-contract.md) for branch-specific fields and explicit session acquisition |
| `PROXMOX_AXI_CA_BUNDLE` | Absolute path of a trusted PEM file |
| `PROXMOX_AXI_CONFIG` | Config file path |
| `PROXMOX_AXI_PROFILE` | File profile name |
| `PROXMOX_AXI_WRITE_LOG` | Host-owned write journal path |

API token profiles use `auth: "api-token"`, an HTTPS `origin`, a full `tokenId` and an optional token SecretRef.
A SecretRef is exactly `{ "env": "VARIABLE_NAME" }` or `{ "file": "/absolute/protected/path" }`.
An omitted reference defaults to `{ "env": "PROXMOX_AXI_TOKEN" }`.

### Config file

The file is selected by `--config`, `PROXMOX_AXI_CONFIG`, or the OS configuration directory's `proxmox-axi/config.json` (`proxmox-axi config path` prints it).
On Linux an absolute `XDG_CONFIG_HOME` overrides `~/.config`.
On Windows the directory is `%APPDATA%`, with an OS home-directory fallback.
The shape is `{ "version": 1, "defaultProfile": "lab", "profiles": { "lab": { ... } } }`.
Select a file profile with `--profile` or `PROXMOX_AXI_PROFILE` to ignore competing environment-profile fields.
Otherwise a complete environment profile takes precedence over file defaults, and a partial environment profile fails.
Private files use one bounded reader and atomic replacement.
Linux checks ownership and modes before reading through a checked file descriptor.
Windows rejects reparse points, applies protected DACLs on writes, verifies DACLs for `auth status` and `doctor`, and bounds rename retries to about one second.

### TLS

A file profile may use `certificatePin: { "origin": "https://pve.example.test:8006", "sha256": "<64 hex characters>" }` instead of `caBundle`.
The pin is bound to the exact origin and leaf certificate, including its validity dates.
DNS-name validation remains enabled unless the pin sets `replaceHostname: true`.
The TLS connection is checked before the HTTP executor receives the socket or sends credentials.
No insecure-TLS flag or automatic trust update exists.

## Output and exit codes

- TOON is the default, and `--format json` preserves the same structured result.
- Lists default to 100 compact rows.
  `--limit <1-1000>` changes the display limit, `--fields` chooses fields, and `--full` includes all received rows and, unless `--fields` is supplied, all received fields.
- Provider totals and pagination remain separate from received counts and display truncation.
- Rendered output has a 65536-byte cap, including `--full`.
- Exit code 0 is success, 1 is a failed command and 2 is an unknown command.
- Common error codes: `AUTH_REQUIRED` (HTTP 401 or no profile), `INVALID_RESPONSE` (malformed success body), `CONNECTION_FAILED` (interrupted response), `TIMEOUT`, `OUTPUT_LIMIT`, `INVALID_INPUT`, `CONTRACT_UNRESOLVED` and `NOT_FOUND_OR_HIDDEN`.
- HTTP 404 reports `NOT_FOUND_OR_HIDDEN`, since absence and hidden resources cannot be distinguished safely.
- Supplied constraints without a reviewed local validator return `CONTRACT_UNRESOLVED` rather than being silently weakened.

## Limitations

- The published 9.2 schema is supported at the contract level, and live commissioning is pending.
  Versions outside 9.2 are labelled unverified.
- The current documentation capture is bound to documentation version 9.2.13, not to a live-tested server patch.
- Managed transfers and duplex sessions are verified with fake services only; live release-specific console token compatibility remains pending.
- Operations outside the reviewed admission policy are discoverable but uncallable.
- Native Windows proof is pending.
- Hosted verification uses an explicitly approved, unmerged temporary admission fixture, and stock hosts remain unsupported.
- No live Proxmox, deployment, publication or hosted CI is part of the checks in this repository.

## Development

Use Node 24.14.0 (pinned in `.node-version`; the supported minimum is 24.11.0) and pnpm 10.22.0.
The lockfile pins every transitive dependency and its integrity, and the `fast-uri` override pins 3.1.8.

```sh
pnpm install --frozen-lockfile
pnpm build
node bin/proxmox-axi.mjs get --help
node bin/proxmox-axi.mjs --version
pnpm lint
pnpm test
```

`pnpm generate` replays both vendor captures and generates the inventory, help, invocation schemas, release diff and shipped credential schema.
`pnpm lint` rejects stale output, and generated files must never be edited by hand.

Policy and data sources:

- `vendor/` retains the unchanged vendor captures with checked SHA-256 hashes: 605 legacy 8.2.7 routes and 680 published-current routes, with a 681-route union.
- `src/operation-policy.json` owns read admission and capture bindings.
- `scripts/write-policy.ts` classifies the reviewed mutation routes and parameter branches.
  The generated `write-policy.json` records every other route as refused, with its vendor privileges, input classification and contract reference.
- `src/operations.json` owns required version fields and version help metadata.
- `src/profile-schema.json` owns the profile contract and runtime validation.
- Before admitting a new schema, compare captures offline with `node scripts/compare-capture.mjs /absolute/previous.txt /absolute/candidate.txt`.
  It parses the JSON schema without executing JavaScript, reports changed contracts and capture hashes, and never updates admission policy or pins.

### Tests

`pnpm test` runs native and offline tests only, including rejection of an explicitly requested hosted journey with missing fixture inputs.
The package-contract test packs and installs the tarball offline, checks its file list and CLI bin entry, runs `--help` and `--version`, and imports the modules and JSON artifacts consumed by Artium.
It requires npm, pnpm and tar, with production dependencies already available in the local pnpm store.
Hosted tests are opt-in and skip with `Artium fixture not supplied` unless an externally prepared, pinned local fixture is selected:

```sh
export PROXMOX_AXI_ARTIUM_FIXTURE=/absolute/path/to/prepared/artium
export PROXMOX_AXI_ARTIUM_MANIFEST=/absolute/path/to/captured/manifest.json
pnpm test
```

Set `PROXMOX_AXI_TEST_FAILURE_DIR` to an external directory to preserve sanitized evidence when a test fails.
The retained captures and their provenance are described in `evidence/README.md`.

### Acceptance checks

The public acceptance entry installs a packed tarball into an isolated consumer and executes its exact binary alongside a competing same-name executable.
It uses real loopback HTTPS and synthetic credentials inside a Linux user/network namespace containing only loopback.
An external connection must fail with `ENETUNREACH` before any product journey runs.
Linux user/network namespaces, iproute2 and OpenSSL are required, and missing isolation fails the check.
Package installation can fetch dependencies before the isolated journeys start.

```sh
pnpm verify:acceptance -- --task S1.1 --pack /absolute/path/to/pack --out /absolute/new/run/S1.1 --network fake-only --through standalone
pnpm verify:acceptance -- --task S1.2 --pack /absolute/path/to/pack --out /absolute/new/run/S1.2 --network fake-only --through both --repeat-through S1
pnpm verify:acceptance -- --task S2.1 --pack /absolute/path/to/pack --out /absolute/new/run/S2.1 --network fake-only --through both --all-route-variants --available-through S2 --repeat-through S1
pnpm verify:acceptance -- --task S2.2 --pack /absolute/path/to/pack --out /absolute/new/run/S2.2 --network fake-only --through both --repeat-through S2
pnpm verify:acceptance -- --task S2.3 --pack /absolute/path/to/pack --out /absolute/new/run/S2.3 --network fake-only --through both --repeat-through S2
pnpm verify:acceptance -- --task S3.1 --pack /absolute/path/to/pack --out /absolute/new/run/S3.1 --network fake-only --through both --repeat-through S3
pnpm verify:acceptance -- --task S3.2 --pack /absolute/path/to/pack --out /absolute/new/run/S3.2 --network fake-only --through both --repeat-through S3
pnpm verify:acceptance -- --task S4.1 --pack /absolute/path/to/pack --out /absolute/new/run/S4.1 --network fake-only --through both --repeat-through S4
pnpm verify:acceptance -- --task S4.2 --pack /absolute/path/to/pack --out /absolute/new/run/S4.2 --network fake-only --through both --repeat-through S4
pnpm verify:acceptance -- --task S5.1 --pack /absolute/path/to/pack --out /absolute/new/run/S5.1 --network fake-only --through standalone --repeat-through S5
pnpm verify:acceptance -- --task S5.2 --pack /absolute/path/to/pack --out /absolute/new/run/S5.2 --network fake-only --through standalone --repeat-through S5
```

The S5 selectors cover transfers/formatters (S5.1) and console/migration duplex sessions (S5.2).
S5.2 also runs the S5.1 journeys.
Hosted S5 proof is optional per slice; select `--through both` only when the pinned external fixture is available.

Use this repository's `evidence` directory for `--pack`, and create the parent run directory first.
The task output directory must be new and outside the checkout.
The driver verifies retained fixture hashes and records package integrity, fixture identity, sanitized public transcripts, case outcomes and the fake request ledger.
Private scratch state and canary values are removed before it returns.

Explicit acceptance with `--through both` requires both external fixture inputs and fails if either is missing or its pinned identity differs.
The selected temporary admission revision and captured manifest digest are recorded in `test/artium-fixture.json`.
Prepare the host from an exact `git archive` export, install its frozen dependencies offline, and follow its fixture startup guide in task-owned scratch space.
For a Git-free export, invoke the host compiler, copy its store migrations into `dist/src/server/store/migrations`, and run `scripts/build-cli.mjs`, since its aggregate build wrapper requires Git metadata.
The `runtimeHashes` in `test/artium-fixture.json` pin the compiled runtime files, and the driver checks those SHA-256 digests before loading the host, so missing or substituted runtime files fail the check.
Keep the manifest snapshot and its original tarballs together outside this repository.
The hosted journey runs the existing credential store, profile writer, adapter and runner with a synthetic user, and the real public client authenticates against the listening server over loopback HTTP.
The vendor boundary remains trusted HTTPS.
The hosted canary differs from the standalone token, and an adapter substitute cannot satisfy this selection.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
The build is offline, and tests never contact a real Proxmox node or use real credentials.

## Security

No `SECURITY.md` ships yet; this is pending.

## License

No `LICENSE` file ships yet; this is pending.
