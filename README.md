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

The package includes the [proxmox-axi agent skill](skills/proxmox-axi/SKILL.md) for profile selection, discovery and safe task completion.
Install it into your agent's skill directory or install from this repository:

```sh
npx skills add knowttl/proxmox-axi --skill proxmox-axi
```

No session hooks are installed automatically.
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
proxmox-axi inventory [--catalogue <release>] [--limit <1-1000>|--full]
proxmox-axi schema <method> <template> [--catalogue <release>] [--view invocation|vendor] [--offset <n>]
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
Offline `inventory` and `schema` accept `--config` without loading credentials.
For callable operations, `schema` defaults to the complete executable `invocation.schema`, policy and return shape, without the raw vendor parameter payload.
Use `invocation.schema` to validate invocation objects shaped as `{ "api": { ... } }`, and check `callable` and `policy` before invoking.
Use `schema <method> '<template>' --view vendor` for complete raw vendor parameters, including refused inputs, in bounded pages.
See [schema views](skills/proxmox-axi/references/guest-management.md#schema-views) for paging, flag scope and full vendor schema access.

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
  The permission map appears once in the top-level `permissions` field; its check entry contains metadata only.
  It then checks the first returned node's version, VMs, containers, stores, tasks and one task status when available, in at most nine bounded reads.
- `auth status` reports the selected credential sources without secret values and sends no request.
- `profile list` lists profile names without resolving secrets.

### Version handling and inventory

Ordinary JSON reads other than `/version` detect the entry version and, for node-specific routes, the selected node version before choosing a catalogue.
For ordinary JSON reads, an explicit `--catalogue` selects a replay contract without version detection, and inventory visibility remains unknown.
Version reads still report compatibility for the returned server version, so their `compatibility.catalogue` can differ from the explicit replay contract.
`compatibility.writeVerification` describes release verification evidence; operation authorization comes from the profile and host policies.
Managed read transfers always detect the selected node version and choose its contract, even when `--catalogue` is supplied.
Writes require a detected major of 8 or 9 and select the corresponding contract, including when an explicit catalogue was supplied.
Automatic inventory reads check effective root audit permissions and report `complete` or `permission-filtered` visibility.
Scoped privileges may provide useful rows but do not establish complete inventory.
An empty filtered or unverified result never establishes that no resources exist.

### Infrastructure discovery across profiles

Select a named profile explicitly for each host or cluster.
`profile list` lists configured names without loading their secrets; `auth status --profile <name>` reports which credential sources that selection uses.
The selected file profile ignores competing environment-profile fields.
Each profile can have its own origin, credential SecretRef, TLS trust and write permissions.

```sh
proxmox-axi profile list
proxmox-axi get /cluster/status --profile lab
proxmox-axi get /cluster/nextid --profile lab
proxmox-axi get '/nodes/{node}/status' --api-node '<node>' --profile lab
proxmox-axi get /storage --profile lab
proxmox-axi get '/nodes/{node}/storage/{storage}/status' --api-node '<node>' --api-storage '<storage>' --profile lab
```

Cluster status returns cluster/node identities and online/quorum flags; `--full` includes the other received status fields.
`/cluster/nextid` returns a free VMID, or checks `--api-vmid <id>` at read time; it does not reserve that ID.
Node status reports CPU, memory, filesystem and boot metrics.
The `/storage` index returns storage identifiers only, including with `--full`, to avoid exposing backend configuration.
Use `/nodes/{node}/storage` for inventory and capacity, or `/nodes/{node}/storage/{storage}/status` for one store's availability, content types and space metrics.
Automatic cluster status and storage index reads include permission visibility; explicit `--catalogue` reads report unknown visibility.

For example, a protected config can keep two independent profiles with separate token references:

```json
{
  "version": 1,
  "defaultProfile": "lab",
  "profiles": {
    "lab": {
      "auth": "api-token",
      "origin": "https://lab.example.test:8006",
      "tokenId": "automation@pve!audit",
      "token": { "env": "PVE_LAB_TOKEN" }
    },
    "production": {
      "auth": "api-token",
      "origin": "https://production.example.test:8006",
      "tokenId": "automation@pve!audit",
      "token": { "env": "PVE_PRODUCTION_TOKEN" }
    }
  }
}
```

Supply credentials through the referenced secret source and set file ownership and permissions as described under [Configuration](#configuration).
These reads do not grant storage administration, node power control, or cluster membership changes.

### Guest configuration and compute settings

QEMU and LXC current status reads expose power state and resource metrics:

```sh
proxmox-axi get '/nodes/{node}/qemu/{vmid}/status/current' --api-node '<node>' --api-vmid 100 --profile lab
proxmox-axi get '/nodes/{node}/lxc/{vmid}/status/current' --api-node '<node>' --api-vmid 101 --profile lab
```

For protected guest reads, follow the [guest private-read guidance](skills/proxmox-axi/references/guest-management.md#private-configuration-reads) for covered operations, pipe setup, delivery metadata and payload handling.

Confirmed `set .../config` supports the settings present in each guest's selected contract: names/description, cores, CPU limits/weights, memory, onboot and startup order; QEMU also supports sockets, vCPUs, balloon memory and a CPU model, while LXC supports swap.
QEMU memory accepts `2048` or `current=2048` in MiB, with a minimum of 16; LXC memory and swap use integer MB values.
CPU configuration accepts a model identifier, optionally prefixed with `cputype=`, and refuses `host` and feature-override subproperties.
Startup strings use canonical order: optional `order` first, then `up`, then `down`, with no duplicate keys; a bare integer is also accepted for `order`.
Pass a configuration digest when available to detect concurrent changes.

```sh
proxmox-axi set '/nodes/{node}/qemu/{vmid}/config' --api-node '<node>' --api-vmid 100 --api-cores 4 --api-sockets 1 --api-memory current=2048 --api-balloon 1024 --api-cpu x86-64-v2-AES --api-startup order=2,up=10,down=15 --profile lab --preview
proxmox-axi set '/nodes/{node}/lxc/{vmid}/config' --api-node '<node>' --api-vmid 101 --api-memory 2048 --api-swap 512 --api-cpulimit 2 --profile lab --preview
```

Repeat the exact selected command with `--confirm '<confirmation>'` after inspecting its preview.
Hardware passthrough, executable hooks and other unreviewed configuration branches remain refused.

### Grow a guest disk

Both guests support confirmed `set '/nodes/{node}/qemu/{vmid}/resize'` or the LXC equivalent.
Supply an ordinary QEMU disk selector (`ide0` through `ide3`, `sata0` through `sata5`, `scsi0` through `scsi30`, or `virtio0` through `virtio15`) or an LXC `rootfs`/mount-point selector from the selected catalogue.
Only positive relative increments with explicit uppercase `K`, `M`, `G` or `T` units are admitted; absolute targets, shrink, zero, lock bypass and EFI/TPM selectors remain refused.
Pass the private configuration digest when available to detect concurrent changes.

```sh
proxmox-axi set '/nodes/{node}/qemu/{vmid}/resize' --api-node '<node>' --api-vmid 100 --api-disk scsi0 --api-size '+8G' --profile lab --preview
```

Repeat the exact command with `--confirm '<confirmation>'`, then use `task wait` with the returned node, UPID and journal ID.
An accepted task does not prove completion or that the guest partition/filesystem expanded.
If delivery is uncertain, inspect the journal/task instead of repeating relative growth, which could add capacity twice.

### Manage disk attachments

Use concrete flags such as `--api-scsi0` or `--api-mp0`, or the same concrete keys in a protected body file.
Follow the [managed disk configuration reference](skills/proxmox-axi/references/guest-management.md#managed-disk-configuration) for admitted slots, managed volume syntax, modifier order, replacement/removal safeguards and refused inputs.

```sh
proxmox-axi set '/nodes/{node}/qemu/{vmid}/config' --api-node '<node>' --api-vmid 100 --api-scsi0 'local-lvm:8,backup=1' --profile lab --preview
proxmox-axi set '/nodes/{node}/lxc/{vmid}/config' --api-node '<node>' --api-vmid 101 --api-mp0 'local-lvm:8,mp=/mnt/data,backup=1' --profile lab --preview
```

Repeat the exact command with its confirmation after inspecting the preview.

### Guest networking, boot media and agent setup

Confirmed QEMU/LXC configuration updates support concrete `net0` through `net31` devices with reviewed property strings.
QEMU also supports ordered boot devices, managed ISO attachment/ejection and agent enablement.
See the [guest networking and boot reference](skills/proxmox-axi/references/guest-management.md#guest-networking-and-boot) for canonical modifier order, supported models, addresses and remaining refusals.

```sh
proxmox-axi set '/nodes/{node}/qemu/{vmid}/config' --api-node '<node>' --api-vmid 100 --api-net0 'virtio,bridge=vmbr0,firewall=1,tag=42' --profile lab --preview
proxmox-axi set '/nodes/{node}/qemu/{vmid}/config' --api-node '<node>' --api-vmid 100 --api-ide2 'local:iso/installer.iso,media=cdrom' --api-boot 'order=ide2;scsi0;net0' --api-agent enabled=1 --profile lab --preview
proxmox-axi set '/nodes/{node}/lxc/{vmid}/config' --api-node '<node>' --api-vmid 101 --api-net0 'name=eth0,bridge=vmbr0,firewall=1,ip=dhcp,ip6=auto,type=veth' --profile lab --preview
```

Repeat the exact command with its confirmation after inspecting the preview.
Follow the [guest networking and boot reference](skills/proxmox-axi/references/guest-management.md#guest-networking-and-boot) for NIC replacement/removal safeguards, host-network boundaries and guest-agent prerequisites.

### Guest-agent readiness and first-boot checks

After the guest start task completes, use the exact QEMU agent `info`, `get-host-name`, `get-osinfo`, `network-get-interfaces` and `ping` routes to inspect readiness.
All five require the inherited private result pipe described in the [readiness reference](skills/proxmox-axi/references/guest-management.md#guest-agent-readiness-and-first-boot-checks), including with `--full`.

```sh
proxmox-axi get '/nodes/{node}/qemu/{vmid}/agent/info' --api-node '<node>' --api-vmid 100 --profile lab
proxmox-axi post '/nodes/{node}/qemu/{vmid}/agent/ping' --api-node '<node>' --api-vmid 100 --profile lab
```

Ping uses the provider's POST method but is a reviewed read, without mutation permission, confirmation or a standalone journal.
Follow the readiness reference above for prerequisites, interpretation of results and failures, and private first-boot marker checks.

### Confirmed guest execution

QEMU `create .../agent/exec` starts an explicitly approved program and arguments inside the guest.
Its `command` input must be an env/file SecretRef containing a JSON array; literal argv and stdin submission remain refused.
Both the returned guest PID and `get .../agent/exec-status` output require the inherited private result pipe.
Status retrieval requires its own operation grant and exact preview/confirmation because completed queries reap process metadata, despite using GET.

```sh
proxmox-axi create '/nodes/{node}/qemu/{vmid}/agent/exec' --body-file '<absolute-protected-request-file>' --profile lab --preview
proxmox-axi get '/nodes/{node}/qemu/{vmid}/agent/exec-status' --api-node '<node>' --api-vmid 100 --api-pid '<private-pid>' --profile lab --preview
```

Confirm each exact preview separately, after privately reviewing the argv source and target.
Launch success does not establish that the guest process completed successfully, and a guest PID is not a node-task UPID.
Follow the [execution and onboarding reference](skills/proxmox-axi/references/guest-management.md#confirmed-guest-execution) for private body files, result interpretation, one-time status consumption and recovery limits.

### Cloud-init onboarding

Confirmed QEMU configuration updates now support `ciuser`, SecretRef-only `cipassword`, percent-encoded SSH public keys, `ipconfig0` through `ipconfig31`, DNS settings and ordinary `storage:cloudinit` media.
QEMU and LXC configuration updates support space-separated reviewed IPv4 DNS servers and DNS search domains.
See the [cloud-init onboarding reference](skills/proxmox-axi/references/guest-management.md#cloud-init-onboarding) for input constraints and secret handling.

```sh
proxmox-axi set '/nodes/{node}/qemu/{vmid}/config' --api-node '<node>' --api-vmid 100 --api-ciuser deployer --api-ipconfig0 'ip=dhcp,ip6=auto' --api-ide2 'local-lvm:cloudinit' --profile lab --preview
proxmox-axi set '/nodes/{node}/qemu/{vmid}/cloudinit' --api-node '<node>' --api-vmid 100 --profile lab --preview
```

Confirm each exact preview separately; regeneration returns synchronous success rather than a UPID.
`get .../cloudinit` exposes protected current/pending values only through the inherited private result pipe, including before regeneration.
Cloud-init dumps, custom snippets and unreviewed input branches remain refused.

### Discover and install guest media

List managed ISO images, container templates, guest disks or backups, or inspect the provider's appliance catalogue:

```sh
proxmox-axi get '/nodes/{node}/storage/{storage}/content' --api-node '<node>' --api-storage local --api-content iso --profile lab
proxmox-axi get '/nodes/{node}/aplinfo' --api-node '<node>' --profile lab
proxmox-axi create '/nodes/{node}/aplinfo' --api-node '<node>' --api-storage local --api-template '<catalogue-template>.tar.zst' --profile lab --preview
```

The [media reference](skills/proxmox-axi/references/guest-management.md#iso-and-container-template-media) covers reviewed content-detail fields, catalogue installation and local ISO/template uploads through the existing private managed byte channel.
Every upload/install needs exact preview confirmation; wait for the returned task and inspect storage content before using the media.
See that reference for the fields retained with `--full` and the metadata excluded from public results.

### Create and clone QEMU guests

Create a blank QEMU guest or clone an existing template with a preview:

```sh
proxmox-axi create '/nodes/{node}/qemu' --api-node '<node>' --api-vmid 200 --api-name new-guest --api-memory 2048 --api-cores 2 --api-scsihw virtio-scsi-single --api-scsi0 'local-lvm:8' --api-ide2 'local:iso/installer.iso,media=cdrom' --api-net0 'virtio,bridge=vmbr0' --api-boot 'order=ide2;scsi0' --api-ostype l26 --profile lab --preview
proxmox-axi create '/nodes/{node}/qemu/{vmid}/clone' --api-node '<source-node>' --api-vmid '<template-id>' --api-newid 201 --api-name cloned-guest --api-full 1 --api-storage local-lvm --profile lab --preview
```

Follow the [QEMU provisioning reference](skills/proxmox-axi/references/guest-management.md#qemu-creation-and-template-cloning) for operation permissions, supported inputs, confirmation, task completion, cross-node clones, onboarding and remaining refusals.

### Create and clone LXC guests

Create from an existing managed container template or clone a reviewed unprivileged template:

```sh
proxmox-axi create '/nodes/{node}/lxc' --api-node '<node>' --api-vmid 202 --api-ostemplate 'local:vztmpl/base.tar.zst' --api-hostname new-container --api-memory 2048 --api-rootfs local-lvm:8 --profile lab --preview
proxmox-axi create '/nodes/{node}/lxc/{vmid}/clone' --api-node '<source-node>' --api-vmid '<template-id>' --api-newid 203 --api-hostname cloned-container --api-full 1 --api-storage local-lvm --profile lab --preview
```

Follow the [LXC provisioning reference](skills/proxmox-axi/references/guest-management.md#lxc-creation-and-template-cloning) for unprivileged creation, source-template checks, supported settings, credential handling, task completion and remaining refusals.

### Guest snapshots

Inspect a QEMU or LXC snapshot tree, then preview an explicitly selected mutation:

```sh
proxmox-axi get '/nodes/{node}/qemu/{vmid}/snapshot' --api-node '<node>' --api-vmid 200 --profile lab
proxmox-axi create '/nodes/{node}/qemu/{vmid}/snapshot' --api-node '<node>' --api-vmid 200 --api-snapname before-upgrade --profile lab --preview
proxmox-axi create '/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback' --api-node '<node>' --api-vmid 200 --api-snapname before-upgrade --profile lab --preview
proxmox-axi delete '/nodes/{node}/qemu/{vmid}/snapshot/{snapname}' --api-node '<node>' --api-vmid 200 --api-snapname before-upgrade --profile lab --preview
```

Use the equivalent LXC paths for containers.
The [snapshot reference](skills/proxmox-axi/references/guest-management.md#guest-snapshots) covers protected configuration reads, confirmation, task completion, RAM-state rollback behavior and remaining refusals.
Rollback and deletion each require their own exact confirmation; QEMU RAM-state rollback may start the VM even when `start=0`.

### Guest backups

Back up explicitly selected guests to managed storage, then inspect completed backups:

```sh
proxmox-axi create '/nodes/{node}/vzdump' --api-node '<node>' --api-vmid '100,101' --api-storage backups --api-mode snapshot --api-compress zstd --profile lab --preview
proxmox-axi get '/nodes/{node}/storage/{storage}/content' --api-node '<node>' --api-storage backups --api-content backup --profile lab
```

Creation fixes `remove=0` to prevent pruning; implicit guest selection, hooks, arbitrary paths and retention selectors remain refused.
The [backup reference](skills/proxmox-axi/references/guest-management.md#guest-backups) covers task completion, selected backup modes and separately confirmed deletion of reviewed dump archives or PBS guest backups.
General media/disk deletion and unprotecting backups remain refused.

### Restore guest backups

Inspect a trusted backup configuration through the private result channel, then preview restoration to an unused guest ID and explicit managed storage:

```sh
proxmox-axi create '/nodes/{node}/qemu' --api-node '<node>' --api-vmid 210 --api-archive 'pbs:backup/vm/100/2026-11-03T06:00:00Z' --api-storage local-lvm --api-unique 1 --api-start 0 --profile lab --preview
proxmox-axi create '/nodes/{node}/lxc' --api-node '<node>' --api-vmid 211 --api-ostemplate 'pbs:backup/ct/101/2026-11-03T06:00:00Z' --api-restore 1 --api-storage local-lvm --api-unique 1 --api-start 0 --profile lab --preview
```

The [restore reference](skills/proxmox-axi/references/guest-management.md#restore-guest-backups) covers protected source inspection, inherited settings, LXC unprivileged mode, confirmation and task completion.
Only reviewed managed backup sources are admitted; force overwrite, raw host paths, stdin and live restore remain refused.

## Safety

- Ordinary JSON reads use trusted HTTPS, a five-second total deadline and a 64 KiB response bound, and reject redirects.
  Managed transfers have separate administrator-controlled byte and elapsed limits.
- Operations whose effects, transport or secret handling are not reviewed remain discoverable but uncallable.
  Unresolved policy fields deny invocation, and changing a capture never admits new operations automatically.
- Writes cover [QEMU creation and cloning](#create-and-clone-qemu-guests), [LXC creation and cloning](#create-and-clone-lxc-guests), [backup restoration](#restore-guest-backups), [confirmed guest execution and status retrieval](#confirmed-guest-execution), guest power operations, guest destruction, [selected guest configuration settings](#guest-configuration-and-compute-settings), [managed disk attachments](#manage-disk-attachments), growth-only guest disk resize, pool management, task cancellation, node execute batches, [media uploads and catalogue installation](#discover-and-install-guest-media), [guest backups](#guest-backups) and the reviewed credential/session setup operations.
  Effectful CIFS/PBS scans use the same preview and confirmation policy even though their vendor method is GET.
- Inspect `schema get|create|set|delete <template>` and the generated `write-policy.json` before enabling an operation.
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
  `task status` and `task wait` label the vendor's running/stopped state as `data.processState`, separately from the action outcome in `status`.
- `task log` returns numbered lines without storing them in the journal.
  Its table columns are always `n` (line number), then `t` (text).
  Ordinary `get`, `ls` and `task log` reject `download=true`, including through `--body-file`, with `INVALID_INPUT` before credential resolution or HTTP.
  Standalone numbered-log reads accept `--api-download false`; hosted ordinary task-log `get` and `ls` omit the download flag entirely.
  For private text downloads, use the [S5 transfer contract](docs/s5-contract.md).
- `task wait` has a 1-30000 ms elapsed budget, defaulting to 5000 ms.
  If the final request exhausts the remaining budget after a valid observation, the wait returns that observation with `wait: deadline-reached`.
  A timeout before the first valid observation remains a failure.
- `task cancel` requires its own preview and exact confirmation, using the same operation permission as deleting the task route.
- Lost responses and crashes remain uncertain, with no automatic mutation retry.
  HTTP 400, 401 and 403 refusals mark the intent failed and include bounded, sanitized parameter or permission hints when recognized.
  A refused batch wrapper leaves all its descendants `not-sent`, including nested batches.
- `journal reconcile` can observe reviewed direct configuration or status fields, or inspect retained UPIDs.
  Description comparisons ignore trailing whitespace in both the requested and observed values.
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
  `--limit <1-1000>` changes the display limit, `--fields` chooses fields, and `--full` includes all received rows and, unless `--fields` is supplied, all fields retained after safety filtering.
  Protected configuration and pending-setting reads follow the [private result contract](docs/s4-contract.md) instead of list display formatting.
  See [Infrastructure discovery across profiles](#infrastructure-discovery-across-profiles) for storage index filtering.
  Unknown `--fields` names return `INVALID_INPUT` with available names from the selected policy's `outputFields` when defined, otherwise from the response schema.
  Except for `/version`, automatic reads validate field names after target catalogue detection; an explicit `--catalogue` validates them before network access.
- Provider totals and pagination remain separate from received counts and display truncation.
  An empty received page with a positive `providerTotal` reports `empty: empty-page`, regardless of visibility.
  Otherwise, an empty result reports `verified-empty` only with complete visibility, or `visibility-unverified` when visibility is filtered or unknown.
  Filtered or unknown visibility keeps `total` null even when `providerTotal` is present.
- Ordinary list-read schema hints run offline and carry the explicit replay catalogue or detected catalogue, without credential selectors.
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

S6 checks exercise native Linux and immutable package admission against fake services with process-level outbound networking denied.
Use an absolute output directory outside the checkout:

```sh
pnpm verify:acceptance -- --task S6.1 --pack "$PWD/evidence" --out "$RUN/S6.1" --network fake-only --through standalone --native-platform current --repeat-through S6
pnpm verify:acceptance -- --task S6.2 --pack "$PWD/evidence" --out "$RUN/S6.2" --network fake-only --through standalone --all-route-variants --all-outcomes --repeat-through S6
```

`admission-delta.json` retains installed file hashes, archive integrity, baseline fixture identity and unresolved admission counts for the next release-candidate Artium fold.
S6 installs the sealed 0.0.1 baseline beside the owned package offline and records both executed versions and archive identities.
Use `node /absolute/owned-package/bin/proxmox-axi.mjs --version` to select the owned executable when a baseline `proxmox-axi` is on PATH.
Current-package S6 `--through both` hosted journeys are deferred to that fold, which runs once per release candidate rather than per slice.
These gates validate the infrastructure and currently admitted capabilities.
They do not certify full release completeness: unreviewed operations remain uncallable, and their expected refusals do not prove runtime support.
Native Windows, live commissioning and the Artium fold remain pending.
Artium journeys are opt-in through the existing fixture environment variables and `--through both`; configured tests explicitly skip them when no fixture is supplied.

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
It also runs the package admission and coexistence checks described above and, on Linux, the native configuration and journal journeys.
It requires npm, pnpm and tar, with both the owned package's and sealed baseline's production dependencies already available in the local pnpm store.
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
Package installation runs offline; see [Tests](#tests) for the required cached dependencies.

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

`--repeat-through S2` includes catalogue route cases in the standalone journey and, with `--through both`, the hosted journey.

The S5 selectors cover transfers/formatters (S5.1) and console/migration duplex sessions (S5.2).
S5.2 also runs the S5.1 journeys.
Hosted S5 proof is optional per slice; select `--through both` only when the pinned external fixture is available.

Use this repository's `evidence` directory for `--pack`, and create the parent run directory first.
The task output directory must be new and outside the checkout.
The driver verifies retained fixture hashes and records package integrity, fixture identity, sanitized public transcripts, case outcomes and the fake request ledger.
S6 `result.json` coverage summaries match evidence IDs as complete slash-delimited segments, including an exact case ID without a suffix, and map executed S5.2 transfer, duplex, guest-file and batch-policy cases to their transport outcomes.
`AC-FULL`, `AC-COVERAGE` and `AC-PLATFORM` remain pending even when cases are recorded; see the [S6 release limitations](#development).
Before retaining each public transcript, it rejects canaries in raw, JSON-escaped or URL-encoded form in either stdout or stderr.
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

Released under the [MIT License](LICENSE).
