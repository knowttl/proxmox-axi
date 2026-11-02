---
name: proxmox-axi
description: Inspect Proxmox hosts and clusters through proxmox-axi, select named profiles, and use reviewed guest operations with preview, confirmation and task tracking.
---

# Proxmox discovery and guest management

Use the configured proxmox-axi CLI for the requested host or cluster.
If it is not installed, invoke the package with `npx --yes --package @knowttl/proxmox-axi proxmox-axi <command>`.
This skill does not authorize mutations or configure credentials on its own.

## Select the target

Run `proxmox-axi profile list` to discover configured names without reading secrets.
Carry `--profile <name>` through every target-specific command and use `--config <absolute-path>` when a nondefault file is selected.
File profile selection ignores competing environment-profile credentials.
Use `proxmox-axi auth status --profile <name>` to inspect credential sources without secret values.
Each profile can select an independent host or cluster, TLS trust and operation permissions.

## Discover infrastructure

```sh
proxmox-axi get /cluster/status --profile '<profile>'
proxmox-axi get /nodes --profile '<profile>'
proxmox-axi get '/nodes/{node}/status' --api-node '<node>' --profile '<profile>'
proxmox-axi get /storage --profile '<profile>'
proxmox-axi get '/nodes/{node}/storage' --api-node '<node>' --profile '<profile>'
proxmox-axi get '/nodes/{node}/storage/{storage}/status' --api-node '<node>' --api-storage '<storage>' --profile '<profile>'
proxmox-axi get /cluster/nextid --profile '<profile>'
```

The storage index exposes identifiers only, even with `--full`; use node storage reads for capacity.
A free VMID is a read-time observation, never a reservation.
Check `visibility` before interpreting an empty inventory; `permission-filtered` or `unknown` does not establish absence.
HTTP 404 means absent or hidden, and permission failures require correcting access rather than assuming an empty host.
Let ordinary reads detect the target catalogue; use explicit `--catalogue` only for intentional contract replay.
Use `--fields`, `--limit` and `--full` when more detail is needed within the output bound.

## Discover operations and complete confirmed tasks

For QEMU/LXC resource metrics, read `/nodes/{node}/qemu/{vmid}/status/current` or its LXC equivalent with the selected node, VMID and profile.
Configuration and `/pending` GETs require a caller-owned inherited pipe or socket selected by `PROXMOX_AXI_RESULT_FD` (descriptor 3 or higher).
Launch the CLI executable directly from the caller that owns that pipe.
Terminals, regular files, stdout and stderr are refused, and a missing private pipe fails before provider access.
Stdout contains `data: { "privateResult": true }`; the complete validated payload travels privately, is not trimmed by table display flags, and creates no journal.
Each private frame is a four-byte unsigned big-endian byte length followed by at most 65536 bytes of UTF-8 JSON containing `version: 1`, `binding` and `payload`.
Validate the frame version and expected origin, identity, operation, request, actor and credential-revision bindings before consuming it.
Standalone guest-read request bindings hash `<selected catalogue> <encoded request path including query>` with SHA-256; hosted callers use the authenticated request ID supplied by the host.
Never redirect that payload into public logs or terminal output.
Use private configuration digests to guard concurrent modifications when changing settings.

Confirmed `set .../config` supports the settings present in each guest's contract: names/description, cores, CPU limits/weights, memory, onboot and startup behavior.
QEMU also supports sockets, vCPUs, balloon memory and an emulated CPU model; LXC also supports swap.
Use QEMU memory as `2048` or `current=2048` in MiB, and integer MB values for LXC memory and swap.
CPU models accept only the model identifier or `cputype=<model>`; `host` and feature overrides remain refused.
Startup keys must appear in canonical order (`order`, `up`, `down`) without duplicates; a bare integer also sets `order`.

Run `proxmox-axi inventory` or `proxmox-axi schema <method> '<template>'` offline before choosing an operation and its supported inputs.
Discoverable routes may remain refused; never bypass admission or broaden permissions to work around a refusal.
For an authorized mutation, use its existing `create`, `set` or `delete` command with `--preview`, inspect the selected target and inputs, then repeat the exact request with `--confirm '<confirmation>'`.
Changed targets, profiles, inputs or policy require a fresh preview.
Supply sensitive inputs through supported env/file SecretRefs in a protected body file, never literal password or token arguments.
Treat a returned UPID as pending and use `proxmox-axi task wait --api-node '<node>' --api-upid '<UPID>' --journal '<intent-id>' --profile '<profile>'` to observe completion.
A bounded wait can end while the task is still running; inspect its outcome before proceeding.
After lost responses, inspect `proxmox-axi journal show '<intent-id>' --profile '<profile>'` and reconcile or inspect independently rather than retrying the mutation automatically.
Keep protected result and byte-channel payloads out of ordinary output and logs.
