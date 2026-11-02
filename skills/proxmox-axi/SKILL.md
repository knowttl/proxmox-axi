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
For configuration and `/pending` reads, compute settings, managed disk attachments and growth-only disk resize, follow the [guest management reference](references/guest-management.md).
That reference ships inside this skill folder and includes private pipe setup, receiver bindings, input constraints and digest handling.

Run `proxmox-axi inventory` or `proxmox-axi schema <method> '<template>'` offline before choosing an operation and its supported inputs.
Discoverable routes may remain refused; never bypass admission or broaden permissions to work around a refusal.
For an authorized mutation, use its existing `create`, `set` or `delete` command with `--preview`, inspect the selected target and inputs, then repeat the exact request with `--confirm '<confirmation>'`.
Changed targets, profiles, inputs or policy require a fresh preview.
Supply sensitive inputs through supported env/file SecretRefs in a protected body file, never literal password or token arguments.
Treat a returned UPID as pending and use `proxmox-axi task wait --api-node '<node>' --api-upid '<UPID>' --journal '<intent-id>' --profile '<profile>'` to observe completion.
A bounded wait can end while the task is still running; inspect its outcome before proceeding.
After lost responses, inspect `proxmox-axi journal show '<intent-id>' --profile '<profile>'` and reconcile or inspect independently rather than retrying the mutation automatically.
Keep protected result and byte-channel payloads out of ordinary output and logs.
