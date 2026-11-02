# Guest settings and disk growth

Carry the selected profile, node and VMID through each request.
Read `/nodes/{node}/qemu/{vmid}/status/current` or its LXC equivalent for ordinary resource metrics.

## Private configuration reads

Configuration and `/pending` GETs require a caller-owned inherited pipe or socket selected by `PROXMOX_AXI_RESULT_FD` (descriptor 3 or higher).
Launch the CLI executable directly from the caller that owns that pipe.
Terminals, regular files, stdout and stderr are refused, and a missing private pipe fails before provider access.
Stdout contains `data: { "privateResult": true }`; the complete validated payload travels privately, is not trimmed by table display flags, and creates no journal.
Each frame is a four-byte unsigned big-endian byte length followed by at most 65536 bytes of UTF-8 JSON containing `version: 1`, `binding` and `payload`.
Validate the frame version and expected origin, identity, operation, request, actor and credential-revision bindings before consuming it.
Standalone guest-read request bindings hash `<selected catalogue> <encoded request path including query>` with SHA-256; hosted callers use the authenticated request ID supplied by the host.
Keep these payloads out of public logs and terminal output.
Use private configuration digests to guard concurrent modifications when changing settings.

## Compute settings

Confirmed `set .../config` supports the settings present in each guest's contract: names/description, cores, CPU limits/weights, memory, onboot and startup behavior.
QEMU also supports sockets, vCPUs, balloon memory and an emulated CPU model; LXC also supports swap.
Use QEMU memory as `2048` or `current=2048` in MiB, and integer MB values for LXC memory and swap.
CPU models accept only the model identifier or `cputype=<model>`; `host` and feature overrides remain refused.
Startup keys must appear in canonical order (`order`, `up`, `down`) without duplicates; a bare integer also sets `order`.

## Disk growth

Use `set '/nodes/{node}/qemu/{vmid}/resize'` or its LXC equivalent with `--api-disk`, `--api-size '+8G'` and an optional `--api-digest` from the private configuration read.
Only positive relative increments with an explicit uppercase `K`, `M`, `G` or `T` unit are admitted.
Absolute targets, zero, negative growth, lock bypass and QEMU EFI/TPM selectors remain refused.
QEMU supports ordinary IDE, SATA, SCSI and VirtIO disk selectors; LXC supports rootfs and the selected catalogue's mount-point selectors.
Inspect `schema set '<resize-template>'` for the exact invocation contract.
Preview first, then repeat the identical target and amount with its confirmation.
Treat the returned UPID as pending and use `task wait` with its node, UPID, journal ID and profile to observe completion.
Growth does not promise that a guest partition or filesystem has expanded.
After an uncertain response, inspect the journal and task rather than repeating relative growth, which could add space twice.
