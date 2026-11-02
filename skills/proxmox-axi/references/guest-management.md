# Guest settings and disk management

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

## Guest networking and boot

Use confirmed `set .../config` with concrete `net0` through `net31` on QEMU or LXC.
Read the existing configuration privately first, construct the complete intended property string, and include its digest when available.
NIC updates replace property strings; omitted modifiers follow provider defaults.
These operations select existing host bridges but do not create or reconfigure host interfaces.

QEMU accepts `virtio`, `e1000`, `e1000e` or `vmxnet3`, optionally prefixed with `model=`, or `<model>=<unicast-MAC>`.
Optional modifiers follow this canonical order: `bridge`, `firewall`, `link_down`, `rate`, `tag`.
For example, `virtio,bridge=vmbr0,firewall=1,tag=42` selects an existing bridge and VLAN tag.
LXC starts with required `name=<interface>` followed by optional `bridge`, `firewall`, `gw`, `hwaddr`, `ip`, `ip6`, `link_down`, `rate`, `tag`, `type` in that order.
LXC `ip` accepts IPv4/CIDR, `dhcp` or `manual`; `gw` accepts IPv4; `ip6` accepts only `auto`, `dhcp` or `manual`; `type` is `veth`.
MAC addresses must be unicast, VLAN tags are 1-4094, rates are nonnegative numbers, and firewall/link flags are `0` or `1`.
Trunks, static IPv6/gw6, host-managed/offload options, MTU/queue tuning and other modifiers remain refused pending their own review.
For confirmed NIC removal with `--api-delete net0`, follow the [configuration removal guidance](#managed-disk-configuration).

QEMU boot order uses `order=<device>;<device>` with admitted ordinary disk/NIC selectors, for example `order=ide2;scsi0;net0`.
Use a supported CD-ROM slot such as `ide2` with `storage:iso/installer.iso,media=cdrom`, or `none,media=cdrom` to eject media.
Only managed ISO filenames are admitted; host paths, remote sources and traversal remain refused.
Enable or disable QEMU agent communication with `--api-agent 1`, `--api-agent 0`, `--api-agent enabled=1` or `--api-agent enabled=0`.
Install and start the guest-agent service inside the VM separately; configuration does not prove guest-agent readiness.
Agent freeze/trim/type modifiers and host passthrough remain refused.

## Schema views

`--view` and `--offset` apply only to `schema`; `--offset` requires `--view vendor`.
The default `--view invocation` returns the complete executable invocation schema, policy and return shape without raw vendor parameters.
Use `schema <method> '<template>' --view vendor` for original vendor templates and constraints, following `page.nextOffset` with `--offset` until null.
Keep the method, template, catalogue and format unchanged between pages.
Both JSON and TOON pages retain complete parameter entries and root metadata within the 65536-byte output bound; a parameter that cannot fit is refused with `OUTPUT_LIMIT`, never truncated.
The full original vendor schemas also ship in `dist/contracts.json`.

## Managed disk configuration

Use confirmed `set .../config` with concrete QEMU slots `ide0`-`ide3`, `sata0`-`sata5`, `scsi0`-`scsi30`, `virtio0`-`virtio15`, or LXC `rootfs`/`mp0`-`mp255`.
Invocation schemas and agent flags expose concrete slot names; the [vendor schema view](#schema-views) retains original numbered templates.
Use `storage:8` for a positive GiB allocation, or conventional managed volume IDs such as `storage:vm-100-disk-0`, QEMU `storage:100/vm-100-disk-0.qcow2`, or LXC `storage:subvol-100-disk-0`.
QEMU accepts optional `file=`, then optional modifiers in canonical order: `backup`, `cache`, `discard`, `format`, `iothread`, `ssd`, `ro`, only when present in the selected vendor branch.
Cache values are `none`, `writethrough`, `writeback`, `directsync`; disk formats are `raw`, `qcow2`, `vmdk`; discard is `ignore` or `on`; other admitted modifiers use `0` or `1`.
LXC accepts optional `volume=`, the managed volume/allocation, then required `mp=/container/path` for numbered mount points, and optional `acl`, `backup`, `quota`, `ro` in that order where supported.
Host sources, bind mounts, imports, unsafe cache and other modifiers remain refused; do not copy informational `size=` fields into updates.
Replacing a configured slot changes its disk attachment and requires preview and exact confirmation.
For configuration removal, use `--api-delete scsi0` or a comma-separated list of ordinary QEMU disk slots or LXC mount points, optionally combined with `net0`-`net31` selectors for that guest.
NIC selectors can also be removed alone; LXC rootfs, unused volumes and arbitrary settings cannot be selected.
This does not admit arbitrary storage-volume deletion or force options.
Use a private configuration digest for concurrent-change protection and inspect the exact guest and disk before confirming replacement/removal.
