# Guest settings and disk management

Carry the selected profile, node and VMID through each request.
Read `/nodes/{node}/qemu/{vmid}/status/current` or its LXC equivalent for ordinary resource metrics.

## Private configuration reads

QEMU and LXC configuration, `/snapshot/{snapname}/config` and `/pending` GETs, including the `ls` aliases for pending-setting reads, QEMU `/cloudinit` GETs and backup `/vzdump/extractconfig` reads require a caller-owned inherited pipe or socket selected by `PROXMOX_AXI_RESULT_FD` (descriptor 3 or higher).
These payloads can contain credentials.
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

## Cloud-init onboarding

Use confirmed QEMU `set .../config` with `ciuser`, `sshkeys`, `ipconfig0`-`ipconfig31`, DNS settings and a cloud-init volume such as `ide2=local-lvm:cloudinit`.
Usernames are lowercase Unix-style names up to 32 characters.
Read private configuration and use its digest when available before replacing settings.
Supply passwords only as `"cipassword": { "env": "VM_BOOT_PASSWORD" }` or a protected file SecretRef in the protected `--body-file` input.
Never put password values in arguments, terminal output, logs or journal notes.
SSH keys are preferable to passwords and must be valid OpenSSH public keys.
For QEMU `sshkeys`, percent-encode the public key text once, including spaces and LF separators, as with `encodeURIComponent`; the CLI applies the outer HTTP form encoding itself.
Reviewed key types are ssh-ed25519, ssh-rsa and ecdsa-sha2-nistp256, with simple ASCII comments and one key per line.
Authorized-key command/options prefixes, blank lines, private keys and other key types remain refused.

Cloud-init IP settings use canonical order: `ip=<IPv4/CIDR>` followed by optional `gw=<IPv4>` and `ip6=auto|dhcp`, or `ip=dhcp` followed by optional dynamic IPv6, or dynamic IPv6 alone.
A gateway requires static IPv4; static IPv6/gw6 and manual QEMU IP modes remain refused.
For QEMU or LXC, `nameserver` is a single-space-separated list of IPv4 addresses and `searchdomain` is a single-space-separated DNS-name list up to 255 characters.
IPv6/scoped DNS servers and custom cloud-init snippets remain refused.
LXC raw SSH-key/password provisioning is creation-only; see [LXC creation and cloning](#lxc-creation-and-template-cloning).

After confirming configuration, preview and separately confirm `set '/nodes/{node}/qemu/{vmid}/cloudinit'` to regenerate managed media.
It returns synchronous success with no UPID; after uncertain delivery, inspect independently rather than repeat automatically.
For `get` on that same route, follow the [private-read guidance](#private-configuration-reads).
Keep that payload private and inspect whether pending values have been applied.
Cloud-init dumps remain refused, and regenerating media does not prove that the guest has booted or applied its configuration.

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

## QEMU creation and template cloning

Inspect `schema create '/nodes/{node}/qemu'` or `schema create '/nodes/{node}/qemu/{vmid}/clone'` for the selected operation and enable only its operation ID in the selected profile and any independent host policy.
Choose a VMID using the cluster's nextid read or explicit inventory; a free-ID read is an observation, never a reservation.
Create with required node/VMID and the reviewed compute, managed disk, NIC, boot, agent and cloud-init settings described above.
Basic create-only inputs include `bios`, `scsihw`, `ostype`, `pool` and optional `start` from the selected vendor schema.
Leave `start` unset or set it to `0` when onboarding must finish before first boot; `start=1` requests startup as part of creation.
Passwords still require SecretRefs in a protected body file and SSH public keys retain the cloud-init encoding rules.
For a blank installation, allocate a managed disk, attach an existing ISO, choose an ordinary boot order and preview the complete request.
Force overwrite, delete/digest selectors, custom arguments, the template flag and unreviewed hardware/machine/EFI/TPM input properties remain refused; [backup restoration](#restore-guest-backups) has its own reviewed source and destination constraints.
BIOS selection does not admit EFI/TPM variable-disk configuration; use an appropriately configured template when those properties are needed.

Select an existing template by reading its configuration privately and checking its template flag.
Preview `create '/nodes/{node}/qemu/{vmid}/clone'` with the source node/VMID and required `newid`; reviewed options are name, description, full, storage, format, target, pool and `bwlimit`.
For a full copy, use `--api-full 1` and select supported destination storage/format; linked clones use the provider's template/storage rules.
Cross-node `target` also follows provider shared-storage rules, and snapshot-source clones remain refused.

Repeat each exact request with its confirmation only after inspecting the source, destination, VMID, storage and settings.
A returned UPID means accepted, not completed; use `task wait` with the returned/source node, UPID, journal ID and profile.
Failed tasks remain failed in the journal; do not treat acceptance or an absent/hidden inventory row as success or failure proof.
After successful creation, inspect the new VMID on its actual destination node through the private configuration read.
Apply the reviewed cloud-init/onboarding settings and regenerate media if needed before first boot, then use the existing confirmed start, shutdown, reboot, stop or delete commands and task tracking.
If provisioning delivery is uncertain, inspect the journal and retained task rather than submit another create/clone automatically.

## LXC creation and template cloning

Inspect `schema create '/nodes/{node}/lxc'` or `schema create '/nodes/{node}/lxc/{vmid}/clone'` and enable only the selected operation ID in the profile and any independent host policy.
Create with required node, VMID and `ostemplate` using an existing managed template volume such as `local:vztmpl/base.tar.zst`.
Template filenames may end in `.tar.zst`, `.tar.xz` or `.tar.gz`; backup archives and host paths remain refused.
Creation always sends `unprivileged=1`, including when omitted; explicitly requesting a privileged container is refused before provider access.
Reviewed options include hostname, description, cores, CPU limits/weights, integer memory/swap, managed rootfs/mount points, NICs, DNS, onboot/startup, storage, pool and optional start.
Leave `start` unset or `0` to finish onboarding before first boot.
Use a protected body file with SecretRef-only `password`, for example `{"password":{"env":"INITIAL_PASSWORD"}}`, alongside required creation settings.
`ssh-public-keys` accepts raw OpenSSH public-key lines, separated by LF, with an optional final LF; do not percent-encode these keys as required for QEMU `sshkeys`.
The reviewed key algorithms and simple comment restrictions are the same as for QEMU keys; authorized-key options, private keys and control characters remain refused.
Host bind mounts, devices, hooks, custom features, overwrite and privilege-changing inputs remain refused; use the [restore workflow](#restore-guest-backups) for managed backups.

Before cloning, read the source template's configuration privately, check its template flag and select an unprivileged template after reviewing its inherited settings and features.
Clone inherits the source configuration, including privilege settings; this command does not rewrite those settings.
Preview `create '/nodes/{node}/lxc/{vmid}/clone'` with the source node/VMID and required `newid`; reviewed options are hostname, description, full, storage, target, pool and `bwlimit`.
Use `--api-full 1` for a full copy; linked clones and cross-node targets follow the provider's source/storage rules.
Snapshot-source cloning remains refused.
Use the same exact confirmation, source-node task wait, destination private-config inspection, VMID collision handling and uncertain-delivery rules described for QEMU provisioning above.
After task success, verify the resulting privilege and onboarding settings privately before requesting a confirmed start.

## ISO and container-template media

Use `get '/nodes/{node}/storage/{storage}/content'` with node/storage and optional `--api-content iso`, `vztmpl`, `images`, `rootdir` or `backup` to discover managed media and volumes.
An optional `--api-vmid` filters guest images; inspect the selected schema for supported content selectors.
Default rows contain volume ID, format, size and approximate size when supplied; `--fields` can request reviewed usage, guest VMID, creation-time and protection metadata.
Use the same route plus `/{volume}` and `--api-volume '<storage>:iso/<filename>.iso'` to inspect a volume's format, size, usage and protection status.
Pass the raw managed volume ID; the CLI encodes embedded separators as part of one path parameter.
Host paths, traversal and pre-encoded separators are refused.
Provider paths, notes and undeclared metadata are excluded even with `--full`.
Permission-scoped lists and empty results do not prove that media is absent or reserve a destination filename.
Large responses remain subject to the response/output byte budgets; request a specific content type or VMID when needed.

Use `get '/nodes/{node}/aplinfo' --api-node '<node>'` to list the provider's existing appliance catalogue.
Default rows expose template/package/version/type; `--fields` or `--full` can include reviewed OS/architecture/section fields.
Source/download URLs and descriptions are excluded even with `--full`.
Preview `create '/nodes/{node}/aplinfo' --api-node '<node>' --api-storage '<storage>' --api-template '<catalogue-template>.tar.zst'` to install a selected catalogue template.
Only leaf template names ending in `.tar.zst`, `.tar.xz` or `.tar.gz` are admitted; the provider must resolve the name in its catalogue and enforce storage permissions.
This does not refresh the catalogue, accept a remote URL or admit registry pulls.

For local media, use the existing managed `transfer create '/nodes/{node}/storage/{storage}/upload'` with node/storage, `--api-content iso` or `vztmpl`, `--api-filename '<safe-leaf-name>'`, an absolute `--input-file` and `--response-format multipart`.
For example, choose `installer.iso` for ISO media or `base.tar.zst` for a container template; the provider still validates supported file types and storage capabilities.
The filename must begin with an ASCII letter or digit and contain only letters, digits, dots, underscores or hyphens, up to 255 characters; paths and provider `tmpfilename` overrides are refused.
The caller must provide a private inherited pipe/socket through `PROXMOX_AXI_STREAM_FD`, descriptor 3 or higher and distinct from stdout, stderr and any private result channel.
The input remains a local file, and ordinary output contains transfer metadata only.
Use `--expected-bytes` and `--expected-sha256` for independent source verification, or the paired vendor `checksum`/`checksum-algorithm` inputs for provider-side verification.
Inspect permissions and the complete preview before repeating the exact request with `--confirm`; source bytes, filename, storage, formatter and transfer limits are bound to confirmation.
File-byte completion and an accepted UPID do not prove installation success.
Wait with the returned node, UPID, journal ID and profile, then list storage content to verify the installed volume before guest creation or attachment.
Failed tasks remain failed; interrupted delivery retains uncertainty and must never trigger an automatic retry.
Storage-content allocation/copy/attribute changes, arbitrary media deletion, remote URL download and registry operations remain refused by this admission.

## Guest snapshots

Use `get '/nodes/{node}/qemu/{vmid}/snapshot'` or the LXC equivalent with the selected node, VMID and profile to inspect the snapshot tree.
Public rows expose name, parent, creation time and QEMU RAM-state metadata; descriptions and undeclared fields stay excluded even with `--full`.
The `current` entry identifies the current guest state and cannot be created, deleted or rolled back as a saved snapshot.
For saved-snapshot details, use `get .../snapshot/{snapname}/config` with `--api-snapname` and the inherited private result channel described above.
Snapshot configuration can include credentials, descriptions and protected settings, so it never goes to ordinary output.
The `get .../snapshot/{snapname}` command index exposes command names only; it does not grant permission to execute those commands.

Inspect the selected schema and enable only each required write operation ID in the profile and any independent host policy.
Preview `create .../snapshot` with `--api-snapname '<snapshot>'` and optional single-line description; QEMU also accepts `--api-vmstate 1` to include RAM.
Snapshot names begin with an ASCII letter, contain only letters, digits, dots, underscores or hyphens, and are at most 40 characters.
Provider storage and guest-state restrictions still apply; snapshots are not independent backups.
Preview `create .../snapshot/{snapname}/rollback` to restore a saved state, with optional `--api-start 1` to request startup after success.
Rollback discards changes after the selected snapshot and requires its own exact confirmation.
A QEMU snapshot containing RAM can automatically start the VM during rollback even with `start=0`; inspect its RAM-state metadata and protected config before confirming.
Preview `delete .../snapshot/{snapname}` to remove that saved snapshot and confirm only after checking its exact identity and tree position.
Force removal, snapshot-description updates and unreviewed inputs remain refused.
Every creation, rollback and deletion requires its own exact confirmation bound to profile, node, VMID, snapshot name and settings.
A returned UPID means accepted, not completed; use `task wait` with the returned node/UPID, journal ID and profile.
After success, inspect the tree and private configuration independently; after failure or uncertain delivery, retain the journal and never retry the mutation automatically.

## Guest backups

Preview `create '/nodes/{node}/vzdump'` with explicit node, managed destination storage and `--api-vmid '100,101'` to back up selected guests.
The guest list is a comma-separated list of IDs from 100 through 999999999; implicit selection, all/pool/exclude selectors and backup-job cancellation remain refused.
Reviewed optional inputs are mode (`snapshot`, `suspend` or `stop`), compression (`0`, `1`, `gzip`, `lzo` or `zstd`), bandwidth limit in KiB/s and protection of the new backups.
Suspend/stop modes can interrupt the selected guests; inspect the mode and destination before confirming.
Creation always sends `remove=0`, including when omitted, so it cannot prune older backups through storage retention defaults.
An explicit request to enable removal, retention/pruning selectors, arbitrary dump/tmp paths, hooks and unreviewed performance or notification selectors is refused.
Existing provider configuration, permissions and storage support still apply.

Wait for the returned node/UPID with the journal ID and selected profile before treating a backup as complete.
List results through `get '/nodes/{node}/storage/{storage}/content' --api-content backup`, using reviewed volume/protection metadata and the selected storage.
Permission-filtered inventory and an absent row never prove success or reserve a backup name.
Use the [restore workflow](#restore-guest-backups) for separately confirmed restoration to a new guest ID.

Preview `delete '/nodes/{node}/storage/{storage}/content/{volume}'` with explicit node, storage and the raw complete backup volume ID, then confirm the exact request.
Deletion admits only conventional `storage:backup/vzdump-qemu-<id>-YYYY_MM_DD-HH_MM_SS.vma` or LXC `.tar` archives, optionally suffixed `.gz`, `.lzo` or `.zst`, and PBS `storage:backup/vm/<id>/YYYY-MM-DDTHH:MM:SSZ` or `ct` IDs.
PBS namespace selection remains part of the existing storage configuration.
The CLI encodes embedded separators as one path parameter; pass the raw ID without pre-encoding it.
ISO images, guest disks, unrelated backup-directory files and non-guest PBS backups cannot use this deletion admission.
The provider checks storage/volume consistency, permissions and backup protection; this admission does not unprotect backups or expose general storage-volume deletion.
Delayed/null-result deletion variants remain refused so successful transmission returns a task UPID.
Deletion is destructive and requires its own exact confirmation; a confirmation for one backup cannot authorize another volume or destination.
After task success, inspect inventory independently; failed tasks and provider protection refusals stay failed in the journal, while uncertain delivery must never trigger an automatic retry.

## Restore guest backups

Choose a trusted QEMU or LXC dump archive or PBS guest backup from reviewed storage-content listing.
Inspect its complete configuration privately with `get '/nodes/{node}/vzdump/extractconfig' --api-node '<node>' --api-volume '<backup-volume-id>'` and the inherited private result channel described above.
The extracted text can contain passwords, host-sensitive settings and descriptions; do not print or journal it.
Restore inherits configuration from the backup, including settings not overridden by supplied reviewed inputs.
Review host-device mappings, mounts, hooks and network identities before confirming; provider restore permissions remain authoritative.
Guest-setting inputs outside the existing reviewed creation allowlist remain refused, including custom arguments, hooks and host passthrough selectors.

Preview QEMU `create '/nodes/{node}/qemu'` with a new VMID, `--api-archive '<qemu-backup-volume-id>'` and explicit destination `--api-storage '<storage>'`.
For LXC, use `create '/nodes/{node}/lxc'` with a new VMID, `--api-ostemplate '<lxc-backup-volume-id>'`, explicit `--api-restore 1` and destination storage.
Sources must use the reviewed dump-archive or PBS volume-ID forms described above and match the guest family; stdin, raw host paths, unqualified filenames and other content remain refused.
LXC templates require creation mode without a restore flag; a backup requires restore mode, and destination storage is mandatory for either family's restore.
Already reviewed guest settings can override restored settings, except QEMU drive slots (`ide`, `sata`, `scsi` and `virtio`), including ISO and cloud-init attachments.
QEMU restores inherit drives from the backup and map them to destination storage; optional `bwlimit` and `unique` are restore-only inputs.
Use `--api-unique 1` to request fresh Ethernet identities when the original guest may still exist, and leave start unset or `0` until onboarding is checked.
Live/background startup during import remains refused; optional `start=1` is a separately bound request to start after completion.
All LXC requests retain the fixed unprivileged setting, including restore; inspect the source privilege/mount configuration and select a compatible backup.

Inspect the source, unused destination VMID, storage and settings before repeating the exact request with its confirmation.
Both provider creation routes refuse existing destination IDs without force; force/overwrite stays refused by this client even with confirmation.
A changed backup source or destination setting invalidates the original confirmation.
Wait on the returned node/UPID with the journal ID and profile, then inspect the destination configuration privately.
Failed tasks can leave partial destination state; inspect it and the journal before manual recovery, without automatically retrying or deleting anything.
