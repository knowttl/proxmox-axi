# Pending node networks and Linux bridges

Select the intended profile and enable only the exact bridge mutation IDs in both applicable operation policies.
Use the inherited private result pipe described in [guest management](guest-management.md) for every network read, preview and confirmed mutation.
Network addresses, comments, custom configuration and native pending diffs must remain private.

```sh
proxmox-axi get '/nodes/{node}/network' --api-node '<node>' --profile '<profile>'
proxmox-axi get '/nodes/{node}/network/{iface}' --api-node '<node>' --api-iface vmbr7 --profile '<profile>'
proxmox-axi create '/nodes/{node}/network' --api-node '<node>' --api-iface vmbr7 --api-bridge_ports '<port>' --api-autostart 1 --profile '<profile>' --preview
proxmox-axi set '/nodes/{node}/network/{iface}' --api-node '<node>' --api-iface vmbr7 --api-mtu 1500 --profile '<profile>' --preview
proxmox-axi delete '/nodes/{node}/network/{iface}' --api-node '<node>' --api-iface vmbr7 --profile '<profile>' --preview
```

Inspect the private plan and prominent management-access warnings, then repeat the exact request with `--confirm '<confirmation>'` instead of `--preview`.
All operations target preferred pending configuration; they do not apply changes.
The collection read returns private `interfaces` and `pendingDiff`; `activeConfiguration: unverified` and `visibility: unknown` prevent interpreting the list as an authoritative active configuration or complete inventory.
Per-interface reads also prefer pending configuration.
Interface `active` and `exists` flags do not establish active addresses or management reachability.

Bridge mutations accept `vmbr` followed by digits, at most 15 characters, and fix the type to Linux `bridge`.
Reviewed fields are `bridge_ports`, `autostart`, `mtu`, static `cidr`/`cidr6` and `gateway`/`gateway6`.
Static prefixes must be 1-32 for IPv4 and 1-128 for IPv6; `/0` is refused because native serialization can discard its mask.
Ports use single spaces; an empty string removes ports, while an omitted creation list creates an isolated bridge.
Ports must already be observed physical, bond or VLAN interfaces; hidden or missing ports cannot be assumed safe.
Existing static address families are carried into updates and shown in the plan so native method/family replacement cannot silently discard them.
Dynamic address methods, type conversions, physical/OVS/VLAN/bond mutations, setting deletion, custom options, comments and VLAN-awareness changes remain refused.
Read unsupported configuration privately before choosing a different admitted workflow; do not bypass refusals.

The private plan includes the observed native pending diff, proposed configuration and known affected/addressed bridge, bond and VLAN dependencies.
Management classification remains unknown because active addresses, permission-hidden interfaces and externally sourced configuration are not established by these reads.
Every mutation needs explicit confirmation even when no known addressed dependency is found.
Changes can cut access when subsequently applied or on reboot; verify recovery access before confirmation.

The confirmation binds the observed interface list and pending diff; intervening changes require a new preview.
Native pending CRUD has no optimistic digest, so client checks cannot make observation and dispatch atomic.
Unexpected post-write configuration or unavailable verification remains uncertain; inspect the journal and private pending state without retry, automatic apply, revert or reboot.
Network apply/revert and SDN changes remain refused in this admission.
