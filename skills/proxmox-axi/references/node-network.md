# Private node-network inspection

Select the intended profile and use the inherited private result pipe described in [guest management](guest-management.md) for every network read.
Network addresses, comments, custom configuration and native pending diffs must remain private.

```sh
proxmox-axi get '/nodes/{node}/network' --api-node '<node>' --profile '<profile>'
proxmox-axi get '/nodes/{node}/network/{iface}' --api-node '<node>' --api-iface '<iface>' --profile '<profile>'
```

The collection accepts only the node selector and returns private `interfaces` and the native envelope `pendingDiff`.
Both reads prefer pending configuration when present.
The collection's `activeConfiguration: unverified` and `visibility: unknown` mean the list is neither authoritative active configuration nor a complete inventory.
The provider omits loopback, may hide bridges by permission, and does not read externally sourced configuration.
Per-interface reads carry preferred configuration only; they do not establish complete visibility or active configuration.
Interface `active` and `exists` flags do not establish active addresses or management reachability.
Native numeric and bridge-port flag representations are narrowly normalized before validation.

Bridge, VLAN and bond create/update/delete, OVS mutations, network apply/revert and SDN changes remain refused, including through batches.
Network mutations are deferred until authoritative complete configuration observation and serialization-preservation safeguards can be established.
Do not bypass a refusal or infer that inspection makes a later mutation safe.
