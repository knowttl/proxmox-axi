# Firewall options and default policies

Select the profile for the intended host or cluster and carry it through reads, previews, confirmation and journal inspection.
Only option reads and enable/default-policy updates at cluster, node, QEMU and LXC scope are admitted here.
Discover each exact operation and its inputs with `schema get|set '<template>'` before enabling its mutation ID in the profile and any independent host policy.
Node options support `enable` only; default policies at that scope are not vendor inputs.
Cluster options support `policy_in`, `policy_out` and `policy_forward`; guest options support `policy_in` and `policy_out`.
Use only the policies present in the selected schema: forward supports ACCEPT/DROP, while in/out also support REJECT.
Cluster enable accepts integers 0 or 1; node/guest enable accepts boolean CLI flags including 0/1, while JSON bodies use true/false.

```sh
proxmox-axi get /cluster/firewall/options --profile '<profile>'
proxmox-axi get '/nodes/{node}/firewall/options' --api-node '<node>' --profile '<profile>'
proxmox-axi get '/nodes/{node}/qemu/{vmid}/firewall/options' --api-node '<node>' --api-vmid 100 --profile '<profile>'
proxmox-axi get '/nodes/{node}/lxc/{vmid}/firewall/options' --api-node '<node>' --api-vmid 101 --profile '<profile>'
```

Reads expose the configured enable flag, supported default policies and a digest when supplied by the provider.
Unrelated and undeclared fields are excluded even with `--full`; omitted values do not establish the effective firewall defaults or filtering state.
Use the returned digest in an update to detect concurrent changes at the provider.
Changing that supplied digest invalidates the original confirmation; an intervening provider change can also reject the confirmed request.

```sh
proxmox-axi set '/nodes/{node}/qemu/{vmid}/firewall/options' --api-node '<node>' --api-vmid 100 --api-enable 1 --api-policy_in DROP --api-policy_out ACCEPT --api-digest '<digest>' --profile '<profile>' --preview
```

Review the exact scope, settings and preview's `warnings` before repeating the same request with `--confirm '<confirmation>'` in place of `--preview`.
Every change needs confirmation, including disabling protection and accepting unmatched traffic.
`FIREWALL PROTECTION DISABLED` identifies enable=0; `DEFAULT ACCEPT` names each supplied ACCEPT default policy.
ACCEPT applies to unmatched traffic in that direction; it does not remove explicit rules or prove that every packet is accepted.
Changing the scope, node, guest, enable flag, policy, digest, identity or permissions requires a fresh preview.
Confirmed execute batches aggregate child warnings with their exact targets and retain each child's independent operation grant.

Firewall changes can cut off management access, including when enabling protection or choosing a restrictive default.
Review existing management allowances and recovery access before confirming.
The provider can update filtering automatically after configuration changes; there is no automatic rollback or separate network-apply step in these commands.
Cluster enablement, node/guest options, guest NIC firewall flags and the active firewall backend/service determine effective coverage.
Forward-policy behavior depends on backend support; this admission does not switch backends.
For a guest NIC's reviewed `firewall=1` setting, use the [guest NIC guidance](guest-management.md#guest-networking-and-boot).

The option PUT returns a synchronous null result, so API `status: success` means the configuration request completed, not that filtering is effective or management connectivity is verified.
Read the selected options again and verify intended connectivity independently before continuing onboarding.
There is no task UPID to pass to `task wait` for this update.
After a provider refusal or uncertain delivery, inspect `journal show '<intent-id>'` and the selected options before deciding on recovery; never automatically retry or disable protection to regain access.
`journal reconcile` compares supplied settings only and cannot establish effective filtering or attribute a matching configuration to this request.

Delete/reset selectors, logging/filter/conntrack/backend changes, SDN-vnet firewall options, rules, aliases, IP sets and security groups remain refused in this admission.
