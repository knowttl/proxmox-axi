# Firewall options and default policies

Select the profile for the intended host or cluster and carry it through reads, previews, confirmation and journal inspection.
Option reads, enable/default-policy updates and [ordered rule management](#ordered-firewall-rules) are admitted at cluster, node, QEMU and LXC scope.
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

Option delete/reset selectors, logging/filter/conntrack/backend changes, SDN-vnet firewall operations, aliases, IP sets and security-group administration remain refused in this admission.

## Ordered firewall rules

Rule lists, individual rules and ordered previews can contain sensitive comments and other provider text.
Prepare the inherited caller-owned private result pipe described in the [private-channel guidance](guest-management.md#private-configuration-reads) before launching these commands directly from its owner.
Ordinary output carries metadata only, and journals retain fingerprints rather than rule content.
The same GET routes exist at `/cluster/firewall/rules`, `/nodes/{node}/firewall/rules` and the QEMU/LXC guest paths:

```sh
proxmox-axi get '/nodes/{node}/qemu/{vmid}/firewall/rules' --api-node '<node>' --api-vmid 100 --profile '<profile>'
proxmox-axi get '/nodes/{node}/qemu/{vmid}/firewall/rules/{pos}' --api-node '<node>' --api-vmid 100 --api-pos 0 --profile '<profile>'
```

The private list includes each current position and the provider's shared rules-list digest; an empty list has no row digest.
Positions are not stable rule identifiers.
Read and review the current list before selecting an edit, move or deletion.
Discover the exact operation ID and executable schema with `schema create|set|delete '<template>' --view invocation`, then grant only that mutation in the selected profile and any independent host policy.
Stateful rule changes inside execute batches remain refused; use a separate preview and confirmation per operation.

Creation is a staged operation with a fixed integer `enable=0` that callers cannot override.
The provider prepends the new disabled rule and ignores creation digests; create-position and digest inputs are refused by this admission.
This is NON-ATOMIC CREATE: the client rechecks the observed list before dispatch, but another writer can change it between that read and creation.
The client compares the observed ordered result afterward and reports uncertainty on any unexpected result or unavailable verification.
It never retries creation or automatically deletes an entry to recover.

```sh
proxmox-axi create '/nodes/{node}/qemu/{vmid}/firewall/rules' --api-node '<node>' --api-vmid 100 --api-type in --api-action ACCEPT --api-proto tcp --api-dport 22 --api-source '<source-cidr>' --profile '<profile>' --preview
```

Inspect `warnings`, including the non-atomic creation limitation, and the private frame's complete `before` and predicted ordered `after` lists before repeating the exact request with its confirmation.
The private preview also carries `nonAtomicCreate`; ordinary output carries `privatePlan: true`.
Validate its request binding as SHA-256 of the fingerprint in that preview's confirmation, as for other private writes; hosted callers use the authenticated request ID.
The complete observed list, including provider `errors` diagnostics, and exact inputs are HMAC-bound to confirmation and re-read before dispatch, so intervening observed changes require a fresh preview even when only diagnostics change.
Plan frames remain bounded to 65536 bytes; oversized plans fail rather than truncating or omitting rules.
The predicted list includes the resulting order and IP-family settings but omits future digest metadata and provider `errors` diagnostics, which are recomputed on reload rather than persisted as rule settings.
Post-write comparison checks ordered persisted settings, excluding digests and diagnostics; inspect current diagnostics through a fresh private read.

A separate fresh preview and confirmation enables the staged rule, using its current position:

```sh
proxmox-axi set '/nodes/{node}/qemu/{vmid}/firewall/rules/{pos}' --api-node '<node>' --api-vmid 100 --api-pos '<current-pos>' --api-enable 1 --profile '<profile>' --preview
```

Edits and deletion automatically carry the currently observed rules-list digest into the provider's locked mutation.
A supplied stale digest is refused; there is no bypass for the native guard.
Supported field changes use `type` in/out, action ACCEPT/DROP/REJECT, integer enable 0/1, literal IPv4 or pure IPv6 addresses with optional CIDR, tcp/udp/icmp/icmpv6, individual numeric ports 1-65535 and reviewed interface names.
Ports require tcp/udp; guest interfaces are net0 through net31.
Source and destination addresses must use the same IP family, consistent with icmp (IPv4) or icmpv6 (IPv6) when selected.
Field edits are refused if the resulting rule retains aliases/IP sets, macros, ICMP subtype selectors, service/range port selectors or unreviewed protocols.
An inherited unsupported address may be replaced with a reviewed literal address when the resulting rule meets these restrictions.
Comments, port lists/ranges, service names, group/forward mutations and field-removal selectors are not admitted here.
Every change requires exact confirmation; broad ACCEPT rules and deletion carry explicit warnings, including when enabling an existing staged rule.

Reordering uses a separate `set .../{pos}` request with `--api-moveto '<boundary>'` and no rule-field edits.
The provider inserts before the original boundary position, not at an interpreted final index: moving original position 0 to boundary 2 in `[A,B,C]` produces `[B,A,C]`.
A boundary at or beyond the original length appends; moving to the same position preserves order.
Inspect the private resulting order before confirming.
Deletion uses `delete .../rules/{pos}` with its own preview and confirmation and preserves the relative order of remaining rules.
Group-reference and forward targets, SDN-vnet and security-group rule namespaces remain refused.

Rule writes return synchronous null results, with completion metadata on stdout and the validated null result privately.
Successful client completion also means the ordered result matched the private plan at the post-write observation; it does not prove effective filtering, enduring state or attribution of concurrent changes.
After an uncertain create or any other uncertain mutation, retain the journal and inspect the complete current list privately without retry or automatic deletion.
A matching rule or position alone does not prove which writer created it.
`journal reconcile` does not turn a later matching list into proof that this request succeeded.
