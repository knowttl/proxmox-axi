# Protected results and memory authentication

Sensitive results require a caller-owned inherited pipe before upstream transmission.
`PROXMOX_AXI_RESULT_FD` selects its descriptor, which must be at least 3 and refer to a pipe or socket.
Terminals, regular files, stdout and stderr are refused.
There is no output-file fallback and no automatic retry after creation or uncertain delivery.
Each frame contains a four-byte unsigned big-endian payload length followed by at most 65536 bytes of UTF-8 JSON.
The JSON shape is `{ "version": 1, "binding": { "origin": "...", "identity": "...", "operation": "...", "request": "...", "actor": "...", "credentialRevision": "..." }, "payload": ... }`.
Standalone request bindings are SHA-256 fingerprints; the host supplies an authenticated request ID, actor and credential revision.
Receivers validate framing, version and every expected binding before accepting the payload.
Broken delivery after transmission returns an uncertain result and consumes its confirmation.

Resolved input values and newly returned protected values are registered before releasing public provider content.
Provider content is scanned/redacted across raw, URL-encoded, JSON-escaped and base64 forms after response chunks are assembled.
Generated protocol metadata, including keys, status words and confirmation tokens, stays outside the value scanner.
Those fields and durable journal records exclude protected inputs and results by construction.
This preserves usable confirmations and status fields when an operation password happens to equal `a` or `success`.
Provider-derived free text remains subject to scanning and redaction.
UPIDs are provider content even inside task metadata.
An identifier containing a registered protected value produces an uncertain outcome without retaining the identifier or retrying the mutation.
Caller-supplied path identifiers containing protected values are refused before creating a preview or transmitting a request.
Every batch child follows the same protected-input and result rules recursively.

Profiles choose exactly one authentication branch.
`api-token` uses `tokenId` and a `token` SecretRef.
`ticket` uses `userId`, `ticket` and `csrfPreventionToken` SecretRefs.
`password` uses `userId`, a `password` SecretRef and an optional `otp` SecretRef.
Omitted required references select `PROXMOX_AXI_TOKEN`, `PROXMOX_AXI_TICKET`, `PROXMOX_AXI_CSRF_PREVENTION_TOKEN` or `PROXMOX_AXI_PASSWORD` respectively.
Ticket requests send the PVE cookie only to the selected HTTPS origin and include CSRF for non-GET methods.
API-token failures never fall back to a user identity.
The four token-forbidden credential-management mutations use user sessions with the shared write gates; ticket acquisition uses the explicit authentication flow.

`auth acquire`, `auth continue --session <id>` and `auth cancel --session <id>` never prompt or launch a browser.
`auth session` explicitly starts a caller-managed process accepting newline-separated JSON argv arrays on stdin, with at most 256 commands, 65536 buffered input bytes and five minutes of process lifetime.
Each command can select its own profile and `--format json`.
The caller keeps stdin open while using returned session IDs, then closes it to end the process.
Acquired tickets, CSRF values and signed challenges remain in memory or the private result channel, with five-minute expiry and explicit cancellation.
They are never written into profiles, disk caches, keyrings or journals.
Use `--session <id>` on subsequent operations in that process, including previews and confirmations.
Automatic password acquisition for a single invocation also requires the private sink; multi-step writes should use an explicitly retained session or supplied ticket profile.

OTP continuation supplies a protected `response` reference in the body object.
WebAuthn continuation additionally supplies `webauthnOrigin` equal to the selected PVE origin and requires a caller capable of the PVE ceremony.
The PVE server remains responsible for verifying the actual challenge response.
An Artium-origin ceremony is never substituted.
OpenID acquisition supplies `openid: { "realm": "<realm>", "redirect-url": "<PVE origin>" }`.
Its authorization URL is returned privately for caller-managed interaction.
Continuation supplies protected `code` and `state` references under `openid` with the same redirect origin.
Completed authentication must return the selected `userId`; an identity change fails.

The reviewed Artium adapter binds each memory session to its authenticated actor, client session family, selected credential ID/revision, PVE origin and identity.
Its public session IDs are identifiers requiring fresh ownership checks, not bearer capabilities.
The adapter resolves selected state before ordinary SecretRef injection and never adds a SecretRef handle kind.
Only explicitly selected `--session` state can supplement the selected credential profile.
Private host state injection is confined to that authenticated boundary.
Artium login and PVE login remain separate.
Hosted protected API input uses `--protected-input` with a bounded stdin object `{ "api": { ... }, "secrets": { "PVE_INPUT_NAME": "<value>" } }`.
API secret fields reference those names with standard `{ "env": "PVE_INPUT_NAME" }` references, including nested batch arguments.
No caller-selected host secret file is accepted.
Host result references are consumed through `artium-axi proxmox-axi result take <operation> <id>` into the same inherited private pipe.
Result retrieval rechecks the current grant, actor, operation and credential revision and is never automatically replayed.
The host retains at most four sessions and four protected results per actor, 64 of each in total, with five-minute expiry.
Native Windows and live commissioning remain pending.
