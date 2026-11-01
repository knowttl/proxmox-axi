# Managed transfers and duplex sessions

`transfer get|create <template>` selects an operation-specific byte transport.
`--response-format` selects the API formatter independently of `--format toon|json`, which controls public metadata.
Use `transfer --help` and the selected operation's schema to inspect parameters.

| Operation | Response format | Handling |
| --- | --- | --- |
| Node, VM, container and storage RRD | `png` | PNG signature checked |
| Guest/node SPICE setup | `spiceconfig` | Exact private configuration bytes |
| Storage upload | `multipart` | Streamed file with source SHA-256 bound into confirmation |
| Backup file restore download | `download` | Exact bytes through the private channel |
| Task log with `download=true`, and journal | `text` | Text with optional gzip decoding |
| QEMU guest-agent file read | `guest-file` | Managed content export with explicit representation and truncation |

`PROXMOX_AXI_STREAM_FD` must identify an inherited pipe or socket distinct from stdout, stderr and the private result channel.
Ordinary output contains byte counts, SHA-256, selected limits and completion state.
No binary, SPICE password or session ticket enters ordinary output.
Binary data is never passed through text redaction.
Callers must discard partial bytes unless the command reports completion and their expected count and hash match.
`--expected-bytes` and `--expected-sha256` allow verification against an independent source.
Managed uploads accept `--input-file <absolute-path>` and safe leaf filenames; provider `tmpfilename` overrides are refused.
The opened source remains held through hashing, confirmation and transmission.
Source changes detected during transmission produce uncertainty and are never retried.
Every effectful setup and upload uses the shared operation allowlist, durable journal and exact single-use confirmation.
Transfer format, source hash, expected result and selected limits form part of that confirmation.
Batch children cannot open byte transports.

Administrator environment settings select `PROXMOX_AXI_TRANSFER_BYTES` (default 8 GiB) and `PROXMOX_AXI_TRANSFER_MS` (default 30 minutes, also the maximum).
File streams use 64 KiB buffers and backpressure.
Guest-file envelopes have a separate fixed 128 MiB bound because the vendor permits 16 MiB content and JSON escaping can expand it.
Acceptance records peak process RSS against a fixed 384 MiB budget.
Upload task acceptance does not establish that the provider's asynchronous storage task completed.
Use the retained UPID with task status/wait.

Current guest-file `decode=true` preserves representable UTF-8 text.
`decode=false` preserves the provider's concatenated base64 chunks, including padding between individual guest-agent reads.
`--raw` decodes every padded chunk into bytes rather than stopping at the first padding marker.
Metadata distinguishes the representation's byte count/hash from the provider's raw byte count and truncation flag.
Legacy content is preserved with `encoding: legacy-unknown`; raw decoding is refused until that representation is independently established.
An absent legacy truncation field remains `unknown`.

`duplex create <setup-template>` supports guest VNC/terminal consoles, node shells and migration setup.
Use the same arguments with `--preview`, then execute with the returned `--confirm` value.
When the setup schema supports a `websocket` flag, duplex execution selects `true`.
Before requesting setup, callers must provide both the byte channel and the existing S4 private result pipe through `PROXMOX_AXI_RESULT_FD`.
The private result frame provides the ticket, user/password and other setup fields needed by the caller's inner protocol.
The tool connects only to the selected HTTPS origin and the corresponding reviewed node/guest WebSocket route.
Returned console ports must be in 5900-5999; the opaque migration socket is taken only from that authenticated setup and returned to its matching node/guest route with the bound ticket.
There is no arbitrary TCP forwarding or reconnection using a consumed confirmation.

Each direction of the inherited byte channel carries a four-byte big-endian payload length followed by that binary message.
WebSocket continuation frames are assembled into the original binary message.
Frames are limited to 1 MiB and each direction to `PROXMOX_AXI_DUPLEX_BYTES` (default 64 MiB).
`PROXMOX_AXI_DUPLEX_IDLE_MS` defaults to 30 seconds; `PROXMOX_AXI_DUPLEX_MS` defaults to five minutes and cannot exceed 30 minutes.
Connection establishment has a five-second bound.
Input EOF requests a normal WebSocket close while retaining the output half until final peer frames arrive.
Cancellation, quota failures, abnormal close and interrupted setup retain an uncertain write outcome and close the provider connection.
No automatic retry occurs.

The Artium extension provides authenticated managed streaming outside the ordinary base64 run input.
`artium-axi proxmox-axi stream -- transfer|duplex <native arguments>` uses the same private byte descriptor.
Duplex calls also require the separate S4 result descriptor; use descriptor 5 or higher for bytes when the client uses managed-session descriptors 3 and 4.
`artium-axi proxmox-axi stream limits` shows host-selected limits before execution.
The host binds actor, session family and credential revision, rechecks them during delivery, and admits one active stream per actor with a global maximum of sixteen.
It streams uploads into a private temporary source, verifies count and hash before native execution, and removes partial sources on cancellation.
Private setup frames use the S4 binding validator and register minted values before public metadata is released.
Only provider free text is scanned; generated metadata and binary messages retain their reviewed channels.
The host exposes `ARTIUM_PVE_TRANSFER_BYTES`, `ARTIUM_PVE_STREAM_MS` and `ARTIUM_PVE_DUPLEX_IDLE_MS` as administrator settings.

All retained checks use fake services under process-level outbound network denial.
Native Windows, real controllers and the release-specific console API-token compatibility disagreement remain pending.
