The opaque `proxmox-axi-0.0.1.tgz.base64` fixture contains the unchanged sealed offline `@knowttl/proxmox-axi` 0.0.1 archive, encoded as base64.
Its decoded SHA-256 is `e7ab445c20c13151772ab1f29ee9d1a68537b01763d46d7cd92a96f1cb890cde`.
Package admission checks that identity before installing and executing it beside the owned package.
This baseline is distinct from the hosted admission archive pinned in `test/artium-fixture.json`; it does not amend that pin or establish hosted compatibility.

`live-8.2.7.json` retains the decimal string port and trailing description newline reported by a live 8.2.7 test.
Session identifiers, credentials and description text are synthetic replacements.
The refusal cases model HTTP validation, authentication and permission responses, including the observed `Pool.Allocate` refusal.
Their envelopes are constructed boundary fixtures rather than exact wire recordings.

`localhost-cert.pem` and `localhost-key.pem` are public test-only TLS material for the package-contract and named-profile infrastructure tests' loopback journeys.
The certificate is valid from 2020 through 2099 to tolerate host clock steps and covers `localhost` and `127.0.0.1`.
Never use this public private key for real services.
