# Retained read fixtures

Sanitized request and response captures are retained from the approved API evidence pack for version, permissions, inventory and task reads.
Repository paths preserve each original pack-relative path beneath this directory.
The original version and anonymous captures preserve their source bytes.
Additional read captures preserve their JSON values with normalized formatting; `retained.json` binds their repository bytes.
The captures establish vendor response contracts, not finished-product or live commissioning results.

| Repository path | Pack path | SHA-256 |
| --- | --- | --- |
| `evidence/P-VERIFIED-VERSION-response.json` | `evidence/P-VERIFIED-VERSION-response.json` | `52b56a5a1d3f31401ab6619e403555bfa8c2d883b42b2dfb7d99eb3f2a7214b3` |
| `evidence/P-VERSION-ANON-response.json` | `evidence/P-VERSION-ANON-response.json` | `76faa31a733ec62dcfcd48acbc2003383071a1e35977aac575323de037d01a27` |

`retained.json` provides all selected file bindings for the acceptance driver.
The replay table is generated from the retained request paths and query parameters.
Before-permission and verified samples remain distinct cases.
Neither the complete manifest nor private planning notes belong in this repository.
