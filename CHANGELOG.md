# Changelog

## [0.1.3](https://github.com/knowttl/proxmox-axi/compare/proxmox-axi-v0.1.2...proxmox-axi-v0.1.3) (2026-11-04)


### Features

* add confirmed firewall option management ([#66](https://github.com/knowttl/proxmox-axi/issues/66)) ([2b4642f](https://github.com/knowttl/proxmox-axi/commit/2b4642fb58f7ea3c5629f7d128c5d08935c665ec))
* add confirmed ordered firewall rule management ([#67](https://github.com/knowttl/proxmox-axi/issues/67)) ([07f4423](https://github.com/knowttl/proxmox-axi/commit/07f4423d25c75ac69e89631c329cbd54aa017fb4))
* add confirmed QEMU guest execution and status retrieval ([#62](https://github.com/knowttl/proxmox-axi/issues/62)) ([8b62ff5](https://github.com/knowttl/proxmox-axi/commit/8b62ff5df661f7c0e38afece6e4d106191dcad5f))
* add firewall security groups and guest references ([#70](https://github.com/knowttl/proxmox-axi/issues/70)) ([01c182b](https://github.com/knowttl/proxmox-axi/commit/01c182b6578f39bf6329698a3d49c4dbc8f11dca))
* add guest backup creation and restricted deletion ([#58](https://github.com/knowttl/proxmox-axi/issues/58)) ([4cedc41](https://github.com/knowttl/proxmox-axi/commit/4cedc41f730c53940ba2bd32a787e14ff0d7a0a0))
* add guest configuration reads and compute settings ([#43](https://github.com/knowttl/proxmox-axi/issues/43)) ([e97fcbc](https://github.com/knowttl/proxmox-axi/commit/e97fcbc4c169de748ec4b30371c5c2ae3fbf3bb9))
* add guest media discovery and catalogue template installation ([#56](https://github.com/knowttl/proxmox-axi/issues/56)) ([b902da4](https://github.com/knowttl/proxmox-axi/commit/b902da4efb697dcc7f7bd8e792fb2addcd787fa2))
* add LXC guest creation and cloning ([#55](https://github.com/knowttl/proxmox-axi/issues/55)) ([54a9dbf](https://github.com/knowttl/proxmox-axi/commit/54a9dbf89a575f3121cddbd3ce8a26275f8b865b))
* add managed guest disk configuration and paginated schemas ([#48](https://github.com/knowttl/proxmox-axi/issues/48)) ([d6ca90a](https://github.com/knowttl/proxmox-axi/commit/d6ca90a71ec6bed28c72ffb872f0589dfabbc6b9))
* add private node-network inspection ([#72](https://github.com/knowttl/proxmox-axi/issues/72)) ([6be8d12](https://github.com/knowttl/proxmox-axi/commit/6be8d129c5ca0057f1605dbb2630e13645b5576d))
* add private QEMU guest-agent readiness checks ([#61](https://github.com/knowttl/proxmox-axi/issues/61)) ([6033681](https://github.com/knowttl/proxmox-axi/commit/6033681355a5215c6a8c185695bbac1a6e2523ff))
* add QEMU and LXC snapshot management ([#57](https://github.com/knowttl/proxmox-axi/issues/57)) ([763d43a](https://github.com/knowttl/proxmox-axi/commit/763d43ae6b3f844cde2525fb67ec3326c4a4cb6e))
* enable QEMU guest creation and cloning ([#53](https://github.com/knowttl/proxmox-axi/issues/53)) ([1dc4a2e](https://github.com/knowttl/proxmox-axi/commit/1dc4a2ea235cf77bd99b87b34ad83daa82506442))
* support cloud-init onboarding and media regeneration ([#51](https://github.com/knowttl/proxmox-axi/issues/51)) ([6423a5b](https://github.com/knowttl/proxmox-axi/commit/6423a5b17fd7ea127d89c1945bda5cf52ae31a5e))
* support confirmed QEMU and LXC disk growth ([#47](https://github.com/knowttl/proxmox-axi/issues/47)) ([ba69d37](https://github.com/knowttl/proxmox-axi/commit/ba69d37472a9ef699bf24427340cf184f3d71a1c))
* support firewall aliases and IP sets ([#69](https://github.com/knowttl/proxmox-axi/issues/69)) ([3c466a6](https://github.com/knowttl/proxmox-axi/commit/3c466a63a777bddfce9026a58a1ccb3524153dd4))
* support guest networking, boot media and agent configuration ([#50](https://github.com/knowttl/proxmox-axi/issues/50)) ([0f19bdd](https://github.com/knowttl/proxmox-axi/commit/0f19bdd36a489cb6907a8c0898119c9f4a4c25a9))
* support managed QEMU and LXC backup restoration ([#59](https://github.com/knowttl/proxmox-axi/issues/59)) ([605c94c](https://github.com/knowttl/proxmox-axi/commit/605c94c8555f6548f6d627f8a8052be768349ccd))


### Bug Fixes

* correct acceptance route replay and evidence coverage ([#52](https://github.com/knowttl/proxmox-axi/issues/52)) ([021eee5](https://github.com/knowttl/proxmox-axi/commit/021eee57bd980cb56c95cbe5c7e2c8f46151a565))
* correct read contracts and hosted inventory flags ([#44](https://github.com/knowttl/proxmox-axi/issues/44)) ([d112f21](https://github.com/knowttl/proxmox-axi/commit/d112f212229517e053f56d324bb7b3143c01a0f7))
* handle Proxmox read response shapes and object field selection ([#75](https://github.com/knowttl/proxmox-axi/issues/75)) ([120020c](https://github.com/knowttl/proxmox-axi/commit/120020ce704480739086fb68ef00e3d962cbee16))
* keep duplex sessions active while partial frames arrive ([#46](https://github.com/knowttl/proxmox-axi/issues/46)) ([63f7ddb](https://github.com/knowttl/proxmox-axi/commit/63f7ddba90c7820869e36ed64cecdeb29a28c9a8))
* normalize numeric guest configuration during journal reconciliation ([#76](https://github.com/knowttl/proxmox-axi/issues/76)) ([196383d](https://github.com/knowttl/proxmox-axi/commit/196383df6e1854747380096d6b306a1806f76596))

## [0.1.2](https://github.com/knowttl/proxmox-axi/compare/proxmox-axi-v0.1.1...proxmox-axi-v0.1.2) (2026-11-02)


### Features

* add infrastructure discovery reads and agent skill ([#42](https://github.com/knowttl/proxmox-axi/issues/42)) ([834cad2](https://github.com/knowttl/proxmox-axi/commit/834cad24c61d7ad3c1a4904ad89a28116505e0a7))


### Bug Fixes

* license the package under MIT ([#40](https://github.com/knowttl/proxmox-axi/issues/40)) ([a029f6d](https://github.com/knowttl/proxmox-axi/commit/a029f6d0e15174242e76772ed2cbac44823cf91e))

## [0.1.1](https://github.com/knowttl/proxmox-axi/compare/proxmox-axi-v0.1.0...proxmox-axi-v0.1.1) (2026-11-02)


### Features

* add confirmed writes, durable journals and task tracking ([#20](https://github.com/knowttl/proxmox-axi/issues/20)) ([e5b5ec1](https://github.com/knowttl/proxmox-axi/commit/e5b5ec1774b6c191ad9eada7999ce167c6235749))
* add managed transfers and protected duplex sessions ([#29](https://github.com/knowttl/proxmox-axi/issues/29)) ([51f376c](https://github.com/knowttl/proxmox-axi/commit/51f376ca5ca4fe151ead282fd0ce2d7e3b4cabea))
* add native Linux and immutable package admission gates ([#35](https://github.com/knowttl/proxmox-axi/issues/35)) ([83607c7](https://github.com/knowttl/proxmox-axi/commit/83607c77e615a03c242167c6ee37d4be9d5e8025))
* add protected results and user authentication sessions ([#22](https://github.com/knowttl/proxmox-axi/issues/22)) ([08d03e2](https://github.com/knowttl/proxmox-axi/commit/08d03e2e778f4d5a1bcf40329563a4d7c437673b))
* complete S3 reconciliation and acceptance follow-ups ([#21](https://github.com/knowttl/proxmox-axi/issues/21)) ([9c63d58](https://github.com/knowttl/proxmox-axi/commit/9c63d58fd9167385ebbd86135c8c1dac9d0bf11c))


### Bug Fixes

* correct live API compatibility and write outcome reporting ([#37](https://github.com/knowttl/proxmox-axi/issues/37)) ([3efa321](https://github.com/knowttl/proxmox-axi/commit/3efa3217766cbca29ac95ccb3dc6b370cfb33965))
