# Changelog

## [0.8.0](https://github.com/agenthooksprotocol/go-sdk/compare/v0.7.0...v0.8.0) (2026-10-17)


### Features

* apply configured HTTP headers to events and uploads ([#39](https://github.com/agenthooksprotocol/go-sdk/issues/39)) ([16824d6](https://github.com/agenthooksprotocol/go-sdk/commit/16824d68a84bc7792a1c512aaa04b596948b0f68))

## [0.7.0](https://github.com/agenthooksprotocol/go-sdk/compare/v0.6.0...v0.7.0) (2026-10-13)


### ⚠ BREAKING CHANGES

* report harness identity on every event ([#36](https://github.com/agenthooksprotocol/go-sdk/issues/36))

### Features

* report harness identity on every event ([#36](https://github.com/agenthooksprotocol/go-sdk/issues/36)) ([d12d155](https://github.com/agenthooksprotocol/go-sdk/commit/d12d1552b74f2d2e35b578cb4896307daf81f3ab))

## [0.6.0](https://github.com/agenthooksprotocol/go-sdk/compare/v0.5.0...v0.6.0) (2026-10-13)


### ⚠ BREAKING CHANGES

* capability.Observe is removed. Replace capability.Observe{} with the event's own declaration, for example capability.SessionEnd{Observe: true}.

### Features

* conform server JSON-RPC handling, route stdio by id, and adopt event-specific capabilities and stdio env ([#33](https://github.com/agenthooksprotocol/go-sdk/issues/33)) ([256c682](https://github.com/agenthooksprotocol/go-sdk/commit/256c6827470cbde9d24d1c5681161a3c13d5d634))

## [0.5.0](https://github.com/agenthooksprotocol/go-sdk/compare/v0.4.1...v0.5.0) (2026-10-12)


### ⚠ BREAKING CHANGES

* replace draft compatibility surfaces with typed event APIs

### Features

* replace draft compatibility surfaces with typed event APIs ([6ab7699](https://github.com/agenthooksprotocol/go-sdk/commit/6ab7699007726d14bbfa9abd2675acbc8b0cbe3b))


### Bug Fixes

* sync merged canonical provenance and pre-major release policy ([f47a035](https://github.com/agenthooksprotocol/go-sdk/commit/f47a03516ed535de28441b84ae7f069864864166))

## [0.4.1](https://github.com/agenthooksprotocol/go-sdk/compare/v0.4.0...v0.4.1) (2026-10-11)


### Bug Fixes

* **client:** preserve typed settlement events and response envelopes ([8a82f70](https://github.com/agenthooksprotocol/go-sdk/commit/8a82f707cbda800ed3408864b5cc4d0f7ca45933))

## [0.4.0](https://github.com/agenthooksprotocol/go-sdk/compare/v0.3.0...v0.4.0) (2026-10-11)


### ⚠ BREAKING CHANGES

* Consumer input and result APIs use domain names, and internal SDK assembly helpers are no longer exported.

### Features

* enforce typed operation contracts and clean public APIs ([197a872](https://github.com/agenthooksprotocol/go-sdk/commit/197a872e48c69c0947b1784e897cb8009dc979a8))

## [0.3.0](https://github.com/agenthooksprotocol/go-sdk/compare/v0.2.0...v0.3.0) (2026-10-10)


### Features

* support inline messages and coordinated attachment uploads ([#16](https://github.com/agenthooksprotocol/go-sdk/issues/16)) ([61da293](https://github.com/agenthooksprotocol/go-sdk/commit/61da293e94646472d017254e859b92f19bf9b7ae))

## [0.2.0](https://github.com/agenthooksprotocol/go-sdk/compare/v0.1.1...v0.2.0) (2026-10-09)


### Features

* add invocation-owned content attachments ([#12](https://github.com/agenthooksprotocol/go-sdk/issues/12)) ([4dd979d](https://github.com/agenthooksprotocol/go-sdk/commit/4dd979db3c09df42c2e0ea9a71b3e4ff78e99edb))

## [0.1.1](https://github.com/agenthooksprotocol/go-sdk/compare/v0.1.0...v0.1.1) (2026-10-09)


### Bug Fixes

* expose semantic typed models with structural decoding ([#9](https://github.com/agenthooksprotocol/go-sdk/issues/9)) ([89c0edc](https://github.com/agenthooksprotocol/go-sdk/commit/89c0edccdc7280a3a488f09d2e2f50e966d95488))

## 0.1.0 (2026-10-07)


### Features

* add public Go SDK and generated ergonomic APIs ([#5](https://github.com/agenthooksprotocol/go-sdk/issues/5)) ([1a506c5](https://github.com/agenthooksprotocol/go-sdk/commit/1a506c536513dbd1dd15160230fa87c8b4373d56))
* bootstrap Go SDK ([286b7ac](https://github.com/agenthooksprotocol/go-sdk/commit/286b7ac020ef2d638ca0e521cf36b64ec5148888))
* implement draft Go SDK and interoperability adapters ([#3](https://github.com/agenthooksprotocol/go-sdk/issues/3)) ([3659dc7](https://github.com/agenthooksprotocol/go-sdk/commit/3659dc7a0595315943a933455cb8e13b9945175f))


### Bug Fixes

* add SDK usage documentation ([ca9aafc](https://github.com/agenthooksprotocol/go-sdk/commit/ca9aafc5f84e5e67eee61c40032f6fa799fe0e10))
* align portable authentication with bearer and OAuth ([#4](https://github.com/agenthooksprotocol/go-sdk/issues/4)) ([348dd94](https://github.com/agenthooksprotocol/go-sdk/commit/348dd947b1fd274bf0785a6c1d3a4bb068fd3179))
* keep SDK documentation focused ([dcdff17](https://github.com/agenthooksprotocol/go-sdk/commit/dcdff17e817fd32730f88756548170845150b5d8))
