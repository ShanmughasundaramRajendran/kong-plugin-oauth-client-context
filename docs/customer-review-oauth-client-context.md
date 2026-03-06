
This document explains improvements, best practices followed, and operational impact.

## Executive Summary
The current plugin implementation modernizes the legacy model by:
- Migrating from Janus-specific APIs to Kong native core + OpenResty libraries
- Simplifying and hardening schema/configuration
- Using vault-reference based key resolution through Kong vault interfaces
- Supporting both `RS256` and `ES256` with explicit, validated configuration
- Using OIDC introspection claim data as primary JWT payload source
- Reducing downstream token exposure by sending context header to upstream only

Overall impact: lower operational complexity, clearer ownership boundaries, safer runtime behavior, and better portability across Kong deployments.

## Comparison Highlights

### 1) Platform API Migration (Janus -> Kong Native)
- Legacy:
  - Relied on `janus.*` modules (`janus.client`, `janus.request`, `janus.keystore`, `janus.endpoint`)
  - Tight coupling to Janus runtime and keystore abstractions
- Current:
  - Uses Kong/OpenResty native APIs:
    - `kong.request.*`, `kong.client.*`, `kong.service.request.set_header`
    - `kong.vault.get` for secret resolution
    - `resty.openssl.pkey`, `cjson.safe`, `resty.lrucache`
- Best practice:
  - Prefer platform-native APIs for maintainability, compatibility, and upgrade safety
- Impact:
  - Easier deployment across Kong OSS/Konnect data planes with fewer proprietary runtime assumptions

### 2) Schema Modernization and Simplification
- Legacy:
  - Nested `propagate_client_auth_context_config`, `key_lookup`, `secret_id`, `secret_syntax_key`, format toggles
  - Extra toggle layers (`enabled` + nested enabled semantics)
- Current:
  - Clean Kong schema with explicit plugin config:
    - `propagate_client_auth_context`
    - `private_key` (referenceable)
    - `algorithm`, `header_name`, `ttl`, `approved_operation_types`, `add_headers`, `additional_headers`
  - Removes legacy nested config model from runtime path
- Best practice:
  - Minimize nested config complexity; keep security-critical inputs explicit and required
- Impact:
  - Faster onboarding, lower misconfiguration risk, easier UI/API configuration audits

### 3) Secret Management Approach
- Legacy:
  - Keystore-driven retrieval logic with lockbox formatting controls and secret-syntax coupling
- Current:
  - `private_key` supports Kong vault references directly (referenceable config field)
  - Runtime resolves vault references with `kong.vault.get`
  - Handles common secret shapes (raw string, JSON/table with `private_key`)
- Best practice:
  - Keep secret retrieval delegated to gateway vault subsystem; avoid custom secret-store coupling in plugin logic
- Impact:
  - Better separation of concerns, easier secrets rotation strategy, consistent behavior with Kong vault providers

### 4) Signing and Crypto Behavior
- Legacy:
  - Supported `RS256` and `ES256`; crypto path built around Janus keystore key objects
- Current:
  - Supports `RS256` and `ES256` using `resty.openssl.pkey`
  - ES256 uses raw-signature mode (`ecdsa_use_raw = true`) for JWS compatibility
  - Parsed signing keys are cached in LRU cache for performance
- Best practice:
  - Use battle-tested crypto libraries, avoid per-request key parsing overhead
- Impact:
  - Improved throughput and predictable JWT interoperability

### 5) Payload Source and Claim Governance
- Legacy:
  - Claims mostly from Janus client context + request headers
  - `approved_operation_types` injected from access policy config
- Current:
  - OIDC introspection payload (from `X-Kong-Introspection-Response`) is primary source
  - Controlled fallbacks from request headers/consumer metadata
  - `approved_operation_types` remains configuration-driven (not introspection-driven)
- Best practice:
  - Define deterministic claim precedence and keep policy claims configuration-owned
- Impact:
  - More consistent upstream context JWT payloads and cleaner policy enforcement model

### 6) Header Propagation Security
- Legacy:
  - Set signed header for upstream request path
- Current:
  - Sends signed context to upstream only
  - Explicitly avoids mirroring signed JWT into downstream response headers
- Best practice:
  - Do not reflect sensitive signed artifacts to external clients unless explicitly required
- Impact:
  - Reduced exposure surface and lower risk of token leakage

### 7) Failure Handling and Observability
- Legacy:
  - Errors often logged and flow returned without strong standardized response behavior
- Current:
  - Validates essential config before signing path
  - Returns explicit error responses on invalid configuration/signing failures
  - Retains structured logging for diagnosis
- Best practice:
  - Fail fast on invalid security config; make runtime failures explicit and diagnosable
- Impact:
  - Faster incident triage and safer behavior under misconfiguration

## Key Improvements
- Migrated to Kong native runtime primitives and removed Janus-only dependencies
- Simplified schema and removed legacy nested key-lookup config complexity
- Standardized vault-based secret resolution through Kong vault interface
- Preserved RS256/ES256 support with explicit algorithm control
- Ensured `approved_operation_types` remains config-driven and deterministic
- Used OIDC introspection as the authoritative claim source for upstream token context
- Eliminated downstream response header exposure while preserving upstream propagation
- Added/kept automated tests to validate behavior and reduce regression risk

## Recommendations Going Forward
- Production:
  - Use vault references for `private_key` (AWS secrets manager via Kong vault provider)
  - Keep `propagate_client_auth_context` explicit per route/service scope
  - Keep `approved_operation_types` managed by config/policy, not caller input
- Operations:
  - Maintain key rotation runbook aligned to vault secret lifecycle
  - Monitor plugin error-rate spikes (`Invalid plugin configuration`, signing failures)
- Governance:
  - Treat additional claim mappings as controlled config changes with peer review
  - Avoid expanding dynamic claims without explicit data ownership and validation

