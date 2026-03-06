# Kong OAuth Client Context Plugin

This plugin injects a signed JWT into `x-client-auth-ctx` for upstream services.

## Customer Requirement
This POC supports both signing algorithms required by the customer:
- `RS256`
- `ES256`

## Production Readiness Notes
- Algorithm is schema-validated (`RS256` or `ES256` only).
- `ttl` is bounded (`1..86400`) to avoid invalid or excessively long-lived tokens.
- Signing errors fail safely with HTTP 500 and an explicit message.
- Runtime fail-fast guards return HTTP 500 for invalid plugin config (`Invalid plugin configuration`).
- Claim sourcing is OIDC introspection-header driven (base64 JSON), with consumer-tag fallback.
- Vault references are resolved via Kong's native vault API (`kong.vault.get`).
- Pongo test suites cover schema, unit, and integration behavior.

## Configuration
- `enabled` (optional): enable/disable plugin execution (default `true`).
- `signing_key_vault_reference` (required): signing key source (vault reference recommended, example: `{vault://env/LOCAL_TEST_RS_PRIVATE_KEY}`).
- `signing_key_secret_syntax_key` (optional): key name to extract when vault returns JSON/table (default `private_key`).
- `additional_headers` (optional): array of request-header to JWT-claim mappings:
  - `header_name`
  - `claim_name`
  - `mode` (`add` only, default `add`)
- `issuer` (optional): JWT `iss` claim. Defaults to incoming request host.
- `algorithm` (optional): `RS256` or `ES256` (default `RS256`).
- `header_name` (optional): defaults to `x-client-auth-ctx`.
- `ttl` (optional): defaults to `60`, valid range `1..86400`.

## Signing Key Resolution
- The plugin resolves signing key using `algorithm` + `signing_key_vault_reference`.
- `signing_key_vault_reference` may point to Kong vault sources (recommended) or direct PEM values.
- `signing_key_secret_syntax_key` is used when secret is JSON/table.
- Kong resolves the vault reference before plugin execution.
- Parsed signing keys are cached in-plugin by `algorithm:key_reference` for 10 minutes (`600` seconds).
- Generated JWT header includes static `tv: 2`.
- Local compose provides dedicated vault env keys per algorithm:
  - `OAUTH_CTX_RS256_SIGNING_KEY`
  - `OAUTH_CTX_ES256_SIGNING_KEY`

## Claims Added To JWT
For both `RS256` and `ES256`, the plugin includes these attributes in JWT claims. Source priority is:
1. OIDC introspection header claims (`X-Kong-Introspection-Response`, base64 JSON)
2. Authenticated consumer tags (`claim:<name>=<value>`) as fallback when introspection claim is absent
3. Empty claim values are treated as missing and also fall back to the next source

Supported claims:
- `client_id`
- `app_id`
- `grant_type`
- `oauth_resource_owner_id`
- `consent_id`
- `ssoid`
- `scopes`
- `x-apigw-origin-client-id`
- `auth_identity_type`
- `oauth_identity_type`
- `approved_operation_types`

Note: Kong tags do not allow literal commas, so use URL-encoded values in tags when needed (example: `query%2Cmutation`).

## Local Dev (Docker Compose)
```bash
make build
make up
make test        # runs all smoke checks + dynamic-claim assertions
make down
```

## Functional Header Scenarios
The plugin supports three explicit consumer request headers:
- `x-consumer-extra-claim`: included as `consumer_extra_claim` in generated JWT.
- `x-consumer-replace-claim`: replaces outgoing JWT `oauth_identity_type`.
- `x-consumer-ignore-claim`: intentionally ignored and not added to generated JWT.
- If a request header has multiple values, the first value is used.
- OIDC introspection header value is expected to be base64(JSON) and has precedence over all other claim sources.
- `additional_headers` can be used to embed any future headers as claims without code changes.

## Pongo Test Workflow
```bash
make pongo-up
make pongo-test
make pongo-down
```

Current Pongo spec layout:
- `spec/01-schema_spec.lua`
- `spec/02-unit_spec.lua`
- `spec/10-integration_spec.lua`

## Mocha Functional Suite
Functional Mocha tests are available at:
- `test/functional/mocha/oauth_client_context/oauth_ctx_test.js`
- Includes signature validation checks for both `RS256` and `ES256` generated JWTs.
- Includes edge coverage for duplicate header values and empty-claim fallback to consumer tags.

Run locally (with Kong already running):
```bash
make npm-install
make test-mocha
```

Environment overrides (optional):
- `BASE_URL` (default `http://localhost:8000`)
- `APIKEY_C1`, `APIKEY_C2`, `APIKEY_C3`
- `OIDC_INTROSPECTION_RESPONSE_B64`
- `HEADER_INCLUDE_VALUE`, `HEADER_REPLACE_VALUE`, `HEADER_IGNORE_VALUE`

## Customer Acceptance Checklist
1. Validate plugin schema and config are loadable.
```bash
make up
make validate-config
```
Pass criteria: no schema/config parse errors.

2. Verify RS256 runtime behavior.
```bash
make test-rs256
```
Pass criteria: command exits `0` and prints `RS256 smoke test passed`.

3. Verify ES256 runtime behavior.
```bash
make test-es256
```
Pass criteria: command exits `0` and prints `ES256 smoke test passed`.

4. Run full integration suite in Pongo.
```bash
make pongo-up
make pongo-test
make pongo-down
```
Pass criteria: all schema, unit, and integration specs pass with `0 failures`.

5. Confirm both customer-required algorithms are configured in declarative config.
```bash
rg -n "algorithm: RS256|algorithm: ES256" config/kong.yml
```
Pass criteria: both lines are present in `config/kong.yml`.

## Declarative Demo Config
`config/kong.yml` includes 3 consumers and 3 services with 6 routes:
- Consumers:
  - `demo-consumer-app` (`demo-consumer-apikey`)
  - `demo-consumer-app-2` (`demo-consumer-apikey-2`)
  - `demo-consumer-app-3` (`demo-consumer-apikey-3`)
- Routes:
  - `/test-rs` (`RS256`) and `/test-es` (`ES256`)
  - `/billing/rs` (`RS256`) and `/billing/es` (`ES256`)
  - `/orders/rs` (`RS256`) and `/orders/es` (`ES256`)
- All routes have `key-auth` enabled (`apikey` header).
- Claims are resolved dynamically per authenticated consumer from that consumer's `claim:*` tags.
- All route plugin configs use Kong Vault `env` references for signing keys.
- Docker compose enables Kong Vault provider with `KONG_VAULTS=env`.

## Mac Terminal Runbook (Consolidated Commands)
```bash
# 1) Go to project
cd /Users/shanmughasundaramrajendran/kong-plugin-oauth-client-context

# 2) Stop anything old (safe cleanup)
make down || true
make pongo-down || true

# 3) Build and start Kong stack
make build
make up

# 4) Validate declarative config loaded format
make validate-config

# 5) Validate runtime smoke tests (both algorithms)
make test-rs256
make test-es256
make test

# 6) Run full integration tests in Pongo
make pongo-up
make pongo-test

# 7) Stop Pongo after tests
make pongo-down

# 8) Stop Kong stack when done
make down
```

## Bruno Collection
- Import folder: `bruno/oauth-client-context-with-oidc`
- Environment file: `bruno/oauth-client-context-with-oidc/environments/local.bru`
- Collection name: `oauth-client-context-with OIDC`
- Included requests:
  - `RS256 C1 OIDC` (`GET {{base_url}}/test-rs`, `apikey_c1`)
  - `ES256 C1 OIDC` (`GET {{base_url}}/test-es`, `apikey_c1`)
  - `Billing RS256 C2 OIDC` (`GET {{base_url}}/billing/rs`, `apikey_c2`)
  - `Billing ES256 C2 OIDC` (`GET {{base_url}}/billing/es`, `apikey_c2`)
  - `Orders RS256 C3 OIDC` (`GET {{base_url}}/orders/rs`, `apikey_c3`)
  - `Orders ES256 C3 OIDC` (`GET {{base_url}}/orders/es`, `apikey_c3`)
  - `RS256 Empty OIDC Claims Fallback` (`GET {{base_url}}/test-rs`)
  - `RS256 Malformed OIDC Fallback` (`GET {{base_url}}/test-rs`)
  - `Admin Enabled Plugins` (`GET {{admin_url}}/plugins/enabled`)
- Route requests use `apikey` + `X-Kong-Introspection-Response` by default.
- `x-consumer-extra-claim` and `x-consumer-replace-claim` are optional test headers.
- `x-consumer-ignore-claim` is included to verify it is ignored by plugin logic.
