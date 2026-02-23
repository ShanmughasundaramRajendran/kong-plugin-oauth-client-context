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
- Pongo integration tests validate both algorithm paths.

## Configuration
- `key_id` (required): JWT `kid` header value.
- `private_key` (required): PEM private key matching `algorithm`, or Kong Vault reference.
- `incoming_jwt_header` (optional): header containing incoming JWT (default `authorization`).
- `subject` (optional): JWT `sub` claim. Defaults to consumer `client_id` when available.
- `issuer` (optional): JWT `iss` claim. Defaults to incoming request host.
- `audience` (optional): JWT `aud` claim. Defaults to incoming request host.
- `algorithm` (optional): `RS256` or `ES256` (default `RS256`).
- `header_name` (optional): defaults to `x-client-auth-ctx`.
- `ttl` (optional): defaults to `60`, valid range `1..86400`.

## Signing Key Resolution
- The plugin resolves signing key using `key_id` and `algorithm`.
- `private_key` can use Kong Vault syntax (example: `{vault://env/LOCAL_TEST_RS_PRIVATE_KEY}`).
- Kong resolves the vault reference before plugin execution.
- Parsed signing keys are cached in-plugin by `algorithm:key_id` for 10 minutes (`600` seconds).
- Generated JWT header includes static `tv: 2`.

## Claims Added To JWT
For both `RS256` and `ES256`, the plugin includes these attributes in JWT claims. Source priority is:
1. Incoming JWT token claims (decoded from `Authorization: Bearer <token>`)
2. Authenticated consumer tags (`claim:<name>=<value>`) as fallback when incoming token claim is absent

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

## Pongo Test Workflow
```bash
make pongo-up
make pongo-test
make pongo-down
```

## Mocha Functional Suite
Functional Mocha tests are available at:
- `test/functional/mocha/oauth_client_context/oauth_ctx_test.js`
- Includes signature validation checks for both `RS256` and `ES256` generated JWTs.

Run locally (with Kong already running):
```bash
make npm-install
make test-mocha
```

Environment overrides (optional):
- `BASE_URL` (default `http://localhost:8000`)
- `APIKEY_C1`, `APIKEY_C2`, `APIKEY_C3`
- `INCOMING_JWT`
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
Pass criteria: `4 successes / 0 failures / 0 errors / 0 pending`.

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
- All route plugin configs use Kong Vault `env` references for signing keys by `key_id`.
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
- Import folder: `bruno/oauth-client-context`
- Environment file: `bruno/oauth-client-context/environments/local.bru`
- Collection name: `oauth-client-context-v5`
- Included requests:
  - `RS256 C1 V5` (`GET {{base_url}}/test-rs`, `apikey_c1`)
  - `ES256 C1 V5` (`GET {{base_url}}/test-es`, `apikey_c1`)
  - `Billing RS256 C2 V5` (`GET {{base_url}}/billing/rs`, `apikey_c2`)
  - `Billing ES256 C2 V5` (`GET {{base_url}}/billing/es`, `apikey_c2`)
  - `Orders RS256 C3 V5` (`GET {{base_url}}/orders/rs`, `apikey_c3`)
  - `Orders ES256 C3 V5` (`GET {{base_url}}/orders/es`, `apikey_c3`)
  - `Admin Enabled Plugins` (`GET {{admin_url}}/plugins/enabled`)
- All route requests send only `apikey`; JWT claims are read dynamically from the matched consumer tags.
