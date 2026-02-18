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
- `private_key` (required): PEM private key matching `algorithm`.
- `subject` (optional): JWT `sub` claim. Defaults to consumer `client_id` when available.
- `issuer` (optional): JWT `iss` claim. Defaults to incoming request host.
- `audience` (optional): JWT `aud` claim. Defaults to incoming request host.
- `algorithm` (optional): `RS256` or `ES256` (default `RS256`).
- `header_name` (optional): defaults to `x-client-auth-ctx`.
- `ttl` (optional): defaults to `60`, valid range `1..86400`.

## Local Dev (Docker Compose)
```bash
make build
make up
make test        # runs /test-rs and /test-es smoke checks
make down
```

## Pongo Test Workflow
```bash
make pongo-up
make pongo-test
make pongo-down
```

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
`config/kong.yml` includes two route-level plugin examples:
- `/test-rs` using `RS256`
- `/test-es` using `ES256`

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
- Included requests:
  - `RS256 Smoke` (`GET {{base_url}}/test-rs`)
  - `ES256 Smoke` (`GET {{base_url}}/test-es`)
  - `Admin Enabled Plugins` (`GET {{admin_url}}/plugins/enabled`)
