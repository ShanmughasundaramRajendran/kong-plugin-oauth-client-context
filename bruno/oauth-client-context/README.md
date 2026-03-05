# Bruno Collection Notes

This collection is aligned with current `oauth-client-context` handler behavior.

## Requests Included
- Core route checks:
  - `01-rs256-smoke.bru`
  - `02-es256-smoke.bru`
  - `03-billing-rs-c2.bru`
  - `04-billing-es-c2.bru`
  - `05-orders-rs-c3.bru`
  - `06-orders-es-c3.bru`
- Edge-case checks:
  - `07-rs256-lowercase-bearer.bru` (accepts lowercase `bearer`)
  - `08-rs256-raw-token.bru` (accepts raw token without `Bearer`)
  - `09-rs256-empty-claims-fallback.bru` (empty incoming claims fall back to consumer tags)
- Admin check:
  - `03-admin-enabled-plugins.bru`

## Header Behavior
- `x-consumer-extra-claim` is copied to JWT as `consumer_extra_claim`.
- `x-consumer-replace-claim` overrides JWT `oauth_identity_type`.
- `x-consumer-ignore-claim` is intentionally ignored.
- When multi-value headers occur, plugin logic takes the first value.

## Expected JWT Shape
- Header includes: `tv`, `typ`, `alg`, `kid`
- Payload includes dynamic claim resolution:
  1. incoming JWT claims
  2. consumer `claim:*` tags fallback
  3. empty incoming values treated as missing

## Environment
Use `environments/local.bru`:
- `incoming_jwt_token` for regular claims propagation checks
- `incoming_jwt_token_empty_claims` for fallback validation
