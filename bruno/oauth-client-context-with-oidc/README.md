# Bruno Collection Notes (OIDC)

Collection name: `oauth-client-context-with OIDC`

This collection validates OIDC introspection-header-driven claim sourcing.

## Behavior Validated
- Claims are sourced from `X-Kong-Introspection-Response` (base64 JSON).
- JWT Authorization header is not used for claim extraction.
- Missing/malformed/empty introspection claim values fall back to consumer `claim:*` tags.
- Include/replace request headers still apply:
  - `x-consumer-extra-claim` -> `consumer_extra_claim`
  - `x-consumer-replace-claim` -> overrides `oauth_identity_type`
  - `x-consumer-ignore-claim` -> ignored

## Environment Variables
- `oidc_introspection_response_b64`
- `oidc_introspection_response_empty_claims_b64`
- `oidc_introspection_response_malformed_b64`
