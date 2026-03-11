local typedefs = require "kong.db.schema.typedefs"

return {
  name = "oauth-client-context",
  fields = {
    -- Plugin applies at service/route/global scope, not consumer scope.
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          -- Backward-compatible toggle name from legacy schema.
          { propagate_client_auth_context = { type = "boolean", default = false } },
          { log_level = {
              type = "string",
              required = false,
              default = "error",
              one_of = { "stderr", "emerg", "alert", "critical", "error", "warn", "notice", "info", "debug" },
            }
          },
          { error_format = { type = "string", required = false, default = "default" } },
          -- GraphQL operation types to include in outgoing JWT payload.
          -- This value is configuration-driven and not sourced from introspection claims.
          { approved_operation_types = {
              type = "string",
              required = false,
              one_of = { "query", "mutation", "subscription" },
            }
          },
          -- Vault reference or direct private key value used to sign JWT.
          -- Example: {vault://aws/cfo/....../SIGNING_PRIVATE_KEY}
          { signing_private_key = {
              type = "string",
              referenceable = true,
              required = true,
              description = "Private key reference/value for JWT signing (RS256/ES256).",
            }
          },
          -- Optional JWT kid value.
          -- Example: {vault://aws/cfo/....../KEY_ID}
          { signing_key_id = {
              type = "string",
              referenceable = true,
              required = false,
            }
          },
          -- Additional request headers to embed as JWT claims.
          { additional_headers = {
              type = "array",
              required = false,
              default = {},
              elements = {
                type = "record",
                fields = {
                  { header_name = { type = "string", required = true } },
                  { claim_name = { type = "string", required = true } },
                },
              },
            }
          },
          { issuer = { type = "string", required = false } },
          { signing_algorithm = { 
              type = "string", 
              default = "RS256",
              one_of = { "RS256", "ES256" }
            } 
          },
          -- Header that receives the generated signed client context JWT.
          { header_name = { 
              type = "string", 
              default = "x-client-auth-ctx" 
            } 
          },
          -- Token lifetime in seconds.
          { ttl = { type = "integer", default = 60, between = { 1, 86400 } } }
        }
      }
    }
  }
}
