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
          { enabled = { type = "boolean", default = true } },
          -- Kong vault reference for signing key (example: {vault://env/LOCAL_TEST_RS_PRIVATE_KEY}).
          { signing_key_vault_reference = { type = "string", required = true } },
          -- Optional syntax key used when the resolved vault secret is table/json.
          { signing_key_secret_syntax_key = { type = "string", required = false, default = "private_key" } },
          -- Additional request headers to embed as JWT claims.
          -- "add": set only when target claim is empty.
          { additional_headers = {
              type = "array",
              required = false,
              default = {},
              elements = {
                type = "record",
                fields = {
                  { header_name = { type = "string", required = true } },
                  { claim_name = { type = "string", required = true } },
                  { mode = { type = "string", required = false, default = "add", one_of = { "add" } } },
                },
              },
            }
          },
          { issuer = { type = "string", required = false } },
          { algorithm = { 
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
