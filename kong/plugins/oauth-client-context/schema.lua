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
          -- JWT header `kid` value used by upstream verifiers.
          { key_id = { type = "string", required = true } },
          -- PEM private key or Kong Vault reference (for example: {vault://...}).
          { private_key = { type = "string", required = true } },
          -- Header that carries the incoming JWT used as claim source.
          { incoming_jwt_header = { type = "string", required = false, default = "authorization" } },
          { subject = { type = "string", required = false } },
          { issuer = { type = "string", required = false } },
          { audience = { type = "string", required = false } },
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
