local typedefs = require "kong.db.schema.typedefs"

return {
  name = "oauth-client-context",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          { enabled = { type = "boolean", default = true } },
          { key_id = { type = "string", required = true } },
          { private_key = { type = "string", required = true } },
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
          { header_name = { 
              type = "string", 
              default = "x-client-auth-ctx" 
            } 
          },
          { ttl = { type = "integer", default = 60, between = { 1, 86400 } } }
        }
      }
    }
  }
}
