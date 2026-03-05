local schema = require "kong.plugins.oauth-client-context.schema"

describe("oauth-client-context schema (01)", function()
  local function get_config_field(name)
    for _, field in ipairs(schema.fields) do
      if field.config and field.config.fields then
        for _, config_field in ipairs(field.config.fields) do
          if config_field[name] then
            return config_field[name]
          end
        end
      end
    end
  end

  it("declares plugin name and config field block", function()
    assert.are.equal("oauth-client-context", schema.name)
    assert.is_not_nil(get_config_field("key_id"))
    assert.is_not_nil(get_config_field("private_key"))
  end)

  it("requires key_id and private_key", function()
    local key_id = get_config_field("key_id")
    local private_key = get_config_field("private_key")
    assert.are.equal(true, key_id.required)
    assert.are.equal(true, private_key.required)
  end)

  it("enforces supported algorithms and default", function()
    local algorithm = get_config_field("algorithm")
    assert.is_not_nil(algorithm)
    assert.are.equal("RS256", algorithm.default)
    assert.same({ "RS256", "ES256" }, algorithm.one_of)
  end)

  it("defines ttl as bounded integer", function()
    local ttl = get_config_field("ttl")
    assert.are.equal("integer", ttl.type)
    assert.same({ 1, 86400 }, ttl.between)
  end)

  it("sets expected defaults for header and incoming auth source", function()
    local header_name = get_config_field("header_name")
    local incoming_jwt_header = get_config_field("incoming_jwt_header")
    assert.are.equal("x-client-auth-ctx", header_name.default)
    assert.are.equal("authorization", incoming_jwt_header.default)
  end)

  it("keeps ttl boundaries and default", function()
    local ttl = get_config_field("ttl")
    assert.is_not_nil(ttl)
    assert.are.equal(60, ttl.default)
    assert.same({ 1, 86400 }, ttl.between)
  end)
end)
