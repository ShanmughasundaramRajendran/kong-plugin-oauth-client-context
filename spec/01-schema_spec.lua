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
    assert.is_not_nil(get_config_field("private_key"))
  end)

  it("requires private_key as signing source (legacy key refs still compatible)", function()
    local private_key = get_config_field("private_key")
    assert.are.equal(true, private_key.required)
    assert.are.equal(true, private_key.referenceable)
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

  it("sets expected defaults for header and key extraction options", function()
    local header_name = get_config_field("header_name")
    local additional_headers = get_config_field("additional_headers")
    local approved_operation_types = get_config_field("approved_operation_types")
    local propagate_client_auth_context = get_config_field("propagate_client_auth_context")
    local add_headers = get_config_field("add_headers")
    local private_key = get_config_field("private_key")
    assert.are.equal("x-client-auth-ctx", header_name.default)
    assert.are.equal("array", additional_headers.type)
    assert.are.equal("string", approved_operation_types.type)
    assert.are.equal("map", add_headers.type)
    assert.are.equal(false, propagate_client_auth_context.default)
    assert.are.equal("string", private_key.type)
  end)

  it("keeps ttl boundaries and default", function()
    local ttl = get_config_field("ttl")
    assert.is_not_nil(ttl)
    assert.are.equal(60, ttl.default)
    assert.same({ 1, 86400 }, ttl.between)
  end)
end)
