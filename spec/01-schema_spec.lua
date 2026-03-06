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
    assert.is_not_nil(get_config_field("signing_key_vault_reference"))
  end)

  it("requires signing_key_vault_reference", function()
    local signing_key_vault_reference = get_config_field("signing_key_vault_reference")
    assert.are.equal(true, signing_key_vault_reference.required)
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
    local signing_key_secret_syntax_key = get_config_field("signing_key_secret_syntax_key")
    local additional_headers = get_config_field("additional_headers")
    assert.are.equal("x-client-auth-ctx", header_name.default)
    assert.are.equal("private_key", signing_key_secret_syntax_key.default)
    assert.are.equal("array", additional_headers.type)
  end)

  it("keeps ttl boundaries and default", function()
    local ttl = get_config_field("ttl")
    assert.is_not_nil(ttl)
    assert.are.equal(60, ttl.default)
    assert.same({ 1, 86400 }, ttl.between)
  end)
end)
