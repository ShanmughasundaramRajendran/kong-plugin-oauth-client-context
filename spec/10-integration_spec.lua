local helpers = require "spec.helpers"
local cjson = require "cjson.safe"

describe("oauth-client-context plugin (10 integration, OIDC input)", function()
  local client

  setup(function()
    local bp = helpers.get_db_utils(nil, {
      "routes",
      "services",
      "plugins",
    }, { "oauth-client-context" })

    local service = bp.services:insert({
      name = "test-service",
      url = "http://httpbin.org/anything"
    })

    local rs_route = bp.routes:insert({
      service = service,
      paths = { "/test-rs" }
    })

    local es_route = bp.routes:insert({
      service = service,
      paths = { "/test-es" }
    })

    local rsa_file = io.open("/kong-plugin/spec/fixtures/private_key.pem", "r")
    assert(rsa_file, "RSA private key not found")
    local rsa_private_key = rsa_file:read("*all")
    rsa_file:close()

    local ec_file = io.open("/kong-plugin/spec/fixtures/ec_private_key.pem", "r")
    assert(ec_file, "EC private key not found")
    local ec_private_key = ec_file:read("*all")
    ec_file:close()

    bp.plugins:insert({
      name = "oauth-client-context",
      route = { id = rs_route.id },
      config = {
        signing_key_vault_reference = rsa_private_key,
        signing_key_secret_syntax_key = "private_key",
        issuer = "kong-gateway",
        algorithm = "RS256",
        header_name = "x-client-auth-ctx",
      }
    })

    bp.plugins:insert({
      name = "oauth-client-context",
      route = { id = es_route.id },
      config = {
        signing_key_vault_reference = ec_private_key,
        signing_key_secret_syntax_key = "private_key",
        issuer = "kong-gateway",
        algorithm = "ES256",
        header_name = "x-client-auth-ctx",
      }
    })

    assert(helpers.start_kong({
      plugins = "bundled,oauth-client-context",
    }))
  end)

  teardown(function()
    helpers.stop_kong()
  end)

  before_each(function()
    client = helpers.proxy_client()
  end)

  after_each(function()
    if client then
      client:close()
    end
  end)

  local function build_oidc_introspection_header(overrides)
    local payload = {
      client_id = "oidc-client-123",
      app_id = "oidc-app-456",
      grant_type = "client_credentials",
      oauth_resource_owner_id = "oidc-owner-789",
      consent_id = "oidc-consent-111",
      ssoid = "oidc-ssoid-222",
      scopes = "payments:read payments:write",
      ["x-apigw-origin-client-id"] = "oidc-origin-333",
      oauth_identity_type = "oidc-from-introspection",
      auth_identity_type = "auth-from-introspection",
      approved_operation_types = "query,mutation",
    }

    if type(overrides) == "table" then
      for key, value in pairs(overrides) do
        payload[key] = value
      end
    end

    return ngx.encode_base64(cjson.encode(payload))
  end

  local function base64url_decode(input)
    local base64 = input:gsub("-", "+"):gsub("_", "/")
    local padding = #base64 % 4
    if padding == 2 then
      base64 = base64 .. "=="
    elseif padding == 3 then
      base64 = base64 .. "="
    elseif padding ~= 0 then
      return nil
    end

    local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    base64 = base64:gsub("[^" .. alphabet .. "=]", "")

    local decoded = base64:gsub(".", function(char)
      if char == "=" then
        return ""
      end
      local value = alphabet:find(char, 1, true) - 1
      local bits = ""
      for i = 6, 1, -1 do
        bits = bits .. ((value % 2 ^ i - value % 2 ^ (i - 1) > 0) and "1" or "0")
      end
      return bits
    end)

    return decoded:gsub("%d%d%d?%d?%d?%d?%d?%d?", function(byte)
      if #byte ~= 8 then
        return ""
      end
      local value = 0
      for i = 1, 8 do
        if byte:sub(i, i) == "1" then
          value = value + 2 ^ (8 - i)
        end
      end
      return string.char(value)
    end)
  end

  local function decode_jwt_payload(token)
    local payload_segment = token:match("^[^.]+%.([^.]+)")
    assert.is_not_nil(payload_segment)
    local decoded_payload = base64url_decode(payload_segment)
    assert.is_not_nil(decoded_payload)
    return cjson.decode(decoded_payload)
  end

  it("injects token using OIDC introspection claims for RS256", function()
    local res = client:get("/test-rs", {
      headers = {
        ["X-Kong-Introspection-Response"] = build_oidc_introspection_header(),
      }
    })

    assert.response(res).has.status(200)
    local body = assert.response(res).has.jsonbody()
    local token = body.headers["X-Client-Auth-Ctx"]
    assert.is_not_nil(token)
    local payload = decode_jwt_payload(token)
    assert.are.equal("oidc-client-123", payload.client_id)
    assert.are.equal("oidc-app-456", payload.app_id)
    assert.are.equal("kong-gateway", payload.iss)
    assert.is_nil(payload.sub)
  end)

  it("injects token using OIDC introspection claims for ES256", function()
    local res = client:get("/test-es", {
      headers = {
        ["X-Kong-Introspection-Response"] = build_oidc_introspection_header(),
      }
    })

    assert.response(res).has.status(200)
    local body = assert.response(res).has.jsonbody()
    local payload = decode_jwt_payload(body.headers["X-Client-Auth-Ctx"])
    assert.are.equal("oidc-client-123", payload.client_id)
    assert.are.equal("kong-gateway", payload.iss)
    assert.is_nil(payload.sub)
  end)

  it("falls back to consumer claims when introspection header is missing", function()
    local res = client:get("/test-rs")
    assert.response(res).has.status(200)
    local body = assert.response(res).has.jsonbody()
    local payload = decode_jwt_payload(body.headers["X-Client-Auth-Ctx"])
    assert.is_nil(payload.client_id)
  end)

  it("falls back from malformed introspection header without crashing", function()
    local res = client:get("/test-rs", {
      headers = {
        ["X-Kong-Introspection-Response"] = "not-base64",
      }
    })

    assert.response(res).has.status(200)
    local body = assert.response(res).has.jsonbody()
    assert.is_not_nil(body.headers["X-Client-Auth-Ctx"])
  end)
end)
