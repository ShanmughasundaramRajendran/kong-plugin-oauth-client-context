local helpers = require "spec.helpers"
local cjson = require "cjson.safe"
describe("oauth-client-context plugin", function()

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
        key_id = "local-test-rs",
        private_key = rsa_private_key,
        subject = "rs-client",
        issuer = "kong-gateway",
        audience = "upstream-rs",
        algorithm = "RS256",
        header_name = "x-client-auth-ctx"
      }
    })

    bp.plugins:insert({
      name = "oauth-client-context",
      route = { id = es_route.id },
      config = {
        key_id = "local-test-es",
        private_key = ec_private_key,
        subject = "es-client",
        issuer = "kong-gateway",
        audience = "upstream-es",
        algorithm = "ES256",
        header_name = "x-client-auth-ctx"
      }
    })

    assert(helpers.start_kong({
      plugins = "bundled,oauth-client-context"
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

  local function assert_token_exists(path)
    local res = client:get(path)
    assert.response(res).has.status(200)

    local body = assert.response(res).has.jsonbody()
    local upstream_token = body.headers["X-Client-Auth-Ctx"]
    local response_token = res.headers["x-client-auth-ctx"] or res.headers["X-Client-Auth-Ctx"]

    assert.is_not_nil(upstream_token)
    assert.is_not_nil(response_token)
    assert.are.equal(upstream_token, response_token)
    return upstream_token
  end

  local function assert_jwt_format(token)
    local parts = {}
    for part in string.gmatch(token, "([^%.]+)") do
      table.insert(parts, part)
    end

    assert.are.equal(3, #parts)
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

  local function assert_jwt_alg(token, expected_alg)
    local header_segment = token:match("^([^.]+)")
    assert.is_not_nil(header_segment)

    local decoded_header = base64url_decode(header_segment)
    assert.is_not_nil(decoded_header)

    local header = cjson.decode(decoded_header)
    assert.is_not_nil(header)
    assert.are.equal(expected_alg, header.alg)
  end

  local function assert_jwt_claims(token, expected_sub, expected_iss, expected_aud)
    local payload_segment = token:match("^[^.]+%.([^.]+)")
    assert.is_not_nil(payload_segment)

    local decoded_payload = base64url_decode(payload_segment)
    assert.is_not_nil(decoded_payload)

    local payload = cjson.decode(decoded_payload)
    assert.is_not_nil(payload)
    assert.are.equal(expected_sub, payload.sub)
    assert.are.equal(expected_iss, payload.iss)
    assert.are.equal(expected_aud, payload.aud)
  end

  it("injects x-client-auth-ctx header to upstream for RS256", function()
    local token = assert_token_exists("/test-rs")
    assert_jwt_format(token)
    assert_jwt_alg(token, "RS256")
    assert_jwt_claims(token, "rs-client", "kong-gateway", "upstream-rs")
  end)

  it("injects x-client-auth-ctx header to upstream for ES256", function()
    local token = assert_token_exists("/test-es")
    assert_jwt_format(token)
    assert_jwt_alg(token, "ES256")
    assert_jwt_claims(token, "es-client", "kong-gateway", "upstream-es")
  end)

  it("produces valid JWT format for RS256", function()
    local token = assert_token_exists("/test-rs")
    assert_jwt_format(token)
    assert_jwt_alg(token, "RS256")
    assert_jwt_claims(token, "rs-client", "kong-gateway", "upstream-rs")
  end)

  it("produces valid JWT format for ES256", function()
    local token = assert_token_exists("/test-es")
    assert_jwt_format(token)
    assert_jwt_alg(token, "ES256")
    assert_jwt_claims(token, "es-client", "kong-gateway", "upstream-es")
  end)

end)
