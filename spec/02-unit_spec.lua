local cjson = require "cjson.safe"

describe("oauth-client-context handler (02 unit)", function()
  local original_kong = _G.kong
  local original_ngx = _G.ngx
  local original_lru = package.loaded["resty.lrucache"]
  local original_pkey = package.loaded["resty.openssl.pkey"]
  local original_handler = package.loaded["kong.plugins.oauth-client-context.handler"]

  local function b64_encode(input)
    local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local output = {}
    local bytes = { string.byte(input, 1, #input) }

    for i = 1, #bytes, 3 do
      local b1 = bytes[i] or 0
      local b2 = bytes[i + 1] or 0
      local b3 = bytes[i + 2] or 0
      local n = b1 * 65536 + b2 * 256 + b3

      local c1 = math.floor(n / 262144) % 64 + 1
      local c2 = math.floor(n / 4096) % 64 + 1
      local c3 = math.floor(n / 64) % 64 + 1
      local c4 = n % 64 + 1

      output[#output + 1] = alphabet:sub(c1, c1)
      output[#output + 1] = alphabet:sub(c2, c2)
      output[#output + 1] = (i + 1 <= #bytes) and alphabet:sub(c3, c3) or "="
      output[#output + 1] = (i + 2 <= #bytes) and alphabet:sub(c4, c4) or "="
    end

    return table.concat(output)
  end

  local function b64_decode(input)
    local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local clean = input:gsub("[^" .. alphabet .. "=]", "")
    local output = {}

    for i = 1, #clean, 4 do
      local c1 = clean:sub(i, i)
      local c2 = clean:sub(i + 1, i + 1)
      local c3 = clean:sub(i + 2, i + 2)
      local c4 = clean:sub(i + 3, i + 3)

      local n1 = (c1 == "=") and 0 or (alphabet:find(c1, 1, true) - 1)
      local n2 = (c2 == "=") and 0 or (alphabet:find(c2, 1, true) - 1)
      local n3 = (c3 == "=") and 0 or (alphabet:find(c3, 1, true) - 1)
      local n4 = (c4 == "=") and 0 or (alphabet:find(c4, 1, true) - 1)

      local n = n1 * 262144 + n2 * 4096 + n3 * 64 + n4
      local b1 = math.floor(n / 65536) % 256
      local b2 = math.floor(n / 256) % 256
      local b3 = n % 256

      output[#output + 1] = string.char(b1)
      if c3 ~= "=" then
        output[#output + 1] = string.char(b2)
      end
      if c4 ~= "=" then
        output[#output + 1] = string.char(b3)
      end
    end

    return table.concat(output)
  end

  local function base64url_decode(input)
    local base64 = input:gsub("-", "+"):gsub("_", "/")
    local remainder = #base64 % 4
    if remainder == 2 then
      base64 = base64 .. "=="
    elseif remainder == 3 then
      base64 = base64 .. "="
    elseif remainder ~= 0 then
      return nil
    end

    return b64_decode(base64)
  end

  local function decode_jwt(token)
    local header_segment = token:match("^([^.]+)%.")
    local payload_segment = token:match("^[^.]+%.([^.]+)")
    assert.is_not_nil(header_segment)
    assert.is_not_nil(payload_segment)
    local header = cjson.decode(base64url_decode(header_segment))
    local payload = cjson.decode(base64url_decode(payload_segment))
    return header, payload
  end

  local function build_oidc_introspection_payload(overrides)
    local payload = {
      client_id = "oidc-client-123",
      app_id = "oidc-app-456",
      oauth_identity_type = "oidc-oauth2",
      auth_identity_type = "oidc-auth",
    }

    if type(overrides) == "table" then
      for key, value in pairs(overrides) do
        payload[key] = value
      end
    end

    return b64_encode(cjson.encode(payload))
  end

  local function url_decode(input)
    return (input:gsub("%%(%x%x)", function(hex)
      return string.char(tonumber(hex, 16))
    end))
  end

  local function load_handler(opts)
    opts = opts or {}
    local state = {
      request_headers = opts.request_headers or {},
      service_headers = {},
      response_headers = {},
      response_exit = nil,
      last_sign = nil,
      last_pkey = nil,
      pkey_new_calls = 0,
    }

    package.loaded["kong.plugins.oauth-client-context.handler"] = nil

    package.loaded["resty.lrucache"] = {
      new = function()
        local store = {}
        return {
          get = function(_, key)
            return store[key]
          end,
          set = function(_, key, value)
            store[key] = value
            return true
          end,
        }
      end
    }

    package.loaded["resty.openssl.pkey"] = {
      new = function(private_key)
        if opts.pkey_new_error then
          return nil, opts.pkey_new_error
        end

        state.pkey_new_calls = state.pkey_new_calls + 1
        state.last_pkey = private_key
        return {
          PADDINGS = { RSA_PKCS1_PADDING = "rsa-padding" },
          sign = function(_, signing_input, digest, padding, sign_opts)
            state.last_sign = {
              signing_input = signing_input,
              digest = digest,
              padding = padding,
              sign_opts = sign_opts,
            }

            if opts.sign_error then
              return nil, opts.sign_error
            end

            return opts.signature or "signature-bytes"
          end
        }
      end
    }

    _G.ngx = {
      encode_base64 = b64_encode,
      decode_base64 = b64_decode,
      unescape_uri = url_decode,
      time = function()
        return opts.now or 1700000000
      end,
    }

    _G.kong = {
      request = {
        get_header = function(name)
          return state.request_headers[name]
        end,
        get_host = function()
          return opts.host or "unit-host"
        end,
      },
      client = {
        get_consumer = function()
          return opts.consumer
        end,
      },
      service = {
        request = {
          set_header = function(name, value)
            state.service_headers[name] = value
          end,
        },
      },
      response = {
        set_header = function(name, value)
          state.response_headers[name] = value
        end,
        exit = function(code, body)
          state.response_exit = { code = code, body = body }
          return state.response_exit
        end,
      },
      log = {
        err = function() end,
        debug = function() end,
      },
      vault = opts.vault,
    }

    local handler = require "kong.plugins.oauth-client-context.handler"
    return handler, state
  end

  local function default_conf(overrides)
    local conf = {
      propagate_client_auth_context = true,
      signing_private_key = "{vault://env/UNIT_PRIVATE_KEY}",
      issuer = "unit-issuer",
      signing_algorithm = "RS256",
      header_name = "x-client-auth-ctx",
      ttl = 60,
      additional_headers = {},
    }

    if type(overrides) == "table" then
      for key, value in pairs(overrides) do
        conf[key] = value
      end
    end
    return conf
  end

  after_each(function()
    _G.kong = original_kong
    _G.ngx = original_ngx
    package.loaded["resty.lrucache"] = original_lru
    package.loaded["resty.openssl.pkey"] = original_pkey
    package.loaded["kong.plugins.oauth-client-context.handler"] = original_handler
  end)

  it("short-circuits when propagate_client_auth_context is false", function()
    local handler, state = load_handler()
    handler:access(default_conf({ propagate_client_auth_context = false }))
    assert.is_nil(next(state.service_headers))
    assert.is_nil(state.response_exit)
  end)

  it("returns 500 when signing_private_key is missing", function()
    local handler, state = load_handler()
    local conf = default_conf()
    conf.signing_private_key = nil
    handler:access(conf)
    assert.are.equal(500, state.response_exit.code)
    assert.are.equal("Invalid plugin configuration", state.response_exit.body.message)
  end)

  it("returns 500 when private key parsing fails", function()
    local handler, state = load_handler({
      pkey_new_error = "bad key",
      vault = {
        get = function()
          return "resolved-private-key"
        end,
      },
    })
    handler:access(default_conf())
    assert.are.equal(500, state.response_exit.code)
    assert.are.equal("Invalid private key", state.response_exit.body.message)
  end)

  it("returns 500 when signing fails", function()
    local handler, state = load_handler({
      sign_error = "cannot sign",
      vault = {
        get = function()
          return "resolved-private-key"
        end,
      },
    })
    handler:access(default_conf())
    assert.are.equal(500, state.response_exit.code)
    assert.are.equal("JWT signing failed", state.response_exit.body.message)
  end)

  it("uses OIDC claims first, then consumer fallback, plus additional headers and config operation types", function()
    local handler, state = load_handler({
      request_headers = {
        ["X-Kong-Introspection-Response"] = build_oidc_introspection_payload({
          client_id = "oidc-client",
          grant_type = "client_credentials",
          approved_operation_types = "subscription",
        }),
        ["x-consumer-extra-claim"] = "include-me",
        ["x-consumer-replace-claim"] = "replace-me",
        ["x-custom-add"] = "custom-add-value",
        ["x-oauth-override"] = "override-from-additional-header",
      },
      consumer = {
        custom_id = "consumer-custom-id",
        tags = {
          "claim:app_id=consumer-app",
          "claim:approved_operation_types=query%2Cmutation",
          "claim:oauth_identity_type=consumer-oauth2",
        },
      },
      now = 1700000200,
      vault = {
        get = function(ref)
          if ref == "{vault://env/UNIT_PRIVATE_KEY}" then
            return "resolved-private-key"
          end
          if ref == "{vault://env/UNIT_KEY_ID}" then
            return "unit-kid-1"
          end
          assert.fail("unexpected vault reference: " .. tostring(ref))
        end,
      },
    })

    handler:access(default_conf({
      approved_operation_types = "query",
      signing_key_id = "{vault://env/UNIT_KEY_ID}",
      additional_headers = {
        { header_name = "x-custom-add", claim_name = "custom_add_claim" },
        { header_name = "x-oauth-override", claim_name = "oauth_identity_type" },
      },
    }))

    local header, payload = decode_jwt(state.service_headers["x-client-auth-ctx"])
    assert.are.equal("RS256", header.alg)
    assert.are.equal("unit-kid-1", header.kid)
    assert.are.equal("oidc-client", payload.client_id)
    assert.are.equal("oidc-app-456", payload.app_id)
    assert.are.equal("override-from-additional-header", payload.oauth_identity_type)
    assert.are.equal("include-me", payload.consumer_extra_claim)
    assert.are.equal("custom-add-value", payload.custom_add_claim)
    assert.are.equal("query", payload.approved_operation_types)
    assert.are.equal(1700000200, payload.iat)
    assert.are.equal(1700000260, payload.exp)
    assert.are.equal("unit-issuer", payload.iss)
    assert.is_nil(payload.sub)
    assert.is_nil(payload.aud)
  end)

  it("falls back to consumer claims when OIDC introspection payload is missing", function()
    local handler, state = load_handler({
      consumer = {
        custom_id = "consumer-custom-id",
        tags = {
          "claim:client_id=consumer-claim-client",
          "claim:app_id=consumer-claim-app",
        },
      },
      vault = {
        get = function()
          return "resolved-private-key"
        end,
      },
    })

    handler:access(default_conf())
    local _, payload = decode_jwt(state.service_headers["x-client-auth-ctx"])
    assert.are.equal("consumer-claim-client", payload.client_id)
    assert.are.equal("consumer-claim-app", payload.app_id)
  end)

  it("falls back to consumer claims when OIDC introspection payload is malformed", function()
    local handler, state = load_handler({
      request_headers = {
        ["X-Kong-Introspection-Response"] = "not-base64",
      },
      consumer = {
        tags = {
          "claim:client_id=consumer-fallback-client",
        },
      },
      vault = {
        get = function()
          return "resolved-private-key"
        end,
      },
    })

    handler:access(default_conf())
    local _, payload = decode_jwt(state.service_headers["x-client-auth-ctx"])
    assert.are.equal("consumer-fallback-client", payload.client_id)
  end)

  it("uses ES256 signing options with vault key source", function()
    local handler, state = load_handler({
      request_headers = {
        ["X-Kong-Introspection-Response"] = build_oidc_introspection_payload({ app_id = "oidc-es-app" }),
      },
      vault = {
        get = function()
          return "resolved-private-key"
        end,
      },
    })

    handler:access(default_conf({
      signing_algorithm = "ES256",
    }))

    local _, payload = decode_jwt(state.service_headers["x-client-auth-ctx"])
    assert.are.equal("oidc-es-app", payload.app_id)
    assert.are.equal(1700000060, payload.exp)
    assert.are.equal("SHA256", state.last_sign.digest)
    assert.is_nil(state.last_sign.padding)
    assert.are.equal(true, state.last_sign.sign_opts.ecdsa_use_raw)
  end)
end)
