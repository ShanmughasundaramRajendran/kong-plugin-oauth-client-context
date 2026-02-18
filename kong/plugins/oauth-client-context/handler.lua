local cjson = require "cjson.safe"
local lrucache = require "resty.lrucache"
local pkey = require "resty.openssl.pkey"

local cache = lrucache.new(100)

local OAuthClientContext = {
  PRIORITY = 900,
  VERSION = "2.0.0",
}

local function base64url_encode(input)
  local encoded = ngx.encode_base64(input)
  encoded = encoded:gsub("+", "-"):gsub("/", "_"):gsub("=+$", "")
  return encoded
end

local function build_token(signing_key, conf, payload)
  local header = {
    typ = "JWT",
    alg = conf.algorithm,
    kid = conf.key_id,
  }

  local header_json = cjson.encode(header)
  if not header_json then
    return nil, "failed to encode JWT header"
  end

  local payload_json = cjson.encode(payload)
  if not payload_json then
    return nil, "failed to encode JWT payload"
  end

  local signing_input = base64url_encode(header_json) .. "." .. base64url_encode(payload_json)

  local signature
  local err
  if conf.algorithm == "ES256" then
    signature, err = signing_key:sign(signing_input, "SHA256", nil, { ecdsa_use_raw = true })
  else
    local padding = signing_key.PADDINGS and signing_key.PADDINGS.RSA_PKCS1_PADDING or nil
    signature, err = signing_key:sign(signing_input, "SHA256", padding)
  end

  if not signature then
    return nil, err
  end

  return signing_input .. "." .. base64url_encode(signature)
end

local function build_payload(conf)
  local payload = {
    iat = ngx.time()
  }

  if conf.ttl then
    payload.exp = ngx.time() + conf.ttl
  end

  local consumer = kong.client.get_consumer()
  if consumer then
    payload.client_id = consumer.id
  end

  payload.sub = conf.subject or payload.client_id
  payload.iss = conf.issuer or kong.request.get_host()
  payload.aud = conf.audience or kong.request.get_host()

  return payload
end

function OAuthClientContext:access(conf)

  if conf.enabled == false then
    return
  end

  local signing_key = cache:get(conf.private_key)
  if not signing_key then
    local err
    signing_key, err = pkey.new(conf.private_key)
    if not signing_key then
      kong.log.err("[oauth-client-context] invalid private key: ", err)
      return kong.response.exit(500, { message = "Invalid private key" })
    end
    cache:set(conf.private_key, signing_key)
  end

  local payload = build_payload(conf)

  local token, err = build_token(signing_key, conf, payload)

  if not token then
    kong.log.err("[oauth-client-context] signing failed: ", err)
    return kong.response.exit(500, { message = "JWT signing failed" })
  end

  kong.service.request.set_header(conf.header_name, token)
  kong.response.set_header(conf.header_name, token)

end

return OAuthClientContext
