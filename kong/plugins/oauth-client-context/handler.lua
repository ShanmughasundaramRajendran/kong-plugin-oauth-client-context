local cjson = require "cjson.safe"
local lrucache = require "resty.lrucache"
local pkey = require "resty.openssl.pkey"

local parsed_key_cache = lrucache.new(100)
local KEY_CACHE_TTL_SECONDS = 600

local OAuthClientContext = {
  PRIORITY = 900,
  VERSION = "2.0.0",
}

local CLAIM_HEADERS = {
  "client_id",
  "app_id",
  "grant_type",
  "oauth_resource_owner_id",
  "consent_id",
  "ssoid",
  "scopes",
  "x-apigw-origin-client-id",
  "auth_identity_type",
  "oauth_identity_type",
  "approved_operation_types",
}

local INCLUDE_HEADER = "x-consumer-extra-claim"
local REPLACE_HEADER = "x-consumer-replace-claim"
local IGNORE_HEADER = "x-consumer-ignore-claim"
local INCLUDE_CLAIM = "consumer_extra_claim"
local REPLACE_TARGET_CLAIM = "oauth_identity_type"

local function trim(s)
  if type(s) ~= "string" then
    return s
  end

  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
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

  return ngx.decode_base64(base64)
end

local function get_incoming_jwt_claims(conf)
  local header_name = conf.incoming_jwt_header or "authorization"
  local auth_header = kong.request.get_header(header_name)
  if not auth_header or auth_header == "" then
    return {}
  end

  local token = auth_header
  local bearer = auth_header:match("^[Bb]earer%s+(.+)$")
  if bearer then
    token = bearer
  end

  local payload_segment = token:match("^[^.]+%.([^.]+)")
  if not payload_segment then
    return {}
  end

  local decoded_payload = base64url_decode(payload_segment)
  if not decoded_payload then
    return {}
  end

  local claims = cjson.decode(decoded_payload)
  if type(claims) ~= "table" then
    return {}
  end

  return claims
end

local function resolve_env_vault_reference(ref)
  local secret_name = ref:match("^%{vault://env/([^}]+)%}$")
  if not secret_name then
    return nil
  end

  return os.getenv(secret_name)
end

local function resolve_private_key_value(private_key_ref)
  local ref = trim(private_key_ref)
  if not ref or ref == "" then
    return nil, "private key is empty"
  end

  if not ref:match("^%{vault://") then
    return ref, nil
  end

  if kong.vault and type(kong.vault.get) == "function" then
    local ok, secret_or_err, maybe_err = pcall(kong.vault.get, ref)
    if ok and type(secret_or_err) == "string" and secret_or_err ~= "" then
      return secret_or_err, nil
    end
    if ok and maybe_err then
      kong.log.err("[oauth-client-context] kong.vault.get failed for reference ", ref, ": ", maybe_err)
    end
    if not ok then
      kong.log.err("[oauth-client-context] kong.vault.get error for reference ", ref, ": ", secret_or_err)
    end
  end

  local env_secret = resolve_env_vault_reference(ref)
  if env_secret and env_secret ~= "" then
    return env_secret, nil
  end

  return nil, "failed to resolve vault reference " .. ref
end

local function get_signing_key(conf)
  local cache_key = conf.algorithm .. ":" .. conf.key_id
  local signing_key = parsed_key_cache:get(cache_key)
  if signing_key then
    return signing_key
  end

  -- `private_key` may be a Kong vault reference; Kong resolves it before plugin access.
  local private_key, err = resolve_private_key_value(conf.private_key)
  if not private_key then
    return nil, err
  end

  signing_key, err = pkey.new(private_key)
  if not signing_key then
    return nil, err
  end

  parsed_key_cache:set(cache_key, signing_key, KEY_CACHE_TTL_SECONDS)
  return signing_key
end

local function parse_consumer_claims(consumer)
  local claims = {}
  if not consumer or type(consumer.tags) ~= "table" then
    return claims
  end

  for _, tag in ipairs(consumer.tags) do
    if type(tag) == "string" then
      local key, value = tag:match("^claim:([^=]+)=(.+)$")
      if key and value and value ~= "" then
        claims[key] = ngx.unescape_uri(value)
      end
    end
  end

  return claims
end

local function base64url_encode(input)
  local encoded = ngx.encode_base64(input)
  encoded = encoded:gsub("+", "-"):gsub("/", "_"):gsub("=+$", "")
  return encoded
end

local function build_token(signing_key, conf, payload)
  local header = {
    tv = 2,
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

  local incoming_claims = get_incoming_jwt_claims(conf)
  local consumer = kong.client.get_consumer()
  local consumer_claims = parse_consumer_claims(consumer)

  for _, claim in ipairs(CLAIM_HEADERS) do
    local value = incoming_claims[claim]
    if value ~= nil and value ~= "" then
      payload[claim] = value
    elseif consumer_claims[claim] ~= nil and consumer_claims[claim] ~= "" then
      payload[claim] = consumer_claims[claim]
    end
  end

  local header_1_value = kong.request.get_header(INCLUDE_HEADER)
  if header_1_value ~= nil and header_1_value ~= "" then
    payload[INCLUDE_CLAIM] = header_1_value
  end

  local header_2_value = kong.request.get_header(REPLACE_HEADER)
  if header_2_value ~= nil and header_2_value ~= "" then
    payload[REPLACE_TARGET_CLAIM] = header_2_value
  end

  -- Header 3 is intentionally ignored by design.
  kong.request.get_header(IGNORE_HEADER)

  if conf.ttl then
    payload.exp = ngx.time() + conf.ttl
  end

  if consumer and not payload.client_id then
    payload.client_id = consumer_claims.client_id or consumer.custom_id or consumer.username or consumer.id
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

  local signing_key, err = get_signing_key(conf)
  if not signing_key then
    kong.log.err("[oauth-client-context] invalid private key: ", err)
    return kong.response.exit(500, { message = "Invalid private key" })
  end

  local payload = build_payload(conf)

  local token
  token, err = build_token(signing_key, conf, payload)

  if not token then
    kong.log.err("[oauth-client-context] signing failed: ", err)
    return kong.response.exit(500, { message = "JWT signing failed" })
  end

  kong.service.request.set_header(conf.header_name, token)
  kong.response.set_header(conf.header_name, token)

end

return OAuthClientContext
