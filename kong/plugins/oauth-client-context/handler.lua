local cjson = require "cjson.safe"
local jwt_parser = require "kong.plugins.jwt.jwt_parser"
local lrucache = require "resty.lrucache"
local pkey = require "resty.openssl.pkey"

local parsed_key_cache = lrucache.new(100)
local KEY_CACHE_TTL_SECONDS = 600
local CJSON_NULL = cjson.null

local ngx_decode_base64 = ngx.decode_base64
local ngx_encode_base64 = ngx.encode_base64
local ngx_unescape_uri = ngx.unescape_uri
local ngx_time = ngx.time

local OAuthClientContext = {
  PRIORITY = 900,
  VERSION = "2.0.0",
}

-- Claims that can be propagated from the incoming token (or consumer tags fallback)
-- into the generated client context JWT.
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
local INCLUDE_CLAIM = "consumer_extra_claim"
local REPLACE_TARGET_CLAIM = "oauth_identity_type"

local ALGORITHMS = {
  RS256 = "RS256",
  ES256 = "ES256",
}

local function is_non_empty(value)
  return value ~= nil and value ~= "" and value ~= CJSON_NULL
end

local function get_first_header_value(value)
  if type(value) == "table" then
    return value[1]
  end

  return value
end

local function payload_set_value(payload, key, value)
  value = get_first_header_value(value)
  if is_non_empty(value) then
    payload[key] = value
  end
end

local function extract_bearer_token(raw_header)
  local header = get_first_header_value(raw_header)
  if not is_non_empty(header) then
    return nil
  end

  local bearer = header:match("^[Bb]earer%s+(.+)$")
  if bearer and bearer ~= "" then
    return bearer
  end

  return header
end

local function decode_claims_from_token_payload(token)
  local payload_segment = token:match("^[^.]+%.([^.]+)")
  if not payload_segment then
    return {}
  end

  local base64 = payload_segment:gsub("-", "+"):gsub("_", "/")
  local remainder = #base64 % 4
  if remainder == 2 then
    base64 = base64 .. "=="
  elseif remainder == 3 then
    base64 = base64 .. "="
  elseif remainder ~= 0 then
    return {}
  end

  local decoded_payload = ngx_decode_base64(base64)
  if not decoded_payload then
    return {}
  end

  local claims = cjson.decode(decoded_payload)
  if type(claims) ~= "table" then
    return {}
  end

  return claims
end

local function get_incoming_jwt_claims(conf)
  local header_name = conf.incoming_jwt_header or "authorization"
  local token = extract_bearer_token(kong.request.get_header(header_name))
  if not token then
    return {}
  end

  local jwt, err = jwt_parser:new(token)
  if not jwt then
    kong.log.debug("[oauth-client-context] unable to parse incoming JWT from header ", header_name, ": ", err)
    return decode_claims_from_token_payload(token)
  end

  if type(jwt.claims) == "table" then
    return jwt.claims
  end

  return decode_claims_from_token_payload(token)
end

local function resolve_private_key_value(private_key_ref)
  local ref = private_key_ref
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

  return nil, "failed to resolve vault reference " .. ref
end

local function get_signing_key(conf)
  local cache_key = conf.algorithm .. ":" .. conf.key_id .. ":" .. conf.private_key
  local signing_key = parsed_key_cache:get(cache_key)
  if signing_key then
    return signing_key
  end

  -- `private_key` can be a raw PEM value or a Kong Vault reference.
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

  -- Expected tag shape: claim:<name>=<url-escaped-value>
  for _, tag in ipairs(consumer.tags) do
    if type(tag) == "string" then
      local key, value = tag:match("^claim:([^=]+)=(.+)$")
      if key and is_non_empty(value) then
        claims[key] = ngx_unescape_uri(value)
      end
    end
  end

  return claims
end

local function base64url_encode(input)
  local encoded = ngx_encode_base64(input)
  encoded = encoded:gsub("+", "-"):gsub("/", "_"):gsub("=+$", "")
  return encoded
end

local function build_token(signing_key, conf, payload)
  if not signing_key or type(signing_key.sign) ~= "function" then
    return nil, "invalid signing key object"
  end

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
  if conf.algorithm == ALGORITHMS.ES256 then
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
  local now = ngx_time()
  local payload = {
    iat = now,
  }

  local incoming_claims = get_incoming_jwt_claims(conf)
  local consumer = kong.client.get_consumer()
  local consumer_claims = parse_consumer_claims(consumer)

  -- Claim precedence:
  -- 1) Incoming JWT claims
  -- 2) Consumer tag claims (fallback)
  for _, claim in ipairs(CLAIM_HEADERS) do
    local value = incoming_claims[claim]
    if is_non_empty(value) then
      payload_set_value(payload, claim, value)
    else
      payload_set_value(payload, claim, consumer_claims[claim])
    end
  end

  payload_set_value(payload, INCLUDE_CLAIM, kong.request.get_header(INCLUDE_HEADER))

  payload_set_value(payload, REPLACE_TARGET_CLAIM, kong.request.get_header(REPLACE_HEADER))

  if conf.ttl then
    payload.exp = now + conf.ttl
  end

  if consumer and not is_non_empty(payload.client_id) then
    payload_set_value(payload, "client_id", consumer_claims.client_id or consumer.custom_id or consumer.username or consumer.id)
  end

  payload_set_value(payload, "sub", conf.subject or payload.client_id)
  payload_set_value(payload, "iss", conf.issuer or kong.request.get_host())
  payload_set_value(payload, "aud", conf.audience or kong.request.get_host())

  return payload
end

-- rewrite phase:
-- Runs early in the request lifecycle (before routing and access control).
-- This plugin does not mutate request state at this stage.
function OAuthClientContext:rewrite(_conf)
  return
end

-- access phase:
-- Runs after routing/auth and before proxying upstream.
-- The plugin builds and signs the client context JWT and injects it as a header.
function OAuthClientContext:access(conf)

  if type(conf) ~= "table" then
    kong.log.err("[oauth-client-context] invalid plugin config: expected table")
    return kong.response.exit(500, { message = "Invalid plugin configuration" })
  end

  if conf.enabled == false then
    return
  end

  if not is_non_empty(conf.header_name) then
    kong.log.err("[oauth-client-context] invalid header_name")
    return kong.response.exit(500, { message = "Invalid plugin configuration" })
  end

  if conf.algorithm ~= ALGORITHMS.RS256 and conf.algorithm ~= ALGORITHMS.ES256 then
    kong.log.err("[oauth-client-context] unsupported algorithm: ", tostring(conf.algorithm))
    return kong.response.exit(500, { message = "Invalid plugin configuration" })
  end

  if not is_non_empty(conf.key_id) or not is_non_empty(conf.private_key) then
    kong.log.err("[oauth-client-context] key_id/private_key must be configured")
    return kong.response.exit(500, { message = "Invalid plugin configuration" })
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

-- log phase:
-- Runs after the upstream response is sent to the client.
-- This plugin currently has no post-response logging side effects.
function OAuthClientContext:log(_conf)
  return
end

return OAuthClientContext
