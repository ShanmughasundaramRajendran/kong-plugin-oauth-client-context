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
  { claim = "client_id", headers = { "client_id" } },
  { claim = "app_id", headers = { "app_id" } },
  { claim = "grant_type", headers = { "grant_type" } },
  { claim = "oauth_resource_owner_id", headers = { "oauth_resource_owner_id" } },
  { claim = "consent_id", headers = { "consent_id" } },
  { claim = "ssoid", headers = { "ssoid" } },
  { claim = "scopes", headers = { "scopes" } },
  { claim = "x-apigw-origin-client-id", headers = { "x-apigw-origin-client-id", "x_apigw_origin_client_id" } },
  { claim = "auth_identity_type", headers = { "auth_identity_type", "oauth_identity_type" } },
  { claim = "oauth_identity_type", headers = { "oauth_identity_type", "auth_identity_type" } },
  { claim = "approved_operation_types", headers = { "approved_operation_types" } },
}

local function trim(s)
  if type(s) ~= "string" then
    return s
  end

  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
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
  local consumer = kong.client.get_consumer()
  local consumer_claims = parse_consumer_claims(consumer)

  for _, mapping in ipairs(CLAIM_HEADERS) do
    for _, header_name in ipairs(mapping.headers) do
      local value = kong.request.get_header(header_name)
      if value ~= nil and value ~= "" then
        payload[mapping.claim] = value
        break
      end
    end

    if payload[mapping.claim] == nil then
      local consumer_value = consumer_claims[mapping.claim]
      if consumer_value ~= nil and consumer_value ~= "" then
        payload[mapping.claim] = consumer_value
      end
    end
  end

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
