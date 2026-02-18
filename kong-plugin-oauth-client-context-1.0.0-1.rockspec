package = "kong-plugin-oauth-client-context"
version = "1.0.0-1"

source = { url = "." }

dependencies = {
  "lua >= 5.1",
  "lua-resty-openssl"
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.oauth-client-context.handler"] =
      "kong/plugins/oauth-client-context/handler.lua",
    ["kong.plugins.oauth-client-context.schema"] =
      "kong/plugins/oauth-client-context/schema.lua",
    ["kong.plugins.oauth-client-context.init"] =
      "kong/plugins/oauth-client-context/init.lua"
  }
}
