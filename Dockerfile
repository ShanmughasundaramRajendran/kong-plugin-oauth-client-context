# ---------- Dockerfile ----------
FROM kong:latest

USER root

# Enable custom plugin
ENV KONG_PLUGINS=bundled,oauth-client-context

# Keep Lua path default (we mount plugin t
