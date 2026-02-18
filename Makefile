# ============================================================
# Kong OAuth Client Context - Makefile
# ============================================================

APP_NAME              := kong-oauth-client-context
COMPOSE               := docker-compose
DOCKER                := docker
PONGO                 := pongo
KONG_ADMIN_URL        := http://localhost:8001
KONG_MANAGER_URL      := http://localhost:8002

.DEFAULT_GOAL := help

# ============================================================
# Utility
# ============================================================

## help: Show available commands
help:
	@echo ""
	@echo "Available targets:"
	@echo "------------------------------------------------------------"
	@awk 'BEGIN {FS = ": "} /^## / {sub(/^## /, "", $$0); printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo "------------------------------------------------------------"
	@echo ""

# ============================================================
# Docker Lifecycle
# ============================================================

## build: Build Docker image
build:
	@echo "Building Docker image..."
	$(COMPOSE) build

## up: Start services in detached mode
up:
	@echo "Starting Kong..."
	$(COMPOSE) up -d

## down: Stop services
down:
	@echo "Stopping Kong..."
	$(COMPOSE) down

## restart: Restart services
restart:
	@echo "Restarting Kong..."
	$(COMPOSE) restart

## rebuild: Full clean rebuild (no cache)
rebuild:
	@echo "Rebuilding from scratch..."
	$(COMPOSE) down -v
	$(COMPOSE) build --no-cache
	$(COMPOSE) up -d

## logs: Follow logs
logs:
	$(COMPOSE) logs -f

# ============================================================
# Health / Status
# ============================================================

## health: Check Kong health
health:
	@echo "Checking Kong health..."
	@curl -s $(KONG_ADMIN_URL)/status | jq . || true

## enabled-plugins: List enabled plugins
enabled-plugins:
	@echo "Fetching enabled plugins..."
	@curl -s $(KONG_ADMIN_URL)/plugins/enabled | jq . || true

## config: Dump loaded declarative config
config:
	@curl -s $(KONG_ADMIN_URL)/config | jq . || true

# ============================================================
# Development Utilities
# ============================================================

## shell: Open shell inside Kong container
shell:
	$(COMPOSE) exec kong sh

## lint: Lint Lua plugin (requires luacheck locally)
lint:
	@echo "Running luacheck..."
	@luacheck kong || echo "luacheck not installed"

## validate-config: Validate kong.yml
validate-config:
	$(COMPOSE) exec kong kong config parse /etc/kong/kong.yml

# ============================================================
# Testing
# ============================================================

## test: Run both proxy smoke tests (RS256 + ES256)
test: test-rs256 test-es256

## test-rs256: Test RS256 route and inspect injected header
test-rs256:
	@curl -s http://localhost:8000/test-rs | jq -re '.headers["X-Client-Auth-Ctx"] | select(type=="string" and test("^[^.]+\\.[^.]+\\.[^.]+$$"))' >/dev/null
	@echo "RS256 smoke test passed"

## test-es256: Test ES256 route and inspect injected header
test-es256:
	@curl -s http://localhost:8000/test-es | jq -re '.headers["X-Client-Auth-Ctx"] | select(type=="string" and test("^[^.]+\\.[^.]+\\.[^.]+$$"))' >/dev/null
	@echo "ES256 smoke test passed"

## test-proxy: Backward-compatible alias to RS256 route
test-proxy:
	@curl -i http://localhost:8000/test-rs

## test-admin: Test admin API
test-admin:
	@curl -i $(KONG_ADMIN_URL)

## pongo-up: Start Pongo environment
pongo-up:
	$(PONGO) up

## pongo-test: Run plugin tests inside Pongo
pongo-test:
	$(PONGO) run

## pongo-shell: Open shell in Pongo test container
pongo-shell:
	$(PONGO) shell

## pongo-down: Stop Pongo environment
pongo-down:
	$(PONGO) down

## manager: Open Kong Manager URL
manager:
	@echo "Kong Manager: $(KONG_MANAGER_URL)"

# ============================================================
# Cleanup
# ============================================================

## clean: Remove containers and volumes
clean:
	$(COMPOSE) down -v
	@echo "Cleaned Docker volumes."

## prune: Docker system prune
prune:
	$(DOCKER) system prune -f
