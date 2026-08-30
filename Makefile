# PVM (Pico VM) — developer targets. See deploy/ for production packaging.
GO ?= go
BIN := agentpvm
UMLCTL := bin/umlctl
# CI-safe integration suites (no kernel/root required; keep in sync with
# .github/workflows/ci.yml and AGENTS.md). 28/30 need artifacts this local
# checkout lacks (28: the real pnpm-generated webui; 30: a working
# fake-kernel re-exec) — CI builds those, so run them there.
CI_SAFE_SUITES := 05 06 07 08 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 29 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 48 49 50 51 52

.PHONY: all build webui test test-safe vet lint install deploy-check clean

all: build

build: $(BIN) $(UMLCTL)

$(BIN):
	$(GO) build -o $(BIN) ./cmd/agentpvm

$(UMLCTL):
	$(GO) build -o $(UMLCTL) ./cmd/umlctl

webui:
	cd webui && pnpm install --frozen-lockfile && pnpm exec nuxt generate

test:
	$(GO) test -v ./...

# Runs the CI-safe shell suites against a freshly built binary.
test-safe: build
	set -e; for n in $(CI_SAFE_SUITES); do \
		s=$(ls tests/$${n}_*.sh 2>/dev/null || true); \
		[ -n "$$s" ] && AGENTPVM_BIN=./$(BIN) UMLCTL_BIN=./$(UMLCTL) bash $$s; \
	done

vet:
	$(GO) vet ./...

lint: vet
	command -v clang-tidy >/dev/null && clang-tidy bpf/egress.c -- -I/usr/include -I/usr/include/bpf || true
	cd sdk/node && node --test "test/*.test.js"
	node webui/test/i18n_parity.mjs

install: build
	sudo deploy/install.sh

# Offline validation of deploy artifacts (no docker needed).
deploy-check:
	bash -n deploy/install.sh
	python3 -c "import yaml; yaml.safe_load(open('deploy/docker-compose.yml')); yaml.safe_load(open('api/openapi.yaml')); print('deploy-check OK')"

clean:
	rm -f $(BIN) $(UMLCTL)
	$(GO) clean -testcache
