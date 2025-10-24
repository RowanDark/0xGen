# Use bash for targets that rely on modern shell features.
SHELL := /bin/bash

# The source .proto files.
PROTO_FILES := $(shell find proto/oxg -name *.proto)

# Output directory for Python stubs.
PYTHON_PLUGIN_RUNTIME_DIR := examples/oxg-passive-headers/oxg_plugin_runtime

# Output directory for Go stubs.
GO_STUBS_DIR := proto/gen/go

BIN ?= ./bin
OXGENCTL := $(BIN)/0xgenctl

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
OXGENCTL_LDFLAGS ?= -s -w -X main.version=$(VERSION)

$(OXGENCTL):
	@mkdir -p $(BIN)
	@go build -ldflags "$(OXGENCTL_LDFLAGS)" -o $(OXGENCTL) ./cmd/0xgenctl

# Development defaults for running the Go services.
0XGEN_ADDR ?= :50051
0XGEN_AUTH_TOKEN ?= dev-token

.PHONY: test
test:
	go test ./...

.PHONY: lint
lint:
	go vet ./...

.PHONY: updater:build-manifests
updater:build-manifests:
	@0XGEN_UPDATER_SIGNING_KEY=$${0XGEN_UPDATER_SIGNING_KEY:-} go run ./hack/updater/build_manifests.go

.PHONY: build
build:
	go build ./...

.PHONY: validate-manifests
validate-manifests:
	@./hack/validate_manifests.sh

.PHONY: new-plugin
new-plugin:
	@hack/new_plugin.sh "$(name)"

.PHONY: plugins-skeleton
plugins-skeleton: $(OXGENCTL)
	@set -euo pipefail; \
	plugins="galdr-proxy cartographer excavator raider osint-well seer scribe ranker grapher cryptographer"; \
		for plugin in $$plugins; do \
			manifest="plugins/$${plugin}/manifest.json"; \
			if [ ! -f "$$manifest" ]; then \
				echo "missing manifest: $$manifest"; \
				exit 1; \
			fi; \
	$(OXGENCTL) --manifest-validate "$$manifest" >/dev/null; \
			done
	@echo "Running excavator crawl sanity check..."
	@npm --prefix plugins/excavator install --no-audit --no-fund >/dev/null
	@tmp_file=$$(mktemp); \
		node plugins/excavator/crawl.js https://example.com > "$$tmp_file"; \
		node -e "const fs=require('fs'); JSON.parse(fs.readFileSync(process.argv[1],'utf8')); JSON.parse(fs.readFileSync('plugins/excavator/sample_output.json','utf8'));" "$$tmp_file"; \
		rm -f "$$tmp_file"

.PHONY: demo-report
demo-report:
	@mkdir -p out
	@cp examples/findings-sample.jsonl out/findings.jsonl
	@go run -ldflags "$(OXGENCTL_LDFLAGS)" ./cmd/0xgenctl report --input out/findings.jsonl --out out/report.md
	@echo "Report written to out/report.md"





.PHONY: crawl-demo
crawl-demo:
	@npm --prefix plugins/excavator install --no-audit --no-fund >/dev/null
	@node plugins/excavator/crawl.js --target=https://example.com --depth=1

.PHONY: demo
demo:
@go run -ldflags "$(OXGENCTL_LDFLAGS)" ./cmd/0xgenctl demo --out out/demo

.PHONY: verify
verify: build
	@golangci-lint run ./...
	@go test ./... -v
	@$(MAKE) validate-manifests

.PHONY: run
run:
	go run ./cmd/0xgend --addr $(0XGEN_ADDR) --token $(0XGEN_AUTH_TOKEN)

# Default target.
.PHONY: all
all: proto

# Main protobuf generation target.
.PHONY: proto
proto: proto-py proto-go

# Generates Python stubs.
.PHONY: proto-py
proto-py:
	@echo "--- Generating Python stubs ---"
	@python -m pip install --upgrade pip grpcio grpcio-tools
	@rm -rf $(PYTHON_PLUGIN_RUNTIME_DIR)
	@mkdir -p $(PYTHON_PLUGIN_RUNTIME_DIR)
	@python -m grpc_tools.protoc -I proto \
	  --python_out=$(PYTHON_PLUGIN_RUNTIME_DIR) \
	  --grpc_python_out=$(PYTHON_PLUGIN_RUNTIME_DIR) \
	  $(PROTO_FILES)
	@touch $(PYTHON_PLUGIN_RUNTIME_DIR)/__init__.py
	@touch $(PYTHON_PLUGIN_RUNTIME_DIR)/oxg/__init__.py
	@echo "Fixing Python imports in generated stubs..."
	@find $(PYTHON_PLUGIN_RUNTIME_DIR)/oxg -name "*_pb2*.py" -exec sed -i -E 's/^from oxg import/from . import/' {} \;

# Generates Go stubs.
.PHONY: proto-go
proto-go:
	@echo "--- Generating Go stubs ---"
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@mkdir -p $(GO_STUBS_DIR)
	@protoc -I proto \
       --go_out=$(GO_STUBS_DIR) --go_opt=module=github.com/RowanDark/0xgen \
       --go-grpc_out=$(GO_STUBS_DIR) --go-grpc_opt=module=github.com/RowanDark/0xgen \
	  $(PROTO_FILES)
	@echo "Go stubs generated in $(GO_STUBS_DIR)"

# Smoke test for the Python plugin.
.PHONY: test-plugin
test-plugin:
	cd examples/oxg-passive-headers && python -m oxg_passive_headers -h || true

# Runs the end-to-end test.
.PHONY: e2e
e2e: proto
	@echo "--- Ensuring cmd directory exists ---"
	@mkdir -p cmd/0xgend
	@echo "--- Building 0xgend server ---"
	@go build -o 0xgend ./cmd/0xgend
	@echo "--- Running E2E test ---"
	@rm -f 0xgend.log plugin.log
	@export 0XGEN_AUTH_TOKEN="supersecrettoken" && ./0xgend > 0xgend.log 2>&1 &
	@sleep 2
@python -m oxg_passive_headers > plugin.log 2>&1 &
	@echo "Server and plugin started. Waiting for interaction..."
	@sleep 4
	@echo "--- Stopping processes ---"
	@pkill -f 0xgend || true
@pkill -f oxg_passive_headers || true
	@sleep 1
	@echo
	@echo "--- Server Log (0xgend.log) ---"
	@cat 0xgend.log
	@echo
	@echo "--- Plugin Log (plugin.log) ---"
	@cat plugin.log
	@rm -f 0xgend 0xgend.log plugin.log

# Runs the real-world scenario regression tests.
.PHONY: e2e-scenarios
e2e-scenarios:
	@echo "--- Running E2E scenario suite ---"
	@go test ./internal/e2e -run TestPassiveHeaderRealWorldScenarios -count=1 -timeout 5m
