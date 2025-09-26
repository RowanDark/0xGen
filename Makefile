# Use bash for targets that rely on modern shell features.
SHELL := /bin/bash

# The source .proto files.
PROTO_FILES := $(shell find proto/glyph -name *.proto)

# Output directory for Python stubs.
PYTHON_PLUGIN_RUNTIME_DIR := examples/glyph-passive-headers/glyph_plugin_runtime

# Output directory for Go stubs.
GO_STUBS_DIR := proto/gen/go

BIN ?= ./bin
GLYPHCTL := $(BIN)/glyphctl

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GLYPHCTL_LDFLAGS ?= -s -w -X main.version=$(VERSION)

$(GLYPHCTL):
        @mkdir -p $(BIN)
        @go build -ldflags "$(GLYPHCTL_LDFLAGS)" -o $(GLYPHCTL) ./cmd/glyphctl

# Development defaults for running the Go services.
GLYPH_ADDR ?= :50051
GLYPH_AUTH_TOKEN ?= dev-token

.PHONY: test
test:
	go test ./...

.PHONY: lint
lint:
	go vet ./...

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
plugins-skeleton: $(GLYPHCTL)
	@set -euo pipefail; \
	plugins="galdr-proxy cartographer excavator raider osint-well seer scribe ranker grapher cryptographer"; \
		for plugin in $$plugins; do \
			manifest="plugins/$${plugin}/manifest.json"; \
			if [ ! -f "$$manifest" ]; then \
				echo "missing manifest: $$manifest"; \
				exit 1; \
			fi; \
			$(GLYPHCTL) --manifest-validate "$$manifest" >/dev/null; \
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
        @go run -ldflags "$(GLYPHCTL_LDFLAGS)" ./cmd/glyphctl report --input out/findings.jsonl --out out/report.md
        @echo "Report written to out/report.md"





.PHONY: crawl-demo
crawl-demo:
	@npm --prefix plugins/excavator install --no-audit --no-fund >/dev/null
	@node plugins/excavator/crawl.js --target=https://example.com --depth=1

.PHONY: demo
demo:
	@set -euo pipefail; \
		out_dir="out"; \
		rm -rf "$$out_dir"; \
		mkdir -p "$$out_dir"; \
		npm --prefix plugins/excavator install --no-audit --no-fund >/dev/null; \
		seer_pid=0; \
		export GLYPH_OUT="$$out_dir"; \
		export GLYPH_AUTH_TOKEN="quickstart-token"; \
		go build -o "$$out_dir/glyphd" ./cmd/glyphd; \
		go build -o "$$out_dir/seer" ./plugins/seer; \
		GLYPH_ENABLE_PROXY=1 "$$out_dir/glyphd" --token "$$GLYPH_AUTH_TOKEN" --proxy-addr 127.0.0.1:8080 --proxy-history "$$out_dir/proxy-history.jsonl" --proxy-rules examples/quickstart/galdr-rules.json >"$$out_dir/glyphd.log" 2>&1 & \
		glyphd_pid=$$!; \
		trap 'if [ "$$seer_pid" -ne 0 ]; then kill "$$seer_pid" >/dev/null 2>&1 || true; fi; kill "$$glyphd_pid" >/dev/null 2>&1 || true' EXIT; \
		sleep 2; \
		"$$out_dir/seer" --server 127.0.0.1:50051 --token "$$GLYPH_AUTH_TOKEN" >"$$out_dir/seer.log" 2>&1 & \
		seer_pid=$$!; \
		sleep 2; \
		EXCAVATOR_PROXY="http://127.0.0.1:8080" node plugins/excavator/crawl.js --target=http://example.com --depth=0 >"$$out_dir/excavator.json"; \
		sleep 2; \
		kill "$$seer_pid" >/dev/null 2>&1 || true; \
		kill "$$glyphd_pid" >/dev/null 2>&1 || true; \
		wait "$$seer_pid" 2>/dev/null || true; \
		wait "$$glyphd_pid" 2>/dev/null || true; \
		if [ ! -s "$$out_dir/findings.jsonl" ]; then go run ./cmd/quickstartseed --html examples/quickstart/demo-response.html --out "$$out_dir/findings.jsonl" --target http://example.com >/dev/null; fi; \
                go run -ldflags "$(GLYPHCTL_LDFLAGS)" ./cmd/glyphctl rank --input "$$out_dir/findings.jsonl" --out "$$out_dir/ranked.jsonl" >/dev/null; \
                go run -ldflags "$(GLYPHCTL_LDFLAGS)" ./cmd/glyphctl report --input "$$out_dir/findings.jsonl" --out "$$out_dir/report.html" --format html >/dev/null; \
                report_path="$$(cd "$$out_dir" && pwd)/report.html"; \
                echo "Quickstart report available at $$report_path"

.PHONY: verify
verify: build
	@golangci-lint run ./...
	@go test ./... -v
	@$(MAKE) validate-manifests

.PHONY: run
run:
	go run ./cmd/glyphd --addr $(GLYPH_ADDR) --token $(GLYPH_AUTH_TOKEN)

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
	@touch $(PYTHON_PLUGIN_RUNTIME_DIR)/glyph/__init__.py
	@echo "Fixing Python imports in generated stubs..."
	@find $(PYTHON_PLUGIN_RUNTIME_DIR)/glyph -name "*_pb2*.py" -exec sed -i -E 's/^from glyph import/from . import/' {} \;

# Generates Go stubs.
.PHONY: proto-go
proto-go:
	@echo "--- Generating Go stubs ---"
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@mkdir -p $(GO_STUBS_DIR)
	@protoc -I proto \
       --go_out=$(GO_STUBS_DIR) --go_opt=module=github.com/RowanDark/Glyph \
       --go-grpc_out=$(GO_STUBS_DIR) --go-grpc_opt=module=github.com/RowanDark/Glyph \
	  $(PROTO_FILES)
	@echo "Go stubs generated in $(GO_STUBS_DIR)"

# Smoke test for the Python plugin.
.PHONY: test-plugin
test-plugin:
	cd examples/glyph-passive-headers && python -m glyph_passive_headers -h || true

# Runs the end-to-end test.
.PHONY: e2e
e2e: proto
	@echo "--- Ensuring cmd directory exists ---"
	@mkdir -p cmd/glyphd
	@echo "--- Building glyphd server ---"
	@go build -o glyphd ./cmd/glyphd
	@echo "--- Running E2E test ---"
	@rm -f glyphd.log plugin.log
	@export GLYPH_AUTH_TOKEN="supersecrettoken" && ./glyphd > glyphd.log 2>&1 &
	@sleep 2
	@python -m glyph_passive_headers > plugin.log 2>&1 &
	@echo "Server and plugin started. Waiting for interaction..."
	@sleep 4
	@echo "--- Stopping processes ---"
	@pkill -f glyphd || true
	@pkill -f glyph_passive_headers || true
	@sleep 1
	@echo
	@echo "--- Server Log (glyphd.log) ---"
	@cat glyphd.log
	@echo
	@echo "--- Plugin Log (plugin.log) ---"
	@cat plugin.log
	@rm -f glyphd glyphd.log plugin.log
