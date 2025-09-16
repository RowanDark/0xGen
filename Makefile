# The source .proto files.
PROTO_FILES := $(shell find proto/glyph -name *.proto)

# Output directory for Python stubs.
PYTHON_PLUGIN_RUNTIME_DIR := examples/glyph-passive-headers/glyph_plugin_runtime

# Output directory for Go stubs.
GO_STUBS_DIR := proto/gen/go

# Development defaults for running the Go services.
GLYPH_ADDR ?= :50051
GLYPH_AUTH_TOKEN ?= dev-token

.PHONY: test
test:
	go test ./...

.PHONY: lint
lint:
	go vet ./...

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
	  --go_out=$(GO_STUBS_DIR) --go_opt=module=github.com/example/glyph \
	  --go-grpc_out=$(GO_STUBS_DIR) --go-grpc_opt=module=github.com/example/glyph \
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
