# Running the Go test suite locally

0xgen's Go packages include integration-heavy suites that compile helper
binaries and spawn subprocesses. When running `go test ./...` on constrained
Linux containers or CI runners with strict thread limits, the
`internal/plugins/runner` package tends to exhaust the available pthread quota
while building temporary plugin binaries. The failure manifests as:

```
runtime/cgo: pthread_create failed: Resource temporarily unavailable
SIGABRT: abort
```

## Reduce concurrency for the plugin runner tests

Use the following command to execute the suite sequentially while keeping the
rest of the build parallel:

```bash
GOMAXPROCS=2 go test -p=1 ./internal/plugins/runner
```

After the runner-specific tests pass, rerun the full suite with a higher process
limit if possible. Alternatively, combine both steps by throttling the global
parallelism when running on a small VM or container:

```bash
GOMAXPROCS=2 go test -p=2 ./...
```

These invocations dramatically reduce the peak number of concurrent threads
spawned during plugin compilation, avoiding the abort while still exercising the
same functionality.
