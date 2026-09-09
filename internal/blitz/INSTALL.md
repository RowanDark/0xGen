# Blitz Installation Notes

## Dependencies

Blitz requires the following Go dependencies:

### Required
- Standard library packages (included with Go)

### Optional (for full functionality)
- `modernc.org/sqlite` - For SQLite storage backend

## Installing Dependencies

To install the SQLite dependency:

```bash
go get modernc.org/sqlite
```

## Building Without SQLite

If you don't need persistent storage (results will only be in memory), you can build without SQLite by:

1. Not using the `--output` flag (results will be processed via callback only)
2. Using only the export flags (`--export-csv`, `--export-json`, `--export-html`)

Note: Release builds use `CGO_ENABLED=0`, so `modernc.org/sqlite` (pure Go) is
the only supported SQLite driver. Do not switch to a CGo-based driver — it
will break every published release artifact.

## Verifying Installation

After installing dependencies, verify Blitz works:

```bash
# Build the CLI
go build -o 0xgenctl cmd/0xgenctl/*.go

# Run a simple test
./0xgenctl blitz run --help
```

## Troubleshooting

**Build errors about sqlite:**
- Install `modernc.org/sqlite` as shown above
- Or build without storage support

**Network issues during `go get`:**
- Retry the command
- Check your internet connection
- Use a Go module proxy: `GOPROXY=https://proxy.golang.org go get modernc.org/sqlite`

**Runtime errors:**
- Ensure all dependencies are properly installed
- Run `go mod tidy` to clean up dependencies
- Check Go version (requires Go 1.19+)
