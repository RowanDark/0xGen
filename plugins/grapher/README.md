# Grapher

Grapher provides two main capabilities:
1. **Schema Discovery**: Unauthenticated discovery of API schemas (OpenAPI, GraphQL) for downstream workflows
2. **Graph Building**: Construct sitemap graphs by parsing HTML responses and extracting links

## Schema Discovery

- Probes common OpenAPI locations (`/.well-known/openapi.json`, `/openapi.json`, `/swagger.json`, `/swagger/v1/swagger.json`).
- Checks likely GraphQL handlers (`/.well-known/graphql`, `/graphql`, `/api/graphql`) with safe `HEAD`/`GET` metadata requests.
- Follows same-host 301/302 redirects, retries transient 429/503 responses with backoff, and caps response bodies at 1 MiB per request.
- Normalizes any hits to JSON Lines at `${0XGEN_OUT:-/out}/schemas.jsonl` for later enrichment, deduped by schema type + URL + hash.
- Optionally fetches JSON OpenAPI documents ≤ 256 KiB with `--fetch`, recording byte counts and SHA-256 digests for diffing. Fetching is disabled by default.

The scanner intentionally uses **no authentication** and performs **no active GraphQL introspection** queries. Many production GraphQL deployments disable introspection for security-hardening, so Grapher only records whether a schema endpoint is reachable and the HTTP status returned.

## Security notes

- Review the [OpenAPI Specification security considerations](https://spec.openapis.org/oas/latest.html#security-considerations) when deciding how to expose schema documents publicly.
- GraphQL administrators frequently lock down introspection in production; see the [GraphQL best practices on security](https://graphql.org/learn/best-practices/#security) for background.

## Examples

Build and run Grapher against one or more base URLs:

```bash
# Scan a single host
go run ./plugins/grapher --target https://example.com

# Read targets from a file and override the output location
cat <<'TARGETS' > /tmp/targets.txt
https://example.com
https://api.example.com
TARGETS

go run ./plugins/grapher --targets-file /tmp/targets.txt --out ./out/schemas.jsonl
```

Each successful discovery is emitted as a JSON object on its own line:

```json
{"type":"openapi","url":"https://example.com/openapi.json","status":200,"ts":"2024-01-01T00:00:00Z"}
{"type":"graphql","url":"https://example.com/graphql","status":400,"ts":"2024-01-01T00:00:01Z"}
```

The timestamps are recorded in RFC3339 UTC format. Downstream tooling can merge or deduplicate the JSONL as needed.

## Graph Building

The `Builder` API allows you to construct sitemap graphs by processing HTTP request/response pairs. It automatically:
- Extracts all links from HTML responses (including `<a>`, `<link>`, `<script>`, and `<img>` tags)
- Resolves relative URLs to absolute URLs correctly
- Filters out invalid schemes (javascript:, mailto:, tel:, data:)
- Handles URL normalization (removes fragments, trailing slashes)
- Creates a directed graph with nodes (URLs) and edges (links)

### Usage Example

```go
import "github.com/RowanDark/0xgen/plugins/grapher"

// Create a new builder
builder := NewBuilder()

// Process HTTP responses as you crawl
req, _ := http.NewRequest("GET", "https://example.com/", nil)
resp := &http.Response{
    StatusCode: 200,
    Header:     http.Header{"Content-Type": []string{"text/html"}},
    Body:       io.NopCloser(strings.NewReader(`<html>...`)),
    Request:    req,
}

// Add the request/response to the graph
err := builder.AddRequest(req, resp)

// Get the resulting graph
graph := builder.GetGraph()

// Access nodes and edges
fmt.Printf("Discovered %d URLs\n", len(graph.Nodes))
fmt.Printf("Found %d links\n", len(graph.Edges))
```

### Features

**Relative URL Resolution**: All relative URLs are correctly resolved to absolute URLs based on the request context:
- `/about` → `https://example.com/about`
- `../parent` → `https://example.com/parent`
- `other.html` → `https://example.com/section/other.html`

**Security Filtering**: Invalid and potentially dangerous schemes are filtered out:
- ❌ `javascript:alert('xss')`
- ❌ `mailto:test@example.com`
- ❌ `tel:+1234567890`
- ✅ `https://example.com/page`

**Smart Processing**:
- Only processes successful HTML responses (status 200-399 with HTML content type)
- Deduplicates links within each page
- Normalizes URLs for consistent node IDs
- Thread-safe for concurrent crawling

See `example_graph_builder.go` for a complete working example.
