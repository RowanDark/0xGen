# Grapher

Grapher performs unauthenticated discovery of API schemas so downstream Glyph workflows can reason about surfaced endpoints without touching production credentials.

## Scope

- Probes common OpenAPI locations (`/.well-known/openapi.json`, `/openapi.json`, `/swagger.json`, `/swagger/v1/swagger.json`).
- Checks likely GraphQL handlers (`/.well-known/graphql`, `/graphql`, `/api/graphql`) with safe `HEAD`/`GET` metadata requests.
- Follows same-host 301/302 redirects, retries transient 429/503 responses with backoff, and caps response bodies at 1 MiB per request.
- Normalizes any hits to JSON Lines at `${GLYPH_OUT:-/out}/schemas.jsonl` for later enrichment, deduped by schema type + URL.

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
