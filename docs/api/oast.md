# OAST API Reference

## Overview

The OAST API provides endpoints for managing Out-of-Application Security Testing functionality, including server status, callback URL generation, and interaction retrieval.

## Authentication

All OAST endpoints require authentication with at least `Viewer` role.

```bash
curl -H "Authorization: Bearer <token>" \
  http://localhost:8080/api/v1/oast/status
```

## Endpoints

### GET /api/v1/oast/status

Get OAST server status, statistics, and recent interactions.

**Response:**

```json
{
  "enabled": true,
  "status": {
    "running": true,
    "port": 8443,
    "mode": "local"
  },
  "stats": {
    "total": 42,
    "uniqueIDs": 15,
    "byType": {
      "http": 42
    }
  },
  "interactions": [
    {
      "id": "oast-1705420800-k7m3np2q-0001",
      "timestamp": "2025-01-16T14:00:00.000Z",
      "type": "http",
      "method": "GET",
      "path": "/callback/oast-1705420800-k7m3np2q-0001",
      "clientIP": "192.168.1.100"
    }
  ]
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | boolean | Whether OAST is enabled |
| `status.running` | boolean | Whether OAST server is running |
| `status.port` | integer | Port number OAST server is listening on |
| `status.mode` | string | OAST mode: "local", "selfhosted", or "cloud" |
| `stats.total` | integer | Total number of interactions |
| `stats.uniqueIDs` | integer | Number of unique callback IDs |
| `stats.byType` | object | Interactions grouped by type |
| `interactions` | array | List of recent interactions |

**Example:**

```bash
curl http://localhost:8080/api/v1/oast/status
```

---

### GET /api/v1/oast/interactions

List all OAST interactions with optional filtering.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 100 | Maximum number of results |
| `since` | timestamp | - | Only return interactions after this time |
| `test_id` | string | - | Filter by test ID |
| `type` | string | - | Filter by interaction type |

**Response:**

```json
{
  "interactions": [
    {
      "id": "oast-1705420800-k7m3np2q-0001",
      "timestamp": "2025-01-16T14:00:00.000Z",
      "type": "http",
      "method": "GET",
      "path": "/callback/oast-1705420800-k7m3np2q-0001",
      "query": "param=value",
      "clientIP": "192.168.1.100",
      "headers": {
        "User-Agent": ["curl/7.68.0"],
        "Accept": ["*/*"]
      },
      "body": "",
      "userAgent": "curl/7.68.0",
      "testID": "scan-001",
      "requestID": "req-abc123"
    }
  ],
  "stats": {
    "total": 42,
    "uniqueIDs": 15,
    "byType": {
      "http": 42
    }
  }
}
```

**Interaction Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique callback ID |
| `timestamp` | string | ISO 8601 timestamp |
| `type` | string | Interaction type (e.g., "http") |
| `method` | string | HTTP method |
| `path` | string | Request path |
| `query` | string | Query string (optional) |
| `clientIP` | string | Client IP address |
| `headers` | object | HTTP headers (optional) |
| `body` | string | Request body (optional) |
| `userAgent` | string | User-Agent header (optional) |
| `testID` | string | Associated test ID (optional) |
| `requestID` | string | Associated request ID (optional) |

**Examples:**

```bash
# Get all interactions
curl http://localhost:8080/api/v1/oast/interactions

# Get last 50 interactions
curl "http://localhost:8080/api/v1/oast/interactions?limit=50"

# Get interactions for specific test
curl "http://localhost:8080/api/v1/oast/interactions?test_id=scan-001"

# Get interactions since timestamp
curl "http://localhost:8080/api/v1/oast/interactions?since=2025-01-16T10:00:00Z"
```

---

### GET /api/v1/oast/interactions/{id}

Get all interactions for a specific callback ID.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Callback ID |

**Response:**

```json
{
  "id": "oast-1705420800-k7m3np2q-0001",
  "count": 3,
  "interactions": [
    {
      "id": "oast-1705420800-k7m3np2q-0001",
      "timestamp": "2025-01-16T14:00:00.000Z",
      "type": "http",
      "method": "GET",
      "path": "/callback/oast-1705420800-k7m3np2q-0001",
      "clientIP": "192.168.1.100"
    },
    {
      "id": "oast-1705420800-k7m3np2q-0001",
      "timestamp": "2025-01-16T14:01:00.000Z",
      "type": "http",
      "method": "POST",
      "path": "/callback/oast-1705420800-k7m3np2q-0001",
      "clientIP": "192.168.1.101"
    }
  ]
}
```

**Example:**

```bash
curl http://localhost:8080/api/v1/oast/interactions/oast-1705420800-k7m3np2q-0001
```

---

### POST /api/v1/oast/generate

Generate a new callback URL.

**Request Body:**

```json
{
  "test_id": "scan-001",
  "path": "/ssrf"
}
```

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `test_id` | string | No | Associated test ID for correlation |
| `path` | string | No | Custom path suffix for the callback URL |

**Response:**

```json
{
  "id": "oast-1705420800-xyz789ab-0001",
  "url": "http://localhost:8443/callback/oast-1705420800-xyz789ab-0001",
  "created": "2025-01-16T14:30:00.000Z",
  "test_id": "scan-001"
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Generated callback ID |
| `url` | string | Full callback URL |
| `created` | string | ISO 8601 creation timestamp |
| `test_id` | string | Associated test ID (if provided) |

**Examples:**

```bash
# Generate simple callback
curl -X POST http://localhost:8080/api/v1/oast/generate

# Generate callback with test ID
curl -X POST http://localhost:8080/api/v1/oast/generate \
  -H "Content-Type: application/json" \
  -d '{"test_id": "ssrf-scan-001"}'

# Generate callback with custom path
curl -X POST http://localhost:8080/api/v1/oast/generate \
  -H "Content-Type: application/json" \
  -d '{"test_id": "xxe-scan", "path": "/xxe"}'
```

---

## Error Responses

### 503 Service Unavailable

OAST is disabled:

```json
{
  "error": "OAST is disabled"
}
```

### 400 Bad Request

Missing or invalid parameters:

```json
{
  "error": "missing interaction ID"
}
```

### 500 Internal Server Error

Server error:

```json
{
  "error": "failed to retrieve interactions: <details>"
}
```

---

## Callback Server Endpoints

When OAST is enabled, the callback server listens on the configured port (default: random).

### GET/POST/PUT/DELETE /callback/{id}

Receive callbacks from vulnerable targets.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Callback ID |

**Response:**

Always returns `200 OK` with empty body to avoid leaking information.

**Example:**

```bash
# Simulating a callback (as if from vulnerable target)
curl http://localhost:8443/callback/oast-1705420800-k7m3np2q-0001
```

### GET /callback/{id}/{extra}

Callbacks with extra path segments are also supported:

```bash
curl http://localhost:8443/callback/oast-123/ssrf/test
```

### GET /health

Health check endpoint:

```bash
curl http://localhost:8443/health
# Returns: 200 OK
```

### GET /admin/interactions

Admin endpoint to list all interactions (GUI use):

```json
{
  "interactions": [...],
  "count": 42
}
```

---

## WebSocket Events

Real-time updates are available via WebSocket (for GUI):

### Event: oast_interaction

Emitted when a new interaction is received:

```json
{
  "type": "oast_interaction",
  "payload": {
    "id": "oast-1705420800-k7m3np2q-0001",
    "timestamp": "2025-01-16T14:00:00.000Z",
    "type": "http",
    "method": "GET",
    "path": "/callback/oast-1705420800-k7m3np2q-0001",
    "clientIP": "192.168.1.100"
  }
}
```

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `/api/v1/oast/generate` | 100 requests/minute |
| `/api/v1/oast/interactions` | 60 requests/minute |
| `/callback/*` | Unlimited |

---

## Code Examples

### Go

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
)

func main() {
    // Generate callback
    reqBody := map[string]string{"test_id": "my-test"}
    body, _ := json.Marshal(reqBody)

    resp, err := http.Post(
        "http://localhost:8080/api/v1/oast/generate",
        "application/json",
        bytes.NewBuffer(body),
    )
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    var result struct {
        ID  string `json:"id"`
        URL string `json:"url"`
    }
    json.NewDecoder(resp.Body).Decode(&result)

    fmt.Printf("Callback URL: %s\n", result.URL)
}
```

### Python

```python
import requests

# Generate callback
response = requests.post(
    'http://localhost:8080/api/v1/oast/generate',
    json={'test_id': 'my-test'}
)
callback = response.json()
print(f"Callback URL: {callback['url']}")

# Check for interactions
response = requests.get(
    f"http://localhost:8080/api/v1/oast/interactions/{callback['id']}"
)
result = response.json()
print(f"Interactions: {result['count']}")
```

### JavaScript

```javascript
// Generate callback
const response = await fetch('http://localhost:8080/api/v1/oast/generate', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ test_id: 'my-test' })
});
const callback = await response.json();
console.log('Callback URL:', callback.url);

// Check for interactions
const interactions = await fetch(
  `http://localhost:8080/api/v1/oast/interactions/${callback.id}`
).then(r => r.json());
console.log('Interactions:', interactions.count);
```

---

## Related

- [OAST User Guide](../features/oast.md)
- [Scanner API](./scanner.md)
- [Authentication](./auth.md)
