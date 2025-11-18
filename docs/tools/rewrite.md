# Rewrite: Traffic Transformation Rules

## Overview

Rewrite is 0xGen's powerful traffic transformation engine that automatically modifies HTTP requests and responses based on user-defined rules. It's designed as a more capable alternative to Burp Suite's Match/Replace feature, offering:

- **Visual Rule Builder**: Create rules without writing code
- **Advanced Conditions**: Match based on headers, body, URL patterns, JSON paths, and more
- **Variable System**: Extract, transform, and reuse values across rules
- **Testing Sandbox**: Test rules safely before enabling on live traffic
- **Performance Optimized**: <10ms overhead even with 100+ active rules

## Quick Start

### Creating Your First Rule

1. Navigate to the **Rewrite** panel in the sidebar
2. Click **New Rule** in the top-right corner
3. Configure the rule:
   - **Name**: "Add API Key Header"
   - **Description**: "Adds X-API-Key to all API requests"
   - **Priority**: 10 (higher = earlier execution)
   - **Enabled**: Toggle on
4. Configure **Scope**:
   - **Direction**: Request
   - **URL Pattern**: `^https://api\.example\.com/.*`
5. Add **Action**:
   - Click "Add Action"
   - **Type**: Add
   - **Location**: Header
   - **Name**: X-API-Key
   - **Value**: your-secret-key
6. Click **Save**
7. Test in the **Sandbox** tab before enabling

### Testing in Sandbox

1. Go to the **Sandbox** tab
2. Select the rule you created
3. Configure test input:
   - **Method**: GET
   - **URL**: https://api.example.com/users
4. Click **Test in Sandbox**
5. Review results:
   - See which rules matched
   - View header changes
   - Check execution time

## Concepts

### Rules

A rule defines when and how to modify traffic. Each rule has:

- **Name & Description**: Human-readable identification
- **Enabled**: Toggle rule on/off without deleting
- **Priority**: Execution order (higher numbers execute first)
- **Scope**: Which traffic to match
- **Conditions**: Additional matching criteria
- **Actions**: What modifications to make

### Scope

Scope determines which requests/responses the rule applies to:

```yaml
Scope:
  Direction: request | response | both
  Methods: [GET, POST, PUT, DELETE, PATCH]  # Optional
  URL Pattern: "^https://api\\.example\\.com/.*"  # Regex
```

### Conditions

Conditions add fine-grained matching beyond scope. All conditions must pass for the rule to execute.

| Type | Description | Example |
|------|-------------|---------|
| `match` | Exact string match | Header equals "Bearer token123" |
| `not_match` | Inverse of match | Header doesn't equal "disabled" |
| `contains` | Substring match | Body contains "error" |
| `regex` | Regular expression | Auth header matches `^Bearer [a-z]+$` |
| `jsonpath` | JSON field exists | Body has `user.role` field |
| `xpath` | XML element exists | Body has `/root/user` element |
| `length` | String length check | Header length `>10` |
| `exists` | Field presence | X-Custom header exists |

**Condition Locations:**
- `header` - HTTP headers
- `cookie` - Cookies
- `body` - Request/response body
- `url` - Full URL
- `path` - URL path
- `query` - Query parameters
- `method` - HTTP method
- `status` - Response status code

### Actions

Actions modify the matched request/response:

| Type | Description | Example |
|------|-------------|---------|
| `add` | Add new value | Add X-Custom: value |
| `replace` | Replace existing value | Replace "old" with "new" |
| `remove` | Remove value | Remove X-Powered-By header |
| `extract` | Extract with regex | Extract token from Auth header |
| `transform` | Apply transformation | Base64 encode value |
| `set_variable` | Store value | Save to ${my_var} |
| `compute_hash` | Generate hash | SHA256 of body |

### Variables

Variables let you extract, store, and reuse values:

**Built-in Variables:**
- `${timestamp}` - Current Unix timestamp
- `${uuid}` - Random UUID
- `${random}` - Random number
- `${request.method}` - HTTP method
- `${request.url}` - Full request URL
- `${request.path}` - URL path
- `${request.header.Name}` - Specific header value

**Variable Substitution:**
```
${varname}              - Simple substitution
${varname:default}      - With default value
${varname|base64}       - With transformation
${varname|base64|upper} - Chained transformations
```

**Transformations:**
- `base64` - Base64 encode
- `base64d` - Base64 decode
- `url` - URL encode
- `urld` - URL decode
- `html` - HTML encode
- `htmld` - HTML decode
- `hex` - Hex encode
- `hexd` - Hex decode
- `md5` - MD5 hash
- `sha1` - SHA1 hash
- `sha256` - SHA256 hash
- `upper` - Uppercase
- `lower` - Lowercase

**Variable Scopes:**
- **Global**: Persist across all requests
- **Session**: Persist within a session
- **Request**: Only available for current request

## Examples

### Remove Security Headers

Strip fingerprinting headers from responses:

```yaml
Name: Remove Server Headers
Direction: response
URL Pattern: .*
Actions:
  - type: remove
    location: header
    name: X-Powered-By
  - type: remove
    location: header
    name: Server
  - type: remove
    location: header
    name: X-AspNet-Version
```

### Replace Cookie Value

Modify a session cookie:

```yaml
Name: Replace Session Cookie
Direction: request
URL Pattern: .*
Actions:
  - type: replace
    location: cookie
    name: session
    value: "new-session-value"
```

### Extract and Reuse JWT Token

Extract JWT from one request and use in another:

```yaml
# Rule 1: Extract JWT
Name: Extract JWT Token
Priority: 100
Direction: request
Conditions:
  - type: exists
    location: header
    name: Authorization
Actions:
  - type: extract
    location: header
    name: Authorization
    value: "Bearer (.+)"  # Captures token in extracted_1

# Rule 2: Forward JWT
Name: Forward JWT
Priority: 50
Direction: request
Actions:
  - type: add
    location: header
    name: X-Forwarded-Token
    value: "${extracted_1}"
```

### Bypass CSRF Protection

Automatically add CSRF tokens to state-changing requests:

```yaml
Name: CSRF Token Injection
Direction: request
Methods: [POST, PUT, DELETE]
URL Pattern: ^https://target\.com/.*
Conditions:
  - type: not_match
    location: header
    name: X-CSRF-Token
    pattern: ".+"
Actions:
  - type: add
    location: header
    name: X-CSRF-Token
    value: "valid-csrf-token-here"
```

### Manipulate JSON Body

Replace values in JSON request bodies:

```yaml
Name: Escalate User Role
Direction: request
URL Pattern: ^https://api\.target\.com/users$
Conditions:
  - type: jsonpath
    location: body
    pattern: "user.role"
Actions:
  - type: replace
    location: body
    name: '"role":"user"'
    value: '"role":"admin"'
```

### Add Request Timing Headers

Add timestamps and unique IDs for debugging:

```yaml
Name: Add Debug Headers
Direction: request
URL Pattern: .*
Actions:
  - type: add
    location: header
    name: X-Request-ID
    value: "${uuid}"
  - type: add
    location: header
    name: X-Timestamp
    value: "${timestamp}"
  - type: add
    location: header
    name: X-Method
    value: "${request.method}"
```

### Conditional Header Based on Body Content

Add header only when body contains specific content:

```yaml
Name: Mark Error Responses
Direction: response
URL Pattern: .*
Conditions:
  - type: contains
    location: body
    pattern: '"error":'
Actions:
  - type: add
    location: header
    name: X-Contains-Error
    value: "true"
```

## Advanced Usage

### Variable Transformations

Chain multiple transformations:

```yaml
Actions:
  - type: set_variable
    name: encoded_data
    value: "${request.body|base64|url}"
```

### Conditional Logic with Multiple Rules

Use multiple rules with conditions for if/else logic:

```yaml
# Rule 1: Handle authenticated requests
Name: Auth Path
Priority: 100
Conditions:
  - type: exists
    location: header
    name: Authorization
Actions:
  - type: set_variable
    name: auth_status
    value: "authenticated"

# Rule 2: Handle unauthenticated requests
Name: No Auth Path
Priority: 100
Conditions:
  - type: not_match
    location: header
    name: Authorization
    pattern: ".+"
Actions:
  - type: set_variable
    name: auth_status
    value: "anonymous"
```

### Performance Optimization

1. **Use specific URL patterns**: Narrow patterns reduce unnecessary evaluations
2. **Set appropriate priorities**: Put frequently-matching rules first
3. **Minimize regex complexity**: Avoid catastrophic backtracking
4. **Use `contains` over `regex`**: When exact pattern isn't needed

**Performance Targets:**
- Single rule: <1ms overhead
- 10 rules: <3ms overhead
- 100 rules: <10ms overhead

### Rule Import/Export

Export rules for backup or sharing:

1. Go to Rewrite panel
2. Click **Export Rules**
3. Save JSON file

Import rules:

```bash
# Via API
curl -X POST http://localhost:8713/api/v1/rewrite/rules/import \
  -H "Content-Type: application/json" \
  -d @rules.json
```

## Real-World Use Cases

### Penetration Testing

1. **Session Fixation**: Replace session tokens to test fixation vulnerabilities
2. **Privilege Escalation**: Modify role/permission fields in requests
3. **Parameter Tampering**: Automatically modify sensitive parameters
4. **Authentication Bypass**: Inject valid tokens or remove auth requirements

### Bug Bounty Hunting

1. **Automated Header Injection**: Test for injection points
2. **Response Modification**: Test client-side trust of server data
3. **Token Manipulation**: Test JWT/session handling

### Development & Debugging

1. **Mock Responses**: Modify responses to test error handling
2. **Add Tracing**: Inject correlation IDs for distributed tracing
3. **Environment Switching**: Route requests to different backends

## Comparison with Burp Match/Replace

| Feature | Burp Match/Replace | 0xGen Rewrite |
|---------|-------------------|---------------|
| Visual Builder | No | Yes |
| Conditions | Basic | Advanced (8 types) |
| Variables | No | Yes (with transformations) |
| Testing Sandbox | No | Yes |
| JSON/XPath | No | Yes |
| Priority Control | Limited | Full control |
| Performance | Good | Excellent (<10ms) |
| Import/Export | Limited | Full JSON support |

## Troubleshooting

### Rule Not Matching

1. **Check Scope**: Verify URL pattern and direction
2. **Check Conditions**: All conditions must pass
3. **Check Priority**: Higher priority rules may be blocking
4. **Test in Sandbox**: Use sandbox to see execution log

### Variable Not Substituting

1. **Check Variable Name**: Must match exactly (case-sensitive)
2. **Check Scope**: Variable must be set before use
3. **Check Extraction**: Regex must have capture group

### Performance Issues

1. **Review Regex Patterns**: Check for catastrophic backtracking
2. **Reduce Active Rules**: Disable unnecessary rules
3. **Check Rule Priority**: Put common matches first

## API Reference

### Rule Management

```go
// List all rules
GET /api/v1/rewrite/rules

// Create rule
POST /api/v1/rewrite/rules

// Get rule by ID
GET /api/v1/rewrite/rules/{id}

// Update rule
PUT /api/v1/rewrite/rules/{id}

// Delete rule
DELETE /api/v1/rewrite/rules/{id}

// Import rules
POST /api/v1/rewrite/rules/import

// Export rules
GET /api/v1/rewrite/rules/export
```

### Sandbox Testing

```go
// Test request
POST /api/v1/rewrite/sandbox/test-request
{
  "input": {
    "method": "GET",
    "url": "https://example.com",
    "headers": {"Authorization": "Bearer token"},
    "body": ""
  },
  "rule_ids": [1, 2, 3]
}

// Test response
POST /api/v1/rewrite/sandbox/test-response
{
  "input": {
    "status_code": 200,
    "headers": {"Content-Type": "application/json"},
    "body": "{\"data\": \"value\"}"
  },
  "rule_ids": [1, 2, 3]
}
```

### Metrics

```go
// Get performance metrics
GET /api/v1/rewrite/metrics
```

## Best Practices

1. **Name Rules Descriptively**: Future you will thank present you
2. **Add Descriptions**: Explain the purpose and context
3. **Test Before Enabling**: Always use sandbox first
4. **Use Appropriate Priorities**: Plan execution order
5. **Monitor Performance**: Check metrics regularly
6. **Backup Rules**: Export before major changes
7. **Keep Rules Focused**: One purpose per rule
8. **Document Variables**: Comment on variable usage

## FAQ

**Q: Can I use Rewrite with other proxy tools?**
A: Rewrite is integrated into 0xGen's proxy. It works alongside other tools like Entropy and Cipher.

**Q: How do I disable a rule temporarily?**
A: Toggle the "Enabled" switch in the rule editor. The rule will stop executing but won't be deleted.

**Q: Can rules modify both request and response?**
A: Yes, set Direction to "both". The rule will execute on both.

**Q: What happens if multiple rules match?**
A: Rules execute in priority order (highest first). All matching rules are applied sequentially.

**Q: How do I share rules with my team?**
A: Export rules to JSON and share the file. Team members can import via the API or GUI.

## Getting Help

- **Documentation**: You're reading it!
- **GitHub Issues**: Report bugs at [github.com/RowanDark/0xgen/issues](https://github.com/RowanDark/0xgen/issues)
- **Community**: Join discussions in the 0xGen community

## Tutorials

- [Bypassing CSRF with Rewrite](tutorials/rewrite-csrf-bypass.md)
- [Automating Parameter Fuzzing](tutorials/rewrite-param-fuzzing.md)
- [Session Manipulation at Scale](tutorials/rewrite-session-manipulation.md)
