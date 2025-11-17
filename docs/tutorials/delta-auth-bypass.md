# Tutorial: Finding Authentication Bypass with Delta

## Overview

This tutorial demonstrates how to use Delta to identify authentication and authorization vulnerabilities by comparing HTTP responses. We'll walk through a real-world example of discovering a privilege escalation vulnerability.

**Time Required**: 15 minutes

**Difficulty**: Intermediate

**Prerequisites**:
- 0xGen installed and running
- Basic understanding of JWT tokens
- Target application with user roles (admin vs user)

## Scenario

You're testing a web application that uses JWT tokens for authentication. You suspect the application might not properly validate JWT claims, potentially allowing privilege escalation from a regular user to an admin.

## Step-by-Step Guide

### Step 1: Capture Baseline Request (Regular User)

1. **Log in as a regular user** to the target application
2. **Capture the authenticated request** using 0xGen Proxy
3. **Navigate to Flows** panel
4. **Find the API request** that returns user data (e.g., `/api/user/profile`)
5. **Save the response** for comparison

**Example Response (Regular User):**
```json
{
  "user": {
    "id": 12345,
    "username": "alice",
    "email": "alice@example.com",
    "role": "user",
    "permissions": ["read", "write"],
    "session": {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expires": "2024-01-15T12:00:00Z"
    }
  },
  "settings": {
    "theme": "light",
    "notifications": true
  }
}
```

### Step 2: Modify JWT Token

1. **Decode the JWT token** using jwt.io or similar tool
2. **Identify the claims** that specify role/permissions:
   ```json
   {
     "sub": "12345",
     "username": "alice",
     "role": "user",
     "permissions": ["read", "write"],
     "exp": 1705320000
   }
   ```

3. **Modify the claims** to escalate privileges:
   ```json
   {
     "sub": "12345",
     "username": "alice",
     "role": "admin",  // Changed from "user"
     "permissions": ["read", "write", "admin", "delete"],  // Added admin perms
     "exp": 1705320000
   }
   ```

4. **Re-encode the JWT** (note: if signature verification is weak/disabled, the modified token might work)

5. **Optional**: Try different modifications:
   - Change `role` to `admin`
   - Add `isAdmin: true` claim
   - Modify `permissions` array
   - Change `user_type` or similar fields

### Step 3: Send Modified Request

1. **In 0xGen Flows**, right-click the original request
2. **Select "Send to Repeater"**
3. **Replace the Authorization header** with modified JWT:
   ```
   Authorization: Bearer <modified-jwt-token>
   ```

4. **Send the request**
5. **Capture the new response**

**Example Response (Modified Token):**
```json
{
  "user": {
    "id": 12345,
    "username": "alice",
    "email": "alice@example.com",
    "role": "admin",  // Server accepted modified role!
    "permissions": ["read", "write", "admin", "delete"],  // All permissions granted!
    "session": {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expires": "2024-01-15T12:00:00Z"
    }
  },
  "settings": {
    "theme": "light",
    "notifications": true
  },
  "admin_panel": {  // New admin-only section!
    "url": "/admin",
    "features": ["user_management", "system_config"]
  }
}
```

### Step 4: Compare Responses with Delta

1. **Navigate to Delta** (/delta in GUI)
2. **Paste the original response** in the left editor
3. **Paste the modified response** in the right editor
4. **Select diff type**: JSON (semantic)
5. **Click "Compare"** or press `Ctrl+D`

### Step 5: Analyze Results

Delta will show you the semantic differences:

**Changes Detected:**

| Type | Path | Old Value | New Value | Noise? |
|------|------|-----------|-----------|--------|
| Modified | `user.role` | `"user"` | `"admin"` | ❌ SIGNAL |
| Modified | `user.permissions[2]` | - | `"admin"` | ❌ SIGNAL |
| Modified | `user.permissions[3]` | - | `"delete"` | ❌ SIGNAL |
| Added | `admin_panel` | - | `{...}` | ❌ SIGNAL |
| Modified | `user.session.token` | `abc...` | `xyz...` | ✅ Noise (filtered) |
| Modified | `user.session.expires` | `10:00` | `10:01` | ✅ Noise (filtered) |

**Similarity Score**: 78.5% (significant differences detected)

**AI Insights:**
- "Role changed from 'user' to 'admin' - potential privilege escalation"
- "New admin_panel object added - indicates elevated access"
- "Permissions array expanded with privileged operations"

### Step 6: Toggle Noise Filter

1. **Press `F`** to toggle noise filter
2. **View only signal changes** (session token changes are hidden)
3. **Focus on security-relevant differences**

**Signal Changes (Noise Filtered):**
- ✅ `user.role`: user → admin
- ✅ `user.permissions`: added ["admin", "delete"]
- ✅ `admin_panel`: entire object added

### Step 7: Verify the Vulnerability

Now test if the elevated permissions actually work:

1. **Access admin-only endpoints** with the modified token:
   ```
   GET /api/admin/users
   Authorization: Bearer <modified-jwt>
   ```

2. **Compare responses**:
   - **With original token**: 403 Forbidden
   - **With modified token**: 200 OK (full user list returned!)

3. **Use Delta to compare** these new responses:
   - Left: 403 error response
   - Right: 200 success response with admin data

**Vulnerability Confirmed**: The application does not properly validate JWT claims server-side!

### Step 8: Document the Finding

1. **Export Delta results**:
   - Click "Export" → "HTML Report"
   - Save as `auth-bypass-evidence.html`

2. **Create a case** in 0xGen:
   - Navigate to Cases panel
   - Create new case: "Authentication Bypass via JWT Manipulation"
   - Severity: Critical
   - Attach Delta export as evidence

3. **Write up the finding**:
   ```markdown
   # Privilege Escalation via JWT Claim Manipulation

   ## Summary
   The application accepts client-controlled JWT claims without server-side
   validation, allowing any user to escalate to admin privileges.

   ## Steps to Reproduce
   1. Log in as regular user
   2. Decode JWT token
   3. Modify "role" claim from "user" to "admin"
   4. Re-encode JWT (signature not validated)
   5. Use modified token in requests
   6. Observe admin privileges granted

   ## Evidence
   - Original vs Modified Response (see delta-report.html)
   - Similarity: 78.5% (significant privilege change)
   - Signal changes: role, permissions, admin_panel access

   ## Impact
   - Complete admin access to application
   - User data exposure (GET /api/admin/users)
   - System configuration changes possible
   - Privilege escalation: Critical severity

   ## Recommendation
   - Validate JWT claims server-side (not just signature)
   - Use role database lookup, not JWT claims
   - Implement proper authorization checks on all endpoints
   ```

## Advanced Techniques

### Technique 1: Batch Fuzzing JWT Claims

Test multiple claim variations at once:

1. **Create 10 JWT tokens** with different claim modifications:
   - `role: "admin"`
   - `role: "superuser"`
   - `isAdmin: true`
   - `admin: true`
   - `permissions: ["*"]`
   - etc.

2. **Capture all 10 responses**

3. **Use Delta Batch Comparison**:
   - Navigate to Delta → Batch mode
   - Load all 10 responses
   - Select "All Pairs" strategy
   - Click "Batch Compare"

4. **Review similarity matrix**:
   - Identify which claims worked (responses differ from baseline)
   - Find outliers (successful bypasses)

**Example Matrix:**

```
         R1    R2    R3    R4    R5    R6
R1 (base) 100%  98%   45%   97%   98%   44%
R2        98%   100%  46%   99%   97%   45%
R3 ✓      45%   46%   100%  47%   46%   99%  ← Successful bypass!
R4        97%   99%   47%   100%  98%   46%
R5        98%   97%   46%   98%   100%  45%
R6 ✓      44%   45%   99%   46%   45%   100% ← Another bypass!
```

**AI Insights:**
- "Responses 3 and 6 cluster together (99% similar)"
- "These 2 responses differ significantly from baseline (45% similarity)"
- "Likely indicate successful authentication bypass"

### Technique 2: Timing Analysis

Compare response times to detect partial validation:

1. **Enable response time tracking** in batch comparison
2. **Send multiple modified JWTs**
3. **Check anomaly detection** for slow responses

**Why?** If the server validates some claims but not others, you'll see timing differences.

**Example:**
```
Response 1 (valid JWT):     150ms
Response 2 (role modified): 148ms  ← Fast, not validated
Response 3 (exp modified):  890ms  ← Slow, server checks expiration!
```

**Conclusion**: Server validates expiration but not role/permissions.

### Technique 3: Error Message Comparison

Compare error messages from different invalid tokens:

1. **Send JWTs with various invalid configurations**
2. **Batch compare error responses**
3. **Look for differences in error messages**

**Findings:**
```
Token A (expired):           "Token expired"
Token B (invalid signature): "Token expired"  ← Same error!
Token C (role modified):     "Token expired"  ← Same error!
```

**Vulnerability**: Server only validates expiration, accepts any signature/claims!

## Common Pitfalls

### Pitfall 1: Forgetting to Filter Noise

**Problem**: Session tokens, timestamps change on every request, hiding real differences.

**Solution**: Press `F` to enable noise filtering, focus on structural changes.

### Pitfall 2: Comparing Wrong Endpoints

**Problem**: Comparing `/api/user/profile` with `/api/admin/dashboard` shows too many differences.

**Solution**: Compare the SAME endpoint with different tokens to isolate auth-related changes.

### Pitfall 3: Not Testing All Endpoints

**Problem**: One endpoint might validate properly while others don't.

**Solution**: Batch compare responses from 10-20 different endpoints with modified token.

## Real-World Examples

### Example 1: Online Banking App

**Claim Modified**: `account_type: "premium"`
**Result**: Free access to premium features (no fees)
**Severity**: Medium (business logic bypass)

### Example 2: SaaS Platform

**Claim Modified**: `tenant_id: "different-org"`
**Result**: Access to other organization's data
**Severity**: Critical (data breach)

### Example 3: E-commerce Site

**Claim Modified**: `is_employee: true`
**Result**: Employee discount applied to all purchases
**Severity**: Medium (financial loss)

## Checklist

- [ ] Captured baseline request (valid token)
- [ ] Decoded JWT and identified claims
- [ ] Modified security-relevant claims
- [ ] Sent modified request
- [ ] Captured modified response
- [ ] Compared responses in Delta
- [ ] Enabled noise filtering
- [ ] Analyzed signal changes
- [ ] Verified vulnerability with admin endpoint test
- [ ] Exported Delta report
- [ ] Documented finding in case
- [ ] Recommended remediation

## Next Steps

1. **Read**: [Delta User Guide](../tools/delta.md)
2. **Try**: [Batch Comparison Tutorial](./delta-batch-fuzzing.md)
3. **Learn**: [Delta API Documentation](../api/delta-api.md)

## Questions?

- **GitHub Issues**: https://github.com/RowanDark/0xGen/issues
- **Community**: 0xGen Discord server

---

**Tutorial Version**: 1.0
**Last Updated**: January 2025
**Difficulty**: Intermediate
**Estimated Time**: 15 minutes
