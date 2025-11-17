# QUICK REFERENCE - Cipher GUI Implementation

## Key Cipher Backend Operations

### All Available Operations (30+)
```
ENCODE/DECODE:
- base64_encode / base64_decode
- base64url_encode / base64url_decode
- url_encode / url_decode
- html_encode / html_decode
- hex_encode / hex_decode
- binary_encode / binary_decode
- ascii_to_hex / hex_to_ascii

COMPRESSION:
- gzip_compress / gzip_decompress

HASHING (non-reversible):
- md5_hash
- sha1_hash
- sha256_hash
- sha512_hash

JWT:
- jwt_decode (no verification)
- jwt_verify (with secret)
- jwt_sign (with secret)
```

## Core Integration Points (Frontend)

### 1. Create Tauri Command (Rust)
**File:** `/home/user/0xGen/apps/desktop-shell/src-tauri/src/main.rs`

Location: Around line 2162 in generate_handler![]

```rust
#[tauri::command]
fn list_cipher_operations() -> Result<Vec<OperationInfo>, String> {
    // Call cipher package functions
    // Return available operations
}

#[tauri::command]
async fn execute_cipher_operation(
    op_name: String,
    input: String,
) -> Result<String, String> {
    // Execute cipher operation via cipher package
}

#[tauri::command]
async fn detect_encoding(input: String) -> Result<Vec<DetectionResult>, String> {
    // Use SmartDetector
}
```

### 2. Create IPC Wrapper (TypeScript)
**File:** `/home/user/0xGen/apps/desktop-shell/src/lib/ipc.ts`

```typescript
export async function listCipherOperations(): Promise<OperationInfo[]> {
  return invoke('list_cipher_operations');
}

export async function executeCipherOperation(
  opName: string,
  input: string
): Promise<string> {
  return invoke('execute_cipher_operation', { op_name: opName, input });
}

export async function detectEncoding(input: string): Promise<DetectionResult[]> {
  return invoke('detect_encoding', { input });
}
```

### 3. Use in React Component
**File:** `/home/user/0xGen/apps/desktop-shell/src/routes/cipher.tsx`

```typescript
import { useState } from 'react';
import { executeCipherOperation, detectEncoding } from '../lib/ipc';
import { toast } from 'sonner';

function CipherScreen() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleExecute = async (operation: string) => {
    setIsLoading(true);
    try {
      const result = await executeCipherOperation(operation, input);
      setOutput(result);
      toast.success(`${operation} executed`);
    } catch (err) {
      toast.error(String(err));
    } finally {
      setIsLoading(false);
    }
  };

  const handleDetect = async () => {
    try {
      const results = await detectEncoding(input);
      // Show detection results
    } catch (err) {
      toast.error(String(err));
    }
  };

  return (
    <div className="grid grid-cols-2 gap-4">
      {/* Input */}
      <textarea value={input} onChange={e => setInput(e.target.value)} />
      
      {/* Output */}
      <textarea value={output} readOnly />
      
      {/* Actions */}
      <button onClick={() => handleExecute('base64_encode')}>
        Base64 Encode
      </button>
      <button onClick={handleDetect}>
        Auto Detect
      </button>
    </div>
  );
}
```

## Navigation Registration

**File:** `/home/user/0xGen/apps/desktop-shell/src/routes/__root.tsx`

Find and update navigation array (around line 22):
```typescript
const navigation = [
  { to: '/', label: 'Dashboard' },
  { to: '/flows', label: 'Flows' },
  { to: '/runs', label: 'Runs' },
  { to: '/compare', label: 'Compare Runs' },
  { to: '/cases', label: 'Cases' },
  { to: '/scope', label: 'Scope' },
  { to: '/blitz', label: 'Blitz' },
  { to: '/cipher', label: 'Cipher' },  // ADD THIS LINE
  { to: '/plugins', label: 'Marketplace' }
];
```

## File Absolute Paths

Key files to modify:
- `/home/user/0xGen/apps/desktop-shell/src/routes/cipher.tsx` (CREATE NEW)
- `/home/user/0xGen/apps/desktop-shell/src/routes/__root.tsx` (UPDATE)
- `/home/user/0xGen/apps/desktop-shell/src/lib/ipc.ts` (UPDATE)
- `/home/user/0xGen/apps/desktop-shell/src-tauri/src/main.rs` (UPDATE)

Key backend files (reference):
- `/home/user/0xGen/internal/cipher/types.go`
- `/home/user/0xGen/internal/cipher/registry.go`
- `/home/user/0xGen/internal/cipher/detector.go`
- `/home/user/0xGen/internal/cipher/recipes.go`

## Example: Complete Minimal Implementation

### 1. IPC Functions (add to lib/ipc.ts)
```typescript
export interface OperationInfo {
  name: string;
  type: string;
  description: string;
}

export interface DetectionResult {
  encoding: string;
  confidence: number;
  reasoning: string;
  operation: string;
}

export async function listCipherOperations(): Promise<OperationInfo[]> {
  return invoke('list_cipher_operations');
}

export async function executeCipherOperation(
  operation: string,
  input: string
): Promise<string> {
  return invoke('execute_cipher_operation', { operation, input });
}

export async function detectEncoding(input: string): Promise<DetectionResult[]> {
  return invoke('detect_encoding', { input });
}
```

### 2. Tauri Commands (add to main.rs)
```rust
#[tauri::command]
fn list_cipher_operations() -> Result<Vec<String>, String> {
    let ops = cipher::ListOperations();
    Ok(ops.iter().map(|op| op.Name()).collect())
}

#[tauri::command]
async fn execute_cipher_operation(operation: String, input: String) -> Result<String, String> {
    let op = cipher::GetOperation(&operation)
        .ok_or_else(|| format!("Unknown operation: {}", operation))?;
    
    let ctx = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || {
            op.Execute(context.Background(), input.as_bytes(), None)
        })
    ).await.map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    
    Ok(String::from_utf8_lossy(&ctx).to_string())
}

#[tauri::command]
async fn detect_encoding(input: String) -> Result<Vec<serde_json::Value>, String> {
    let detector = cipher.NewSmartDetector();
    let results = detector.Detect(context.Background(), input.as_bytes())?;
    Ok(serde_json::to_value(results).map_err(|e| e.to_string())?)
}
```

### 3. Register Commands in generate_handler![]
```rust
.invoke_handler(tauri::generate_handler![
    // ... existing handlers ...
    list_cipher_operations,
    execute_cipher_operation,
    detect_encoding,
    // ... other handlers ...
])
```

### 4. React Route (create cipher.tsx)
```typescript
import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { Sparkles, Copy, Zap } from 'lucide-react';
import { Button } from '../components/ui/button';
import { executeCipherOperation, detectEncoding } from '../lib/ipc';
import { toast } from 'sonner';

export const Route = createFileRoute('/cipher')({
  component: CipherScreen
});

function CipherScreen() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const executeOp = async (op: string) => {
    setIsLoading(true);
    try {
      const result = await executeCipherOperation(op, input);
      setOutput(result);
      toast.success(`Executed: ${op}`);
    } catch (err) {
      toast.error(String(err));
    } finally {
      setIsLoading(false);
    }
  };

  const detect = async () => {
    try {
      const results = await detectEncoding(input);
      setOutput(JSON.stringify(results, null, 2));
    } catch (err) {
      toast.error(String(err));
    }
  };

  return (
    <div className="h-full flex flex-col gap-4 p-4">
      <h1 className="text-2xl font-bold">Cipher</h1>
      
      <div className="grid grid-cols-2 gap-4 flex-1 min-h-0">
        {/* Input */}
        <div className="flex flex-col gap-2">
          <h2 className="text-sm font-medium">Input</h2>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="flex-1 p-3 rounded-lg border border-border bg-muted/30 font-mono text-sm"
            placeholder="Enter data to transform..."
          />
        </div>

        {/* Output */}
        <div className="flex flex-col gap-2">
          <div className="flex justify-between items-center">
            <h2 className="text-sm font-medium">Output</h2>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                navigator.clipboard.writeText(output);
                toast.success('Copied!');
              }}
            >
              <Copy className="h-4 w-4" />
            </Button>
          </div>
          <textarea
            value={output}
            readOnly
            className="flex-1 p-3 rounded-lg border border-border bg-muted/30 font-mono text-sm"
          />
        </div>
      </div>

      {/* Operations */}
      <div className="flex gap-2 flex-wrap">
        <Button onClick={() => executeOp('base64_encode')}>
          Base64 Encode
        </Button>
        <Button onClick={() => executeOp('base64_decode')}>
          Base64 Decode
        </Button>
        <Button onClick={() => executeOp('url_encode')}>
          URL Encode
        </Button>
        <Button onClick={detect} variant="outline">
          <Sparkles className="h-4 w-4 mr-2" />
          Auto Detect
        </Button>
      </div>
    </div>
  );
}
```

## Testing the Integration

1. Start backend: `go run ./cmd/0xgenctl/...`
2. Start frontend: `cd apps/desktop-shell && npm run dev`
3. Navigate to `/cipher` route
4. Test operations on sample data
5. Verify toast notifications appear
6. Check console for errors

## Next Steps

1. Implement Rust-Go integration for cipher package calls
2. Add operation parameter support (for JWT secret, etc.)
3. Build operation selection UI/dropdown
4. Implement recipe loading and saving
5. Add pipeline builder interface
6. Implement reversible operation toggling
7. Add result export features

