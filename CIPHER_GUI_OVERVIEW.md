# Cipher GUI Panel Implementation Guide

## 1. CURRENT CIPHER IMPLEMENTATION (Issue 13.1)

### Backend Location
**Path:** `/home/user/0xGen/internal/cipher/`

### Core Files and Components

#### a) **types.go** - Core Data Structures
- `Operation` interface: Base abstraction for all transformations
  - `Name()`, `Type()`, `Description()`, `Execute()`, `Reverse()`
- `OperationType` enum: encode, decode, hash, compress, decompress, encrypt, decrypt
- `OperationConfig`: Configuration for operations in pipelines
- `Pipeline`: Chain of sequential operations with reversibility support
- `Recipe`: Named, reusable transformation pipelines
- `DetectionResult`: Output from automatic encoding detection
- `BaseOperation`: Common implementation for operations

#### b) **operations.go** - Basic Encoding/Decoding (14+ operations)
```
Supported operations:
- Base64: encode/decode (standard and URL-safe)
- URL: encode/decode
- HTML: entity encode/decode
- Hex: encode/decode
- Binary: encode/decode (8-bit aligned)
- ASCII ↔ Hex conversion
```

#### c) **crypto_operations.go** - Cryptographic & Compression Operations
```
Gzip:
- gzip_compress / gzip_decompress

Hashing (non-reversible):
- md5_hash, sha1_hash, sha256_hash, sha512_hash

JWT Operations:
- jwt_decode: Decode without verification
- jwt_verify: Verify with secret
- jwt_sign: Sign with secret
```

#### d) **registry.go** - Operation Registry (Thread-safe)
```
Functions:
- RegisterOperation(op Operation) - Add operation to registry
- GetOperation(name string) - Retrieve by name
- ListOperations() - Get all operations (sorted)
- ListOperationsByType(opType OperationType) - Filter by type
- UnregisterOperation(name string) - For testing
- ClearRegistry() - For testing
```

#### e) **detector.go** - SmartDetector (AI-powered detection)
```
Detects with 90%+ accuracy:
- Base64 (90-95% confidence)
- Hexadecimal (80-95%, higher with 0x prefix)
- URL encoding (50-95% based on density)
- JWT (95% confidence)
- Gzip (99% confidence via magic bytes)
- HTML entities (40-90% based on count)
- Binary (60-85% for 8-bit aligned strings)

Methods:
- Detect(ctx context.Context, input []byte) - Returns sorted results
- SupportedEncodings() - List detectable formats
```

#### f) **recipes.go** - Recipe Management (Persistent)
```
RecipeManager:
- SaveRecipe(recipe) - Store with auto timestamps
- GetRecipe(name string) - Retrieve single recipe
- ListRecipes() - Get all recipes
- DeleteRecipe(name string) - Remove recipe
- LoadRecipes() - Load from disk
- SearchRecipes(query string) - Query by name/tags/description
- persistRecipe() - Internal disk persistence

Features:
- Thread-safe (RWMutex)
- JSON persistence to disk
- Filename sanitization
- Search by tags
```

### Key Features
- Stateless, thread-safe operations
- Reversible pipelines (auto-reverse chains)
- Recipe library with persistent storage
- AI-powered encoding auto-detection
- Zero dependencies for core operations

---

## 2. GUI FRAMEWORK & TECHNOLOGY STACK

### Frontend Technology
**Framework:** React 18 with TypeScript
**Router:** TanStack Router (file-based routing)
**Build Tool:** Vite
**Component Library:** Custom UI components + Lucide icons
**Styling:** Tailwind CSS
**Animations:** Framer Motion
**Communication:** Tauri IPC

### Desktop Container
**Technology:** Tauri (Rust backend + React frontend)
**Tauri Version:** Latest (using async_runtime)
**Backend Language:** Rust
**IPC Pattern:** `invoke('command_name', { payload })` from React → Rust command handlers

### Key Dependencies
- `@tauri-apps/api`: Tauri communication
- `react`, `react-dom`: UI library
- `@tanstack/react-router`: Routing
- `framer-motion`: Animations
- `sonner`: Toast notifications
- `lucide-react`: Icon library
- `monaco-editor`: Code editor (for scope.tsx)
- `recharts`: Charts (for metrics)

---

## 3. GUI FRAMEWORK STRUCTURE & PANEL PATTERNS

### Navigation Architecture
**Location:** `/home/user/0xGen/apps/desktop-shell/src/routes/__root.tsx`

Navigation items defined as:
```typescript
const navigation = [
  { to: '/', label: 'Dashboard' },
  { to: '/flows', label: 'Flows' },
  { to: '/runs', label: 'Runs' },
  { to: '/compare', label: 'Compare Runs' },
  { to: '/cases', label: 'Cases' },
  { to: '/scope', label: 'Scope' },
  { to: '/blitz', label: 'Blitz' },
  { to: '/plugins', label: 'Marketplace' }
];
```

### File-Based Routing Pattern
**Location:** `/home/user/0xGen/apps/desktop-shell/src/routes/`

Each route is a `.tsx` file that:
1. Imports `createFileRoute` from '@tanstack/react-router'
2. Defines a React component (exported as default)
3. Exports route definition with `export const Route = createFileRoute('/path')({ component: MyComponent })`

**Example structure:**
```typescript
// /routes/example.tsx
import { createFileRoute } from '@tanstack/react-router';

export const Route = createFileRoute('/example')({
  component: ExampleScreen
});

function ExampleScreen() {
  return (
    <div>
      {/* Route content */}
    </div>
  );
}
```

### Layout Pattern
**Root Layout:** `/routes/__root.tsx`
- Header with navigation
- `<Outlet />` for page content
- Command palette integration
- Metrics display
- Health status indicators

### Existing Route Examples

#### a) **Scope (/scope)** - Complex Editor Route
- Monaco editor for policy editing
- Real-time validation
- Dry-run testing
- Benchmark suite
- Multiple panels with tabs
- Forms and text input
- Error messages and badges

#### b) **Blitz (/blitz)** - Fuzzing Interface
- Request template editor
- Position markers
- Multiple input areas
- Real-time result display
- Status tracking
- Progress indicators

#### c) **Index (/)** - Dashboard
- Multiple stat cards
- Sparkline charts
- Run history
- Navigation actions

### Common Component Patterns
```typescript
// Input Area
<div className="flex-1 overflow-hidden rounded-lg border border-border bg-muted/30">
  <textarea
    value={value}
    onChange={(e) => setValue(e.target.value)}
    className="..."
  />
</div>

// Button with Icon
<Button
  variant="outline"
  size="sm"
  onClick={handleClick}
>
  <IconName className="mr-1.5 h-3.5 w-3.5" />
  Action Label
</Button>

// Status Badge
<span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium bg-success/10 text-success">
  <Icon className="h-3.5 w-3.5" />
  Status Text
</span>

// Loading State
const [isLoading, setIsLoading] = useState(false);
const [result, setResult] = useState(null);

useEffect(() => {
  setIsLoading(true);
  invoke('some_command', { payload }).then(res => {
    setResult(res);
  }).catch(err => {
    toast.error(err);
  }).finally(() => {
    setIsLoading(false);
  });
}, []);
```

---

## 4. HOW TO ADD A NEW PANEL/TAB

### Step 1: Create Route File
**File:** `/home/user/0xGen/apps/desktop-shell/src/routes/cipher.tsx`

```typescript
import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { Button } from '../components/ui/button';

export const Route = createFileRoute('/cipher')({
  component: CipherScreen
});

function CipherScreen() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');

  return (
    <div className="flex h-full flex-col gap-4 p-4">
      <h1 className="text-2xl font-bold">Cipher</h1>
      
      <div className="grid grid-cols-2 gap-4 flex-1">
        {/* Input area */}
        <InputPanel value={input} onChange={setInput} />
        
        {/* Output area */}
        <OutputPanel value={output} />
      </div>
    </div>
  );
}

function InputPanel({ value, onChange }) {
  return (
    <div className="flex flex-col gap-2">
      <h2 className="text-sm font-medium">Input</h2>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="flex-1 p-3 rounded-lg border border-border bg-muted/30 font-mono text-sm"
      />
    </div>
  );
}

function OutputPanel({ value }) {
  return (
    <div className="flex flex-col gap-2">
      <h2 className="text-sm font-medium">Output</h2>
      <textarea
        value={value}
        readOnly
        className="flex-1 p-3 rounded-lg border border-border bg-muted/30 font-mono text-sm"
      />
    </div>
  );
}
```

### Step 2: Register in Navigation
**File:** `/home/user/0xGen/apps/desktop-shell/src/routes/__root.tsx`

Add to navigation array:
```typescript
const navigation = [
  // ... existing items
  { to: '/cipher', label: 'Cipher' }
];
```

### Step 3: Create Tauri Command Handler
**File:** `/home/user/0xGen/apps/desktop-shell/src-tauri/src/main.rs`

Add command function:
```rust
#[tauri::command]
async fn execute_cipher_operation(
    operation: String,
    input: String,
    params: Option<serde_json::Value>
) -> Result<String, String> {
    // Implementation here
    Ok(result)
}
```

### Step 4: Register Command in Handler List
**File:** Same main.rs, in `.invoke_handler()`

```rust
.invoke_handler(tauri::generate_handler![
    // ... existing handlers
    execute_cipher_operation,
    // ... other handlers
])
```

### Step 5: Create IPC wrapper
**File:** `/home/user/0xGen/apps/desktop-shell/src/lib/ipc.ts`

```typescript
export async function executeCipherOperation(
  operation: string,
  input: string,
  params?: Record<string, unknown>
): Promise<string> {
  return invoke('execute_cipher_operation', { operation, input, params });
}
```

### Step 6: Use in Component
```typescript
import { executeCipherOperation } from '../lib/ipc';

function CipherScreen() {
  const handleExecute = async () => {
    try {
      const result = await executeCipherOperation('base64_encode', input);
      setOutput(result);
    } catch (err) {
      toast.error(`Error: ${err}`);
    }
  };

  return (
    // ... jsx with handleExecute callback
  );
}
```

---

## 5. EXISTING RECIPE/TRANSFORMATION INFRASTRUCTURE

### Recipe Data Structure
```go
type Recipe struct {
    Name        string                `json:"name"`
    Description string                `json:"description"`
    Tags        []string              `json:"tags,omitempty"`
    Pipeline    Pipeline              `json:"pipeline"`
    CreatedAt   string                `json:"created_at"`
    UpdatedAt   string                `json:"updated_at"`
}

type Pipeline struct {
    Operations []OperationConfig `json:"operations"`
    Reversible bool              `json:"reversible"`
}

type OperationConfig struct {
    Name       string                 `json:"name"`
    Parameters map[string]interface{} `json:"parameters,omitempty"`
}
```

### Example Recipe Usage
```go
rm := cipher.NewRecipeManager("/path/to/recipes")
rm.LoadRecipes() // Load from disk

// Create recipe
recipe := &cipher.Recipe{
    Name:        "double-base64",
    Description: "Double Base64 encoding",
    Tags:        []string{"encoding", "obfuscation"},
    Pipeline: cipher.Pipeline{
        Operations: []cipher.OperationConfig{
            {Name: "base64_encode"},
            {Name: "base64_encode"},
        },
        Reversible: true,
    },
}

rm.SaveRecipe(recipe) // Persist to disk

// Use recipe
results, _ := recipe.Pipeline.Execute(ctx, []byte("data"))

// Reverse if reversible
reversed, _ := recipe.Pipeline.Reverse()
decoded, _ := reversed.Execute(ctx, results)
```

### Recipe Manager Features
- Persistent storage (JSON files)
- Thread-safe operations (RWMutex)
- Search by name, tags, description
- Auto-timestamps (CreatedAt, UpdatedAt)
- Filename sanitization

### Pipeline Execution
```go
// Execute operations sequentially
pipeline := &cipher.Pipeline{
    Operations: []cipher.OperationConfig{
        {Name: "base64_encode"},
        {Name: "url_encode"},
    },
    Reversible: true,
}

// Forward execution
result, _ := pipeline.Execute(ctx, []byte("test"))

// Reverse execution (if all ops reversible)
reversed, _ := pipeline.Reverse()
decoded, _ := reversed.Execute(ctx, result)
```

---

## 6. MAIN GUI ENTRY POINTS & PANEL REGISTRATION

### Tauri Desktop Entry Point
**File:** `/home/user/0xGen/apps/desktop-shell/src-tauri/src/main.rs`

```rust
fn main() {
    tauri::Builder::default()
        .manage(OxgApi::new())          // API client
        .manage(SnapshotStore::new())   // State management
        .manage(ReplayState::new())     // Replay state
        .setup(|app| {
            // Initialize components
            // Attach crash reporter
            // Load snapshots
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Command list (30+ commands)
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

### React Router Entry Point
**File:** `/home/user/0xGen/apps/desktop-shell/src/main.tsx`

```typescript
import { RouterProvider } from '@tanstack/react-router';
import { router } from './router';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <RouterProvider router={router} />
);
```

### Route Tree Generation
**File:** `/home/user/0xGen/apps/desktop-shell/src/routeTree.gen.ts` (Auto-generated)

TanStack Router automatically generates from file-based routes in `/routes/` directory.

### Root Layout
**File:** `/home/user/0xGen/apps/desktop-shell/src/routes/__root.tsx`

Main layout component that:
- Provides navigation header
- Renders `<Outlet />` for page content
- Manages theme switching
- Handles command palette
- Displays metrics
- Sets up providers

### Provider Chain
**Location:** `/home/user/0xGen/apps/desktop-shell/src/providers/`

Key providers:
- `theme-provider`: Dark/light mode
- `mode-provider`: Online/offline modes
- `artifact-provider`: Artifact state (replay data)
- `metrics-provider`: Real-time metrics
- `command-center`: Command palette
- `feedback-provider`: Feedback UI
- `toaster` (Sonner): Toast notifications
- `error-boundary`: Error handling

---

## 7. EXISTING PATTERNS FOR INPUT/OUTPUT AREAS

### Standard Two-Column Layout
```typescript
<div className="grid grid-cols-2 gap-4 flex-1 min-h-0">
  {/* Left: Input */}
  <div className="flex flex-col gap-3">
    <div className="flex items-center justify-between">
      <h3 className="text-sm font-medium">Input</h3>
      <Button size="sm" onClick={handleAction}>Action</Button>
    </div>
    <textarea
      value={value}
      onChange={(e) => setValue(e.target.value)}
      className="flex-1 p-3 rounded-lg border border-border bg-muted/30 font-mono text-sm overflow-auto"
    />
  </div>

  {/* Right: Output */}
  <div className="flex flex-col gap-3">
    <h3 className="text-sm font-medium">Output</h3>
    <textarea
      value={output}
      readOnly
      className="flex-1 p-3 rounded-lg border border-border bg-muted/30 font-mono text-sm overflow-auto"
    />
  </div>
</div>
```

### Three-Section Layout (Input, Operations, Output)
```typescript
<div className="grid grid-cols-3 gap-4 flex-1">
  {/* Section 1 */}
  {/* Section 2 */}
  {/* Section 3 */}
</div>
```

### Toolbar Pattern
```typescript
<div className="flex items-center justify-between gap-2">
  <div className="flex items-center gap-2">
    <Icon className="h-4 w-4 text-muted-foreground" />
    <h3 className="text-sm font-medium">Label</h3>
  </div>
  <div className="flex gap-2">
    <Button variant="ghost" size="sm" onClick={handleAction1}>
      <Icon1 className="h-4 w-4" />
    </Button>
    <Button variant="outline" size="sm" onClick={handleAction2}>
      Action
    </Button>
  </div>
</div>
```

### Loading & Error States
```typescript
const [isLoading, setIsLoading] = useState(false);
const [error, setError] = useState<string | null>(null);

const handleExecute = async () => {
  setIsLoading(true);
  setError(null);
  try {
    const result = await invoke('some_command', { payload });
    setOutput(result);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    setError(message);
    toast.error(message);
  } finally {
    setIsLoading(false);
  }
};

// In JSX:
{error && (
  <div className="rounded-md bg-destructive/10 border border-destructive/20 p-3 text-sm text-destructive">
    <AlertTriangle className="h-4 w-4 inline mr-2" />
    {error}
  </div>
)}

{isLoading && <Loader2 className="h-4 w-4 animate-spin" />}
```

### List/Dropdown Pattern
```typescript
<div className="space-y-2">
  {items.map((item) => (
    <div
      key={item.id}
      className="rounded-md border border-border p-3 cursor-pointer hover:bg-muted/50"
      onClick={() => handleSelect(item)}
    >
      <div className="font-medium text-sm">{item.name}</div>
      <div className="text-xs text-muted-foreground">{item.description}</div>
    </div>
  ))}
</div>
```

---

## 8. KEY FILES REFERENCE

### Backend (Go)
```
/home/user/0xGen/internal/cipher/
├── types.go              # Core interfaces & data structures
├── operations.go         # 14+ encoding/decoding operations
├── crypto_operations.go  # Hashing, JWT, compression
├── detector.go           # Smart auto-detection (90%+ accuracy)
├── registry.go           # Thread-safe operation registry
├── recipes.go            # Recipe management & persistence
└── *_test.go            # Unit tests
```

### Frontend (React/TypeScript)
```
/home/user/0xGen/apps/desktop-shell/src/
├── routes/              # File-based route components
│   ├── __root.tsx       # Root layout with navigation
│   ├── cipher.tsx       # TO CREATE: Cipher panel
│   ├── scope.tsx        # Example: Complex editor route
│   └── blitz.tsx        # Example: Fuzzing interface
├── lib/
│   ├── ipc.ts           # Tauri IPC communication wrappers
│   └── utils.ts         # Utility functions
├── components/
│   ├── ui/              # Base UI components
│   └── *.tsx            # Feature components
└── providers/           # Context providers

/home/user/0xGen/apps/desktop-shell/src-tauri/src/
└── main.rs              # Tauri app setup & command handlers
```

---

## IMPLEMENTATION CHECKLIST FOR CIPHER GUI PANEL

- [ ] Create `/routes/cipher.tsx` with basic layout
- [ ] Add navigation entry in `__root.tsx`
- [ ] Create Tauri command handler in `main.rs`
- [ ] Register command in `generate_handler![]`
- [ ] Create IPC wrapper in `lib/ipc.ts`
- [ ] Implement operation execution (input → output)
- [ ] Add auto-detect functionality
- [ ] Implement recipe selector & loader
- [ ] Add pipeline builder UI
- [ ] Implement reversible operation toggle
- [ ] Add result copy-to-clipboard
- [ ] Add operation library dropdown
- [ ] Style with Tailwind & Lucide icons
- [ ] Add error handling & toast notifications
- [ ] Test with various encodings
