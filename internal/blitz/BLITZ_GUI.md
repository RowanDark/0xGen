# Blitz GUI Documentation

## Overview

The Blitz GUI provides an intuitive, modern interface for setting up and executing AI-powered fuzzing attacks. Built with React, TypeScript, and Tailwind CSS, it offers a familiar experience similar to Burp Suite Intruder but with enhanced AI capabilities and real-time feedback.

## Location

**Frontend Component:** `/home/user/0xGen/apps/desktop-shell/src/routes/blitz.tsx`

## Architecture

The Blitz GUI is structured as a multi-panel layout:

```
┌─────────────────────────────────────────────────────────┐
│                    Header & Controls                     │
├──────────────────────────┬──────────────────────────────┤
│                          │  Payload Configuration       │
│   Request Template       │  - Type selection            │
│   - Position markers     │  - File/range/custom         │
│   - Color-coded editing  │  - Preview                   │
│                          │                              │
│                          ├──────────────────────────────┤
│                          │  Attack Settings             │
│                          │  - Attack type               │
│                          │  - Concurrency               │
│                          │  - Rate limiting             │
├──────────────────────────┴──────────────────────────────┤
│              Results Table (Live Updates)                │
│  - Status, Length, Time, Anomaly detection              │
└─────────────────────────────────────────────────────────┘
```

## Components

### 1. RequestTemplateEditor

**Purpose:** Define the HTTP request template and mark injection positions.

**Features:**
- Monaco-based editor with syntax highlighting
- Interactive position marker system
- Visual marker indicators with 5 distinct colors
- Click-and-drag selection to add markers
- Remove markers with a single click
- Position markers are color-coded and indexed

**Usage:**
1. Paste or type your HTTP request template
2. Select the text you want to fuzz
3. Click "Add Marker" to create a position marker
4. Give the marker a descriptive name
5. Repeat for additional positions

**Example:**
```http
POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{"username":"{{user}}","password":"{{pass}}"}
```

Two markers: `{{user}}` and `{{pass}}`

### 2. PayloadConfigPanel

**Purpose:** Configure payload sources for each position marker.

**Payload Types:**
- **Wordlist:** Load payloads from a file (txt/csv/json)
  - CSV: Select column
  - JSON: Specify JSONPath
- **Range:** Generate numeric/alphabetic sequences
  - Numeric: Start, end, step
  - Alphabetic: a-z, A-Z ranges
- **Custom:** Manually enter payloads (one per line)
- **AI-Generated:** Context-aware payloads (requires AI flag)

**Features:**
- Live payload preview (first 10 items)
- File browser integration
- Validation and error messages
- Position-specific configuration

### 3. AttackSettingsPanel

**Purpose:** Configure attack execution parameters.

**Settings:**
- **Attack Type:**
  - **Sniper:** One position at a time, one payload at a time
  - **Battering Ram:** Same payload to all positions
  - **Pitchfork:** Pair payloads across positions (parallel iteration)
  - **Cluster Bomb:** All combinations (cartesian product)

- **Concurrency:** Number of parallel requests (1-100)
- **Rate Limit:** Requests per second (0 = unlimited)

**Visual Aids:**
- Each attack type has a descriptive tooltip
- Sliders with real-time value display
- Collapsible panel to save screen space

### 4. ProgressIndicator

**Purpose:** Show real-time fuzzing progress and metrics.

**Metrics:**
- Progress bar (completed/total requests)
- Requests Per Second (RPS)
- Estimated Time to Completion (ETA)
- Anomalies detected count
- Current status (Ready/Running/Paused/Completed)

**Features:**
- Color-coded progress bar
- Live updating during execution
- Animated transitions

### 5. ResultsTable

**Purpose:** Display fuzzing results with sortable columns and anomaly highlighting.

**Columns:**
- **#** - Result number
- **Payload** - The payload(s) used
- **Status** - HTTP status code (color-coded)
- **Length** - Response content length
- **Time** - Response time in milliseconds
- **Anomaly** - Anomaly indicator (badge if interesting)

**Features:**
- Sortable columns (click header to sort)
- Click row to view full request/response details
- Status code color coding:
  - Green: 2xx (Success)
  - Blue: 3xx (Redirect)
  - Orange: 4xx (Client error)
  - Red: 5xx (Server error)
- Anomaly highlighting with red badge
- Virtualized scrolling for large result sets

## Control Panel

The top control panel provides:

- **Start/Pause/Stop Controls:**
  - Start button (disabled until valid config)
  - Pause button (during execution)
  - Stop button (abort attack)

- **Clear Results:** Reset the results table

- **Export Results:** Export to CSV/JSON/HTML
  - CSV: Tabular format
  - JSON: Structured data
  - HTML: Visual report

## Workflow

### Basic Fuzzing Workflow

1. **Define Request Template**
   - Paste HTTP request or load from file
   - Mark injection positions with `{{marker}}`

2. **Configure Payloads**
   - For each position, select payload type
   - Configure source (file/range/custom)
   - Preview payloads to verify

3. **Select Attack Type**
   - Choose based on your fuzzing strategy
   - Sniper for single-point testing
   - Cluster Bomb for comprehensive coverage

4. **Set Execution Parameters**
   - Concurrency: Balance speed vs. server load
   - Rate limit: Respect server constraints

5. **Execute Attack**
   - Click "Start Fuzzing"
   - Monitor progress in real-time
   - Review anomalies as they're detected

6. **Analyze Results**
   - Sort by status, time, or length
   - Click interesting results for details
   - Export for further analysis

### AI-Powered Workflow

When AI features are enabled (backend integration):

1. **Automatic Payload Selection**
   - Blitz analyzes your request context
   - Suggests relevant vulnerability payloads
   - Reduces false positives

2. **Smart Anomaly Detection**
   - AI classifies responses in real-time
   - Flags potential vulnerabilities
   - Maps to CWE/OWASP categories

3. **Findings Integration**
   - Interesting results auto-create findings
   - Appears in 0xGen findings dashboard
   - Ready for reporting

## Integration with Backend

### IPC Communication (Pending Implementation)

The GUI will communicate with the Blitz backend via Tauri IPC:

```typescript
// Start fuzzing
await invoke('blitz_start', {
  sessionId: string,
  config: BlitzConfig
});

// Poll for results
await invoke('blitz_get_results', {
  sessionId: string,
  offset: number,
  limit: number
});

// Stop fuzzing
await invoke('blitz_stop', {
  sessionId: string
});

// Export results
await invoke('blitz_export', {
  sessionId: string,
  format: 'csv' | 'json' | 'html',
  outputPath: string
});
```

### Current Implementation

Currently, the GUI uses simulated fuzzing for demonstration:
- Generates mock results at configurable RPS
- Simulates anomaly detection
- Demonstrates all UI features

**TODO:** Replace simulation with actual Tauri IPC calls to Blitz engine.

## Styling and Theming

The GUI uses Tailwind CSS with:
- Dark/light theme support (follows system theme)
- Consistent spacing and typography
- Framer Motion animations for smooth transitions
- Accessible color contrast ratios
- Focus indicators for keyboard navigation

## Accessibility

The GUI is built with accessibility in mind:
- Semantic HTML structure
- ARIA labels for screen readers
- Keyboard navigation support
- Focus management
- Color-blind friendly status indicators

## Performance Optimizations

- **Virtual Scrolling:** Results table uses virtual scrolling for large datasets
- **Debounced Updates:** Live metrics update at 100ms intervals
- **Memoized Components:** React.memo prevents unnecessary re-renders
- **Efficient State Management:** Local state for UI, shared context for data

## Future Enhancements

### Planned Features

1. **Result Detail View**
   - Full request/response display
   - Syntax highlighting
   - Diff view comparing with baseline

2. **Context Menu Actions**
   - Right-click results for quick actions
   - Send to Repeater
   - Add to report
   - Copy as curl command

3. **Filter and Search**
   - Filter by status code
   - Search payloads
   - Filter by anomaly type

4. **Session Management**
   - Save/load fuzzing sessions
   - Resume interrupted attacks
   - Session history

5. **Advanced Payload Editor**
   - Payload encoding/decoding
   - Payload transformations
   - Custom payload generators

6. **Findings Integration**
   - Click anomaly to view finding
   - Add notes to findings
   - Mark false positives

7. **Collaborative Features**
   - Share sessions with team
   - Export to Burp Suite format
   - Import from other tools

## Comparison with Burp Intruder

| Feature | Burp Intruder | Blitz GUI |
|---------|--------------|-----------|
| Position Markers | § markers | {{ }} markers |
| Attack Types | 4 types | 4 types (same) |
| Payload Sources | Multiple | Multiple + AI |
| Live Updates | Yes | Yes |
| Anomaly Detection | Basic | AI-powered |
| Theming | Light only | Dark/Light |
| Export Formats | XML, CSV | CSV, JSON, HTML |
| Findings Integration | Manual | Automatic |
| Open Source | No | Yes |

## Troubleshooting

### GUI doesn't load
- Check browser console for errors
- Verify route is registered in `routeTree.gen.ts`
- Ensure dependencies are installed (`npm install`)

### Position markers not working
- Ensure text is selected before clicking "Add Marker"
- Check that marker name is unique
- Verify markers don't overlap

### Results not updating
- Check that backend IPC is configured
- Verify WebSocket connection (if used)
- Check browser DevTools Network tab

### Export fails
- Verify write permissions for output directory
- Check available disk space
- Ensure valid export format selected

## Code Structure

```
blitz.tsx
├── Types & Interfaces
│   ├── Position
│   ├── PayloadConfig
│   ├── FuzzResult
│   └── BlitzSession
│
├── Components
│   ├── RequestTemplateEditor
│   ├── PayloadConfigPanel
│   ├── AttackSettingsPanel
│   ├── ProgressIndicator
│   └── ResultsTable
│
├── State Management
│   ├── Request template state
│   ├── Position markers state
│   ├── Payload config state
│   ├── Attack settings state
│   └── Session state
│
└── Event Handlers
    ├── Start/Stop fuzzing
    ├── Add/Remove markers
    ├── Update config
    └── Export results
```

## Testing

### Manual Testing Checklist

- [ ] Add position markers
- [ ] Remove position markers
- [ ] Configure wordlist payload
- [ ] Configure range payload
- [ ] Configure custom payload
- [ ] Select each attack type
- [ ] Adjust concurrency slider
- [ ] Adjust rate limit slider
- [ ] Start fuzzing
- [ ] Pause fuzzing
- [ ] Resume fuzzing
- [ ] Stop fuzzing
- [ ] Sort results by each column
- [ ] Click result row
- [ ] Export to CSV
- [ ] Export to JSON
- [ ] Export to HTML
- [ ] Toggle dark/light theme
- [ ] Test keyboard navigation

### Automated Testing (TODO)

- Component unit tests
- Integration tests with mock backend
- E2E tests with Playwright
- Accessibility tests

## Contributing

When contributing to the Blitz GUI:

1. Follow React best practices
2. Use TypeScript strict mode
3. Maintain accessibility standards
4. Add JSDoc comments for complex logic
5. Test in both dark and light themes
6. Ensure responsive design
7. Update this documentation

## License

Part of the 0xGen project. See main repository for license details.
