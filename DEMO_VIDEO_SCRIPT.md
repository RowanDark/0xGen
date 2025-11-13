# 0xGen Demo Video Script

**Duration:** 2:30-3:30 minutes
**Format:** Screen capture with voiceover
**Tone:** Professional, technical, enthusiastic

---

## Script Overview

| Section | Time | Description |
|---------|------|-------------|
| Hook | 0:00-0:15 | Attention-grabbing introduction |
| Launch & Interface | 0:15-0:30 | Start 0xGen, tour main UI |
| Proxy & Intercept | 0:30-1:15 | HTTP traffic capture and modification |
| Vulnerability Scanning | 1:15-2:00 | AI-powered security analysis |
| Plugin System | 2:00-2:30 | Plugin marketplace and sandboxing |
| Technical Highlights | 2:30-2:50 | Architecture and supply chain security |
| Call to Action | 2:50-3:00 | Links and community |

---

## Detailed Script with Actions

### [0:00-0:15] Hook & Introduction

**TITLE CARD:** "0xGen: Open-Source Security Testing"
*(Fade in, 2 seconds, with subtle animation)*

**VOICEOVER:**
> "This is 0xGen – an open-source security testing platform. It's completely free, has AI-powered scanning, and ships with supply chain security built-in. Let me show you how it works."

**SCREEN ACTIONS:**
- [0:00-0:02] Title card
- [0:02-0:05] Quick montage: CLI output, GUI panels, plugin interface (fast cuts)
- [0:05-0:15] Desktop with terminal ready to launch

**PACING NOTES:**
- Speak confidently and quickly
- No pauses – maintain energy
- Music starts (low volume under voiceover)

---

### [0:15-0:30] Launch & Interface Tour

**VOICEOVER:**
> "Let's start the 0xGen daemon and launch the GUI."

**SCREEN ACTIONS:**
- [0:15] Type command in terminal:
  ```bash
  0xgenctl daemon start
  ```
- [0:17] Press Enter, show daemon starting
- [0:19] Launch desktop shell:
  ```bash
  cd apps/desktop-shell
  pnpm tauri:dev
  ```
- [0:21] Desktop shell window opens (allow 2-3 seconds for app to load)

**VOICEOVER (continued):**
> "The interface has several panels: Flows for HTTP traffic, Plugins for scanning tools, and Learn Mode for guided tutorials."

**SCREEN ACTIONS:**
- [0:24] Click through sidebar navigation:
  - **Flows** panel
  - **Plugins** panel
  - **Cases** panel
  - **Learn Mode** toggle

**VOICEOVER (continued):**
> "0xGen supports multiple themes. Let's switch to dark mode."

**SCREEN ACTIONS:**
- [0:28] Click theme switcher (top-right)
- [0:29] Select "Dark" theme
- [0:30] UI transitions to dark theme

**PACING NOTES:**
- Keep cursor movements smooth and deliberate
- Pause briefly after each click to let UI respond
- Don't rush the theme transition – let viewer see the change

---

### [0:30-1:15] Proxy & Intercept (45 seconds)

**TITLE CARD:** "Proxy & Intercept"
*(2 seconds)*

**VOICEOVER:**
> "0xGen includes a full-featured HTTP proxy. Let's configure our browser to route traffic through it."

**SCREEN ACTIONS:**
- [0:32] Navigate to **Flows** panel
- [0:33] Click "Start Proxy" button
- [0:34] Show proxy status: "Listening on 127.0.0.1:8080"
- [0:35] Switch to browser window (Firefox or Chrome)
- [0:36] Open proxy settings:
  - **Firefox:** Settings → Network Settings → Manual proxy configuration
  - **Chrome:** Settings → System → Open proxy settings
- [0:40] Set HTTP proxy to `127.0.0.1:8080`
- [0:42] Click "OK" to save

**VOICEOVER (continued):**
> "Now let's navigate to a test site. I'm using OWASP Juice Shop – a vulnerable web application for security testing."

**SCREEN ACTIONS:**
- [0:46] Type in browser address bar: `http://localhost:3000`
- [0:48] Juice Shop homepage loads
- [0:49] Switch to 0xGen Flows panel

**VOICEOVER (continued):**
> "Every request appears in the Flows panel. Let's intercept one and modify it."

**SCREEN ACTIONS:**
- [0:52] Click on a captured request (e.g., GET `/api/Products`)
- [0:53] Request/response details expand below
- [0:54] Click "Replay" or "Send to Repeater" button

**VOICEOVER (continued):**
> "I can modify parameters, headers, or the request body, then send it again."

**SCREEN ACTIONS:**
- [0:58] Modify a query parameter or header value (show edit in Monaco editor)
  - Example: Change `?q=apple` to `?q=apple' OR '1'='1`
- [1:02] Click "Send" or "Replay" button
- [1:03] Show new response appearing

**VOICEOVER (continued):**
> "The response appears instantly. We can compare it with the original using the diff view."

**SCREEN ACTIONS:**
- [1:06] Click "Compare" button (if available) or show side-by-side view
- [1:08] Highlight differences in response (status code, body content)

**PACING NOTES:**
- This is the longest section – 45 seconds
- Demonstrate a realistic security testing workflow
- Keep cursor movements visible
- If any action is slow (page load), speed up in post-production (1.2x-1.5x)

---

### [1:15-2:00] Vulnerability Scanning (45 seconds)

**TITLE CARD:** "AI-Powered Vulnerability Scanning"
*(2 seconds)*

**VOICEOVER:**
> "Now let's scan this traffic for vulnerabilities using the Hydra plugin, which uses AI analysis."

**SCREEN ACTIONS:**
- [1:17] Right-click on a flow in the Flows panel
- [1:18] Context menu appears
- [1:19] Click "Scan with Hydra" (or similar option)

**VOICEOVER (continued):**
> "Hydra analyzes the request and response patterns, looking for security issues."

**SCREEN ACTIONS:**
- [1:22] Scan progress indicator appears
- [1:23-1:28] Show scan running (progress bar or spinner – 5 seconds)
  - *Speed up in post if actual scan is longer*
- [1:28] Scan completes

**VOICEOVER (continued):**
> "The scan found several issues. Let's look at the findings panel."

**SCREEN ACTIONS:**
- [1:30] Click on "Cases" or "Findings" panel in sidebar
- [1:31] Findings list appears with severity indicators
- [1:32] Show list of findings:
  - 🔴 High: SQL Injection
  - 🟡 Medium: Reflected XSS
  - 🟢 Low: Information Disclosure

**VOICEOVER (continued):**
> "Each finding includes an AI-generated explanation, severity rating, and CVSS score."

**SCREEN ACTIONS:**
- [1:37] Click on "SQL Injection" finding
- [1:38] Details panel expands showing:
  - Severity: High
  - CVSS Score: 8.2
  - AI Explanation (show first few lines)
  - Proof of Concept
  - Remediation advice

**VOICEOVER (continued):**
> "The AI explains exactly what the vulnerability is, how to exploit it, and how to fix it."

**SCREEN ACTIONS:**
- [1:44] Scroll through explanation (slowly, let viewer see some text)
- [1:47] Highlight CVSS score
- [1:49] Show proof-of-concept code or curl command

**VOICEOVER (continued):**
> "You can export findings to SARIF, JSON, or HTML reports for your clients."

**SCREEN ACTIONS:**
- [1:53] Click "Export" button
- [1:54] Show export options dropdown:
  - SARIF (for CI/CD)
  - JSON (for tooling)
  - HTML Report
- [1:56] Click "HTML Report"
- [1:57] Report generates (show progress if quick)
- [1:58] Browser opens showing HTML report preview

**PACING NOTES:**
- Show enough detail to be credible without overwhelming viewer
- If scan takes longer than 5 seconds, speed up footage
- Make sure finding details are readable (zoom if necessary in post)

---

### [2:00-2:30] Plugin System (30 seconds)

**TITLE CARD:** "Plugin Ecosystem"
*(2 seconds)*

**VOICEOVER:**
> "0xGen has a plugin system for extending functionality. Let's open the plugin manager."

**SCREEN ACTIONS:**
- [2:02] Click "Plugins" in sidebar navigation
- [2:03] Plugin marketplace interface appears

**VOICEOVER (continued):**
> "Here we can see installed plugins and browse the marketplace."

**SCREEN ACTIONS:**
- [2:06] Show list of plugins:
  - ✅ Hydra (AI Vulnerability Analyzer) – **Installed**
  - ✅ Seer (Passive Scanner) – **Installed**
  - ⬇️ Blitz (Fuzzing Engine) – *Phase 3*
  - ⬇️ Cipher (Encoder/Decoder) – *Phase 3*
- [2:08] Click on "Hydra" plugin

**VOICEOVER (continued):**
> "Each plugin runs in a sandbox with limited permissions. The isolation indicators show the security boundaries."

**SCREEN ACTIONS:**
- [2:12] Plugin details panel shows:
  - Name: Hydra
  - Version: 1.0.0
  - Capabilities: CAP_AI_ANALYSIS, CAP_HTTP_PASSIVE
  - Status: 🔐 Sandboxed
  - Signature: ✅ Verified
- [2:14] Hover over "Sandboxed" badge – tooltip appears
- [2:15] Show capability tags

**VOICEOVER (continued):**
> "Plugins communicate via gRPC and have strict resource limits. 0xGen tracks metrics and performance for every plugin."

**SCREEN ACTIONS:**
- [2:20] Scroll to "Metrics" section (if visible):
  - Findings emitted: 14
  - Execution time: 2.3s
  - Memory usage: 45MB
- [2:23] Click "Configure" button (if present) to show settings
- [2:25] Settings dialog appears (show briefly, don't interact)

**PACING NOTES:**
- This section moves quickly – 30 seconds
- Focus on security indicators (sandbox, signatures)
- Don't get bogged down in configuration details

---

### [2:30-2:50] Technical Highlights (20 seconds)

**TITLE CARD:** "Built for Security & Performance"
*(2 seconds)*

**VOICEOVER:**
> "0xGen is built in Go for performance. Plugins communicate via gRPC for speed and security."

**SCREEN ACTIONS:**
- [2:32-2:38] Quick montage or keep desktop shell visible:
  - Show code editor with Go files (brief flash)
  - Show terminal with `go version` output
  - Show gRPC architecture diagram (if available) or just keep GUI visible

**VOICEOVER (continued):**
> "Every build has SLSA Level 3 provenance. That means every release is cryptographically verified, protecting against supply chain attacks."

**SCREEN ACTIONS:**
- [2:38-2:42] Switch to GitHub releases page in browser:
  - Show release artifacts
  - Highlight `.intoto.jsonl` provenance files
  - Show SLSA badge or checksum

**VOICEOVER (continued):**
> "It's Apache 2.0 licensed, so you can use it however you want – personally or commercially."

**SCREEN ACTIONS:**
- [2:45-2:48] Show LICENSE file in repository root, or
- Show GitHub repo page with license badge visible

**PACING NOTES:**
- This is a fast-paced "Why 0xGen?" pitch
- Don't linger on technical details – keep moving
- Build credibility with specifics (SLSA L3, Go, gRPC)

---

### [2:50-3:00] Call to Action (10 seconds)

**TITLE CARD:** "Get Started Today"
*(Full screen, 2 seconds)*

**VOICEOVER:**
> "The alpha is out now. Links are in the description."

**SCREEN ACTIONS:**
- [2:52] Show GitHub repository page:
  - Repo URL visible in address bar
  - Star button highlighted

**VOICEOVER (continued):**
> "Star it on GitHub if you find it useful. Join our Discord to follow development. I'm building this in public."

**SCREEN ACTIONS:**
- [2:55] Show Discord server (if available) or just display link on screen
- [2:57] Fade to end card with:
  - GitHub: github.com/RowanDark/0xgen
  - Docs: rowandark.github.io/0xgen
  - Discord: [link]

**VOICEOVER (continued):**
> "Thanks for watching!"

**SCREEN ACTIONS:**
- [2:59] Fade to black
- [3:00] End screen (YouTube end screen elements: Subscribe, related video)

**PACING NOTES:**
- Keep CTA clear and concise
- Give viewer time to see URLs
- End on positive, inviting note

---

## Timing Breakdown

| Section | Duration | Words | WPM Target |
|---------|----------|-------|------------|
| Hook | 15s | 30 | 120 |
| Launch & Interface | 15s | 28 | 112 |
| Proxy & Intercept | 45s | 98 | 131 |
| Vulnerability Scanning | 45s | 95 | 127 |
| Plugin System | 30s | 68 | 136 |
| Technical Highlights | 20s | 46 | 138 |
| Call to Action | 10s | 22 | 132 |
| **Total** | **3:00** | **387** | **129** |

**Average Speaking Rate:** 129 words per minute (ideal for technical content is 120-140 WPM)

---

## Voiceover Tips

### Preparation
- **Print script** or display on second monitor
- **Practice 3-5 times** before recording
- **Mark breathing points** (after sentences, natural pauses)
- **Highlight emphasis words** (free, AI-powered, SLSA Level 3)

### Recording
- **Posture:** Sit up straight, don't slouch
- **Distance:** 6-12 inches from microphone
- **Pace:** Slightly slower than conversation (120-140 WPM)
- **Energy:** Smile while speaking – it affects tone
- **Articulation:** Pronounce clearly, especially technical terms:
  - "SLSA" = S-L-S-A (spell it out)
  - "gRPC" = "gee-R-P-C"
  - "0xGen" = "zero-ex-gen"

### Common Mistakes
- ❌ **Rushing:** Take your time, breathe
- ❌ **Monotone:** Vary pitch and energy
- ❌ **Filler words:** Edit out "um", "uh", "so", "like"
- ❌ **Mouth noises:** Stay hydrated, avoid smacking lips
- ❌ **Background noise:** Turn off fans, close windows

### Retakes
- **Don't start over** for small mistakes
- **Pause, then repeat sentence** – easier to edit
- **Mark good takes** in recording software
- **Record multiple versions** of key phrases

---

## Screen Recording Tips

### Before Recording
- **Close unnecessary apps:** Email, Slack, notifications
- **Clean desktop:** Hide icons, use neutral wallpaper
- **Set resolution:** 1920x1080
- **Increase font sizes:** Terminal, code editor (14-16pt)
- **Disable animations:** Reduce window effects (optional)

### During Recording
- **Cursor speed:** Slow, deliberate movements
- **Click pauses:** Wait 1 second after clicks for UI response
- **Typing speed:** Slower than normal, but not unnaturally slow
- **Window focus:** Keep 0xGen window centered and full-screen
- **Avoid mistakes:** Hard to fix in post – practice beforehand

### Common Issues
- **Lag:** Lower frame rate to 30fps, close background apps
- **Cursor disappears:** Use cursor highlighting in OBS
- **Text too small:** Zoom in during editing
- **Off-screen actions:** Keep important actions in center of frame

---

## Alternative Script (Shorter Version: 2:30)

If you need to fit into exactly 2:30 minutes, use this condensed version:

**Cuts to make:**
- Reduce Proxy & Intercept section from 45s to 30s (skip diff comparison)
- Reduce Vulnerability Scanning from 45s to 30s (skip HTML report export)
- Reduce Plugin System from 30s to 20s (skip metrics display)

**New timing:**
- Hook: 15s
- Launch & Interface: 15s
- Proxy & Intercept: 30s (cut -15s)
- Vulnerability Scanning: 30s (cut -15s)
- Plugin System: 20s (cut -10s)
- Technical Highlights: 20s
- Call to Action: 10s
- **Total: 2:20** (allows 10s buffer)

---

## Video Chapters (for YouTube Description)

Add these timestamps to YouTube description for easier navigation:

```
Chapters:
0:00 Introduction
0:15 Launch & Interface Tour
0:30 Proxy & HTTP Interception
1:15 AI Vulnerability Scanning
2:00 Plugin Ecosystem
2:30 Technical Architecture
2:50 Get Started
```

---

## Additional Notes

### Accessibility
- Speak all important UI actions aloud ("Now I'm clicking the Scan button...")
- Describe visual elements ("The finding appears in red, indicating high severity...")
- Use captions to reinforce technical terms

### Brand Consistency
- Always say "zero-ex-gen" not "oh-ex-gen"
- Emphasize "open-source" and "free"
- Mention "Apache 2.0" and "SLSA Level 3" (differentiators)

### Engagement
- **Use "we" and "let's"** (inclusive, collaborative)
- **Show enthusiasm** without being over-the-top
- **Ask implicit questions** ("What if we modify this parameter?")
- **End with invitation** ("Join us", "Star if you find this useful")

---

## Script Version

**Version:** 1.0
**Duration Target:** 3:00 minutes (2:30-3:30 acceptable)
**Word Count:** 387 words
**Last Updated:** 2025-11-13

**Related Documents:**
- `DEMO_VIDEO_PRODUCTION_GUIDE.md` – Full production instructions
- `TEST_ENVIRONMENT_SETUP.md` – Test target configuration
- `YOUTUBE_METADATA.md` – Upload metadata and distribution

---

Good luck with your recording! 🎬
