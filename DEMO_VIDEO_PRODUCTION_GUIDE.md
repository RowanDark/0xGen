# 0xGen Demo Video Production Guide

**Issue #9: Demo Video Production**
**Target Duration:** 2:30-3:30 minutes
**Resolution:** 1080p (1920x1080)
**Format:** MP4

---

## Table of Contents

1. [Overview](#overview)
2. [Pre-Production Checklist](#pre-production-checklist)
3. [Equipment & Software](#equipment--software)
4. [Test Environment Setup](#test-environment-setup)
5. [Recording Process](#recording-process)
6. [Post-Production](#post-production)
7. [Distribution](#distribution)
8. [Quality Checklist](#quality-checklist)

---

## Overview

This guide provides step-by-step instructions for producing a professional demo video showcasing 0xGen's core capabilities. The video will serve as the primary marketing asset for the alpha launch.

**Target Audience:** Security professionals, penetration testers, developers interested in security tooling

**Key Message:** 0xGen is a free, open-source, AI-powered security testing platform with enterprise-grade supply chain security.

---

## Pre-Production Checklist

### Environment Preparation

- [ ] Install and configure 0xgenctl
- [ ] Set up test target (DVWA or OWASP Juice Shop)
- [ ] Install desktop shell (`apps/desktop-shell`)
- [ ] Configure browser proxy settings
- [ ] Test all features to be demonstrated
- [ ] Clear any sensitive data from previous testing
- [ ] Prepare a clean browser profile (no personal bookmarks/history)

### Script & Storyboard

- [ ] Review `DEMO_VIDEO_SCRIPT.md`
- [ ] Create storyboard or shot list
- [ ] Practice voiceover multiple times
- [ ] Time each segment to ensure pacing
- [ ] Identify title card insertion points

### Software Setup

- [ ] Install screen recording software (see [Equipment & Software](#equipment--software))
- [ ] Test audio recording (voiceover or live narration)
- [ ] Install video editing software
- [ ] Download royalty-free background music
- [ ] Prepare title card templates

---

## Equipment & Software

### Recording Software

**macOS:**
- **QuickTime Player** (built-in, simple)
- **OBS Studio** (free, professional features)
- **ScreenFlow** (paid, excellent editing integration)

**Windows:**
- **OBS Studio** (free, recommended)
- **Camtasia** (paid, easy to use)
- **Windows Game Bar** (built-in, basic)

**Linux:**
- **OBS Studio** (free, recommended)
- **SimpleScreenRecorder** (free, lightweight)
- **Kazam** (free, simple)

**Recording Settings:**
- Resolution: 1920x1080 (1080p)
- Frame rate: 30 fps minimum, 60 fps preferred
- Bitrate: 5-10 Mbps
- Format: MP4 (H.264)

### Audio Recording

**Hardware:**
- Phone microphone (acceptable)
- USB microphone (recommended: Blue Yeti, Audio-Technica ATR2100)
- Lavalier mic (for professional quality)

**Software:**
- **Audacity** (free, cross-platform)
- **GarageBand** (macOS, free)
- **Adobe Audition** (paid, professional)

**Audio Settings:**
- Format: WAV or FLAC (lossless)
- Sample rate: 44.1 kHz or 48 kHz
- Bit depth: 16-bit minimum, 24-bit preferred
- Record in a quiet room with minimal echo

### Video Editing

**Free Options:**
- **DaVinci Resolve** (professional, recommended)
- **iMovie** (macOS only)
- **Shotcut** (cross-platform)
- **Kdenlive** (Linux)

**Paid Options:**
- **Adobe Premiere Pro** (industry standard)
- **Final Cut Pro** (macOS only)
- **Camtasia** (easy to learn)

### Assets

**Background Music:**
- [YouTube Audio Library](https://studio.youtube.com) (royalty-free)
- [Incompetech](https://incompetech.com) (free with attribution)
- [Purple Planet Music](https://www.purple-planet.com) (free)

**Recommended tracks:**
- Upbeat, tech-focused, minimal vocals
- 80-100 BPM
- Electronic or ambient genres
- Low volume during narration (ducking at -20dB to -30dB)

---

## Test Environment Setup

See `TEST_ENVIRONMENT_SETUP.md` for detailed instructions on:

- Installing OWASP Juice Shop (recommended for demo)
- Installing DVWA (Damn Vulnerable Web Application)
- Configuring test targets for scanning
- Setting up proxy interception

**Quick Start (Juice Shop):**

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
```

Access at: `http://localhost:3000`

---

## Recording Process

### Session Setup

1. **Close unnecessary applications**
   - Close Slack, email, notifications
   - Use "Do Not Disturb" mode
   - Close browser tabs not needed for demo

2. **Prepare desktop**
   - Clean desktop wallpaper (solid color or minimal)
   - Hide desktop icons
   - Set screen resolution to 1920x1080
   - Increase font sizes for readability

3. **Start services**
   ```bash
   # Start test target
   docker run -d -p 3000:3000 bkimminich/juice-shop

   # Start 0xGen daemon (if required)
   0xgenctl daemon start

   # Launch desktop shell
   cd apps/desktop-shell
   pnpm tauri:dev
   ```

4. **Configure recording software**
   - Set capture area (full screen or window)
   - Enable audio recording
   - Test recording 30 seconds, review quality
   - Adjust audio levels (voice should peak at -6dB to -12dB)

### Recording Strategy

**Option 1: Record in Segments**
- Record each section separately (Intro, Proxy, Scanning, Plugins, Outro)
- Easier to fix mistakes
- More editing work required
- **Recommended for first-time producers**

**Option 2: Record in One Take**
- Record entire demo continuously
- Requires practice and rehearsal
- Less editing work
- Use teleprompter or cue cards for script

**Option 3: Record Video + Voiceover Separately**
- Record silent screen capture
- Record voiceover later while watching video
- Best audio quality
- Can adjust timing independently
- **Recommended for professional quality**

### Script Adherence

Follow `DEMO_VIDEO_SCRIPT.md` closely:

- **[0:00-0:15]** Hook & Introduction
- **[0:15-0:30]** Launch & Interface Tour
- **[0:30-1:15]** Proxy & Intercept Demo
- **[1:15-2:00]** Vulnerability Scanning
- **[2:00-2:30]** Plugin System
- **[2:30-2:50]** Technical Highlights
- **[2:50-3:00]** Call to Action

### Recording Tips

- **Pace your speech:** Speak clearly and deliberately (not rushed)
- **Pause between sections:** Easier to edit
- **Cursor movements:** Slow, deliberate cursor movements
- **Clicks:** Pause briefly after each click for UI response
- **Zoom/Highlight:** Use editor to zoom on important UI elements
- **Mistakes:** Keep recording, fix in post-production
- **Energy:** Maintain enthusiasm throughout (smile while speaking)

### Backup Strategy

- **Save recording immediately** after completion
- **Make backup copy** to external drive or cloud storage
- **Keep raw footage** until final video is published
- **Record multiple takes** if time permits (choose best segments)

---

## Post-Production

### Import & Organization

1. **Create project structure:**
   ```
   0xGen-Demo-Video/
   ├── 01-raw-footage/
   ├── 02-audio/
   ├── 03-music/
   ├── 04-title-cards/
   ├── 05-exports/
   └── project-file.prproj
   ```

2. **Import all assets:**
   - Raw screen recordings
   - Voiceover audio (if separate)
   - Background music
   - Title card images
   - Logo/branding assets

### Editing Workflow

#### 1. Rough Cut
- Trim dead air and mistakes
- Remove long pauses
- Cut to match script timing
- Add markers for title cards
- **Goal:** Get video to ~3-4 minutes

#### 2. Fine Cut
- Smooth transitions between segments
- Add title cards (see [Title Card Specifications](#title-card-specifications))
- Synchronize voiceover with screen actions
- Remove filler words ("um", "uh")
- **Goal:** Tighten to 2:30-3:30 range

#### 3. Audio Enhancement
- **Noise reduction:** Remove background hiss
- **Normalize audio:** Consistent volume throughout
- **EQ:** Boost clarity (high-pass filter at 80Hz, presence boost at 3-5kHz)
- **Compression:** Even out volume dynamics
- **De-essing:** Reduce harsh "s" sounds

#### 4. Background Music
- Add music bed under voiceover
- **Duck music volume** during speech (-20dB to -30dB from peak)
- Fade in at start (2-3 seconds)
- Fade out at end (3-4 seconds)
- Ensure music doesn't overpower narration

#### 5. Visual Enhancements
- **Zoom effects:** Highlight important UI elements (2x zoom, 1-2 seconds)
- **Arrows/callouts:** Point to specific buttons or features (use sparingly)
- **Color correction:** Ensure consistent brightness/contrast
- **Cursor highlighting:** Add subtle cursor highlight effect (optional)
- **Lower thirds:** Add text labels for complex sections (optional)

#### 6. Title Cards
Insert title cards at key transitions:
- **[0:00]** Opening title: "0xGen: Open-Source Security Testing"
- **[0:30]** Section: "Proxy & Intercept"
- **[1:15]** Section: "AI-Powered Scanning"
- **[2:00]** Section: "Plugin Ecosystem"
- **[2:50]** Call to Action: "Star on GitHub • Join Discord"

**Duration:** 2-3 seconds per card

#### 7. Captions/Subtitles
- **Generate auto-captions** in YouTube Studio, or
- **Manually create SRT file** for accuracy
- **Review and correct** all captions
- **Export SRT** for upload with video

**Caption Style:**
- White text with black background
- Sans-serif font (Arial, Roboto)
- Centered at bottom of frame
- 2 lines maximum
- Sync precisely with audio

### Title Card Specifications

**Design Guidelines:**
- **Resolution:** 1920x1080
- **Background:** Solid dark color (match 0xGen dark theme) or gradient
- **Text:** Large, bold, sans-serif font (e.g., Inter, Roboto, Montserrat)
- **Branding:** Include 0xGen logo if available
- **Colors:** Match brand colors (dark background, accent colors for text)
- **Animation:** Simple fade in/out (0.5-1 second transitions)

**Template structure:**
```
┌─────────────────────────────────┐
│                                 │
│         [0xGen Logo]            │
│                                 │
│     Section Title Text          │
│                                 │
│                                 │
└─────────────────────────────────┘
```

**Tools for creating title cards:**
- **Canva** (free, easy templates)
- **Figma** (free, design control)
- **Photoshop** (paid, professional)
- **GIMP** (free, open-source alternative)

### Quality Control Checklist

Before exporting final video:

**Video Quality:**
- [ ] Resolution is 1920x1080
- [ ] Frame rate is consistent (30fps or 60fps)
- [ ] No compression artifacts or pixelation
- [ ] Text is readable at full screen and mobile sizes
- [ ] Color grading is consistent
- [ ] No accidental personal information visible

**Audio Quality:**
- [ ] Volume is consistent throughout
- [ ] No background noise or hiss
- [ ] Music doesn't overpower narration
- [ ] All words are clearly intelligible
- [ ] No audio clipping or distortion

**Content:**
- [ ] Follows script timing accurately
- [ ] All features are demonstrated clearly
- [ ] No mistakes or errors visible
- [ ] Captions are accurate and synchronized
- [ ] Transitions are smooth
- [ ] Duration is 2:30-3:30 minutes

**Accessibility:**
- [ ] Captions/subtitles included
- [ ] Text is high contrast and readable
- [ ] Important actions are announced verbally
- [ ] Cursor movements are visible

### Export Settings

**YouTube Upload Settings:**

```
Format: MP4
Codec: H.264
Resolution: 1920x1080
Frame Rate: 30fps or 60fps (match source)
Bitrate: 10-12 Mbps (VBR or CBR)
Audio Codec: AAC
Audio Bitrate: 192-320 kbps
Audio Sample Rate: 48kHz
```

**File Naming:**
```
0xGen-Demo-Alpha-v1.0-1080p.mp4
```

**Deliverables:**
1. **Final video:** `0xGen-Demo-Alpha-v1.0-1080p.mp4`
2. **SRT captions:** `0xGen-Demo-Alpha-v1.0-captions.srt`
3. **Thumbnail image:** `0xGen-Thumbnail-1080p.png` (1280x720)
4. **Project backup:** Archive of editing project

---

## Distribution

### YouTube Upload

See `YOUTUBE_METADATA.md` for complete upload details.

**Upload Process:**

1. **Sign in to YouTube Studio**
   - Navigate to [studio.youtube.com](https://studio.youtube.com)
   - Click "Create" → "Upload videos"

2. **Upload video file**
   - Drag `0xGen-Demo-Alpha-v1.0-1080p.mp4`
   - Wait for processing

3. **Add metadata:**
   - **Title:** "0xGen: Open-Source Security Testing Platform (Burp Suite Alternative)"
   - **Description:** See `YOUTUBE_METADATA.md`
   - **Thumbnail:** Upload custom thumbnail
   - **Playlist:** Create "0xGen Tutorials" playlist
   - **Tags:** See `YOUTUBE_METADATA.md`
   - **Category:** Science & Technology
   - **Language:** English

4. **Upload subtitles:**
   - Click "Subtitles" tab
   - Upload `0xGen-Demo-Alpha-v1.0-captions.srt`
   - Review auto-sync

5. **Set visibility:**
   - **Private** for initial review
   - **Public** after final approval

6. **YouTube SEO:**
   - Add timestamps in description (chapters)
   - Add end screen (last 20 seconds): Subscribe button, related video
   - Add cards: GitHub link at 0:30, Discord link at 2:50

### README Embed

Update `README.md` with video embed:

```markdown
## Demo Video

Watch 0xGen in action (3 minutes):

[![0xGen Demo Video](https://img.youtube.com/vi/VIDEO_ID_HERE/maxresdefault.jpg)](https://www.youtube.com/watch?v=VIDEO_ID_HERE)

*Click to watch: Proxy interception, AI-powered scanning, and plugin system overview.*
```

Replace `VIDEO_ID_HERE` with actual YouTube video ID after upload.

### Social Media

**Twitter/X Post:**
```
🚀 0xGen Alpha is live!

Open-source security testing with:
✅ AI-powered scanning
✅ HTTP proxy & intercept
✅ Plugin ecosystem
✅ SLSA L3 builds

Watch the demo 👇
[YouTube link]

#infosec #cybersecurity #opensource
```

**LinkedIn Post:**
```
I'm excited to share 0xGen Alpha – an open-source security testing platform built for modern pentesting workflows.

Key features:
• AI-powered vulnerability detection
• HTTP proxy with TLS interception
• Sandboxed plugin system with capability controls
• SLSA Level 3 build provenance for supply chain security

Built in Go, Apache 2.0 licensed. Free for personal and commercial use.

Watch the 3-minute demo: [YouTube link]
GitHub: [repo link]

#CyberSecurity #InfoSec #OpenSource #ApplicationSecurity
```

**Reddit Posts:**

- **r/netsec:** Include technical details, SLSA provenance
- **r/HowToHack:** Focus on learning features and UI
- **r/bugbounty:** Emphasize workflow integration
- **r/golang:** Highlight Go architecture and gRPC

**Hacker News Submission (Week 2):**
```
Title: Show HN: 0xGen – Open-source security testing platform with AI scanning

Link: [YouTube video URL]

Comment (first comment from submitter):
Creator here. 0xGen is a security testing platform I've been building to address gaps in existing tools. It features HTTP proxy interception, AI-powered vulnerability scanning, and a sandboxed plugin system.

Built in Go, with SLSA Level 3 provenance for supply chain security. Apache 2.0 licensed.

The desktop shell is built with Tauri + React. Plugins communicate via gRPC with capability-based security.

Happy to answer questions about the architecture, plugin SDK, or roadmap!

GitHub: [repo URL]
Docs: [docs URL]
```

### Metrics Tracking

After publishing, track:

- **YouTube Analytics:**
  - Views, watch time, audience retention graph
  - Traffic sources (external, YouTube search, suggested)
  - Demographics and geography

- **GitHub:**
  - Stars increase
  - Repo traffic (unique visitors, clones)
  - Issues/discussions activity

- **Social Media:**
  - Engagement (likes, shares, comments)
  - Click-through rate to GitHub

**Review metrics after 7 days and 30 days.**

---

## Quality Checklist

### Pre-Upload Review

- [ ] Duration is within 2:30-3:30 minute range
- [ ] All features demonstrated work correctly
- [ ] Audio is clear and professional
- [ ] Video quality is 1080p with no artifacts
- [ ] Captions are accurate and complete
- [ ] No personal information exposed
- [ ] Title cards are professional and on-brand
- [ ] Call to action is clear (GitHub star, Discord join)
- [ ] Background music enhances without distracting
- [ ] Pacing keeps viewer engaged

### Post-Upload Review

- [ ] YouTube processing complete (all resolutions available)
- [ ] Thumbnail displays correctly
- [ ] Description links are functional
- [ ] Captions are synchronized properly
- [ ] Video plays without issues
- [ ] End screen elements work
- [ ] Cards appear at correct timestamps

### Distribution Checklist

- [ ] Video uploaded to YouTube
- [ ] README.md updated with embed
- [ ] Twitter/X post published
- [ ] LinkedIn post published
- [ ] Discord announcement posted
- [ ] GitHub release notes updated (if applicable)
- [ ] Hacker News submission scheduled for Week 2

---

## Resources

### Reference Videos

Study these for pacing and style:

- **Burp Suite tutorials** (PortSwigger's official videos)
- **Caido introduction videos** (similar tool, good UI demos)
- **OWASP ZAP tutorials** (clear screen captures)
- **Product Hunt demo videos** (concise, hook-focused)

### Learning Materials

- **Video editing:** [DaVinci Resolve tutorials](https://www.youtube.com/blackmagicdesign)
- **Voiceover:** [Booth Junkie YouTube channel](https://www.youtube.com/boothjunkie)
- **Screen recording:** [OBS Studio quickstart](https://obsproject.com/wiki/OBS-Studio-Quickstart)

### Tools

- **OBS Studio:** [obsproject.com](https://obsproject.com)
- **DaVinci Resolve:** [blackmagicdesign.com](https://www.blackmagicdesign.com/products/davinciresolve)
- **Audacity:** [audacityteam.org](https://www.audacityteam.org)
- **Canva:** [canva.com](https://www.canva.com)

---

## Troubleshooting

### Common Issues

**Problem:** Screen recording is laggy or dropped frames
- **Solution:** Lower recording resolution to 720p, reduce frame rate to 30fps, close background apps, record in segments

**Problem:** Audio has background noise or echo
- **Solution:** Use noise suppression in Audacity, record in smaller room with soft furnishings, move closer to microphone

**Problem:** Video file is too large to upload
- **Solution:** Re-export with lower bitrate (8 Mbps), use H.264 instead of ProRes, compress with HandBrake

**Problem:** Text or UI elements are too small/unreadable
- **Solution:** Zoom in during editing, increase font sizes before recording, use 1920x1080 resolution consistently

**Problem:** Demo features don't work as expected during recording
- **Solution:** Practice dry run beforehand, have backup recordings, use screen freeze frames if needed

**Problem:** Video duration exceeds 3:30 minutes
- **Solution:** Trim pauses between actions, speed up slow sections (1.1x-1.2x), remove non-essential demonstrations

---

## Timeline Estimate

**Total Effort:** 3 hours (as per Issue #9)

| Task | Duration |
|------|----------|
| Pre-production (setup, practice) | 30 minutes |
| Recording (including retakes) | 45 minutes |
| Editing (rough + fine cut) | 60 minutes |
| Audio enhancement & music | 20 minutes |
| Captions & title cards | 15 minutes |
| Export & upload | 10 minutes |
| **Total** | **3 hours** |

*Note: First-time producers may need 4-5 hours. Experienced video editors can complete in 2-3 hours.*

---

## Support

Questions or issues during production?

- **GitHub Issues:** [github.com/RowanDark/0xgen/issues](https://github.com/RowanDark/0xgen/issues)
- **Discord:** (Add link when available)
- **Email:** (Add contact when available)

---

## Acceptance Criteria

Per Issue #9, the final video must meet these requirements:

- ✅ Video is 2:30-3:30 minutes long
- ✅ Shows all core features (proxy, scanning, plugins)
- ✅ Audio is clear and professional
- ✅ Includes captions/subtitles
- ✅ Embedded in README and shared on social media

**Review this checklist before marking Issue #9 as complete.**

---

**Document Version:** 1.0
**Last Updated:** 2025-11-13
**Related Files:** `DEMO_VIDEO_SCRIPT.md`, `TEST_ENVIRONMENT_SETUP.md`, `YOUTUBE_METADATA.md`
