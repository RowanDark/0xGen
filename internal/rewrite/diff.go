package rewrite

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// generateRequestDiff compares two requests and returns the differences.
func (s *Sandbox) generateRequestDiff(original, modified *http.Request) *DiffResult {
	diff := &DiffResult{
		HeaderChanges: make([]HeaderDiff, 0),
	}

	// Compare URLs
	if original.URL.String() != modified.URL.String() {
		diff.URLChanged = true
		diff.URLDiff = fmt.Sprintf("- %s\n+ %s", original.URL.String(), modified.URL.String())
	}

	// Compare headers
	diff.HeaderChanges = compareHeaders(original.Header, modified.Header)

	// Compare bodies
	originalBody, _ := io.ReadAll(original.Body)
	modifiedBody, _ := io.ReadAll(modified.Body)
	original.Body = io.NopCloser(bytes.NewReader(originalBody))
	modified.Body = io.NopCloser(bytes.NewReader(modifiedBody))

	if !bytes.Equal(originalBody, modifiedBody) {
		diff.BodyChanged = true
		diff.BodyDiff = generateTextDiff(string(originalBody), string(modifiedBody))
	}

	return diff
}

// generateResponseDiff compares two responses and returns the differences.
func (s *Sandbox) generateResponseDiff(original, modified *http.Response) *DiffResult {
	diff := &DiffResult{
		HeaderChanges: make([]HeaderDiff, 0),
	}

	// Compare status codes
	if original.StatusCode != modified.StatusCode {
		diff.StatusChanged = true
		diff.OldStatus = original.StatusCode
		diff.NewStatus = modified.StatusCode
	}

	// Compare headers
	diff.HeaderChanges = compareHeaders(original.Header, modified.Header)

	// Compare bodies
	originalBody, _ := io.ReadAll(original.Body)
	modifiedBody, _ := io.ReadAll(modified.Body)
	original.Body = io.NopCloser(bytes.NewReader(originalBody))
	modified.Body = io.NopCloser(bytes.NewReader(modifiedBody))

	if !bytes.Equal(originalBody, modifiedBody) {
		diff.BodyChanged = true
		diff.BodyDiff = generateTextDiff(string(originalBody), string(modifiedBody))
	}

	return diff
}

// compareHeaders compares two sets of headers and returns the differences.
func compareHeaders(original, modified http.Header) []HeaderDiff {
	diffs := make([]HeaderDiff, 0)

	// Track all header names
	allHeaders := make(map[string]bool)
	for name := range original {
		allHeaders[name] = true
	}
	for name := range modified {
		allHeaders[name] = true
	}

	// Compare each header
	for name := range allHeaders {
		originalValue := original.Get(name)
		modifiedValue := modified.Get(name)

		if originalValue == "" && modifiedValue != "" {
			// Header added
			diffs = append(diffs, HeaderDiff{
				Name:     name,
				OldValue: "",
				NewValue: modifiedValue,
				Action:   "added",
			})
		} else if originalValue != "" && modifiedValue == "" {
			// Header removed
			diffs = append(diffs, HeaderDiff{
				Name:     name,
				OldValue: originalValue,
				NewValue: "",
				Action:   "removed",
			})
		} else if originalValue != modifiedValue {
			// Header modified
			diffs = append(diffs, HeaderDiff{
				Name:     name,
				OldValue: originalValue,
				NewValue: modifiedValue,
				Action:   "modified",
			})
		}
	}

	return diffs
}

// generateTextDiff generates a simple unified diff between two text strings.
func generateTextDiff(original, modified string) string {
	if original == modified {
		return ""
	}

	// Simple line-by-line diff
	originalLines := strings.Split(original, "\n")
	modifiedLines := strings.Split(modified, "\n")

	var diff strings.Builder

	// If the texts are very different, just show full replacement
	if len(originalLines) > 100 || len(modifiedLines) > 100 {
		diff.WriteString(fmt.Sprintf("--- Original (%d bytes)\n", len(original)))
		diff.WriteString(fmt.Sprintf("+++ Modified (%d bytes)\n", len(modified)))
		diff.WriteString("\n[Large change - showing summary only]\n")
		diff.WriteString(fmt.Sprintf("Original: %d lines\n", len(originalLines)))
		diff.WriteString(fmt.Sprintf("Modified: %d lines\n", len(modifiedLines)))
		return diff.String()
	}

	// Simple unified diff format
	diff.WriteString("--- Original\n")
	diff.WriteString("+++ Modified\n")

	// Use a simple LCS-based diff
	maxLen := len(originalLines)
	if len(modifiedLines) > maxLen {
		maxLen = len(modifiedLines)
	}

	for i := 0; i < maxLen; i++ {
		if i < len(originalLines) && i < len(modifiedLines) {
			if originalLines[i] != modifiedLines[i] {
				diff.WriteString(fmt.Sprintf("- %s\n", originalLines[i]))
				diff.WriteString(fmt.Sprintf("+ %s\n", modifiedLines[i]))
			} else {
				diff.WriteString(fmt.Sprintf("  %s\n", originalLines[i]))
			}
		} else if i < len(originalLines) {
			diff.WriteString(fmt.Sprintf("- %s\n", originalLines[i]))
		} else if i < len(modifiedLines) {
			diff.WriteString(fmt.Sprintf("+ %s\n", modifiedLines[i]))
		}
	}

	return diff.String()
}

// DiffSummary provides a high-level summary of changes.
type DiffSummary struct {
	TotalChanges   int      `json:"total_changes"`
	HeadersAdded   int      `json:"headers_added"`
	HeadersRemoved int      `json:"headers_removed"`
	HeadersChanged int      `json:"headers_changed"`
	BodyChanged    bool     `json:"body_changed"`
	URLChanged     bool     `json:"url_changed"`
	StatusChanged  bool     `json:"status_changed"`
	ChangedBy      []string `json:"changed_by"` // Rule names that caused changes
}

// GetDiffSummary generates a summary of the diff.
func (d *DiffResult) GetSummary() *DiffSummary {
	summary := &DiffSummary{
		ChangedBy: make([]string, 0),
	}

	for _, h := range d.HeaderChanges {
		switch h.Action {
		case "added":
			summary.HeadersAdded++
		case "removed":
			summary.HeadersRemoved++
		case "modified":
			summary.HeadersChanged++
		}
	}

	summary.TotalChanges = summary.HeadersAdded + summary.HeadersRemoved + summary.HeadersChanged
	summary.BodyChanged = d.BodyChanged
	summary.URLChanged = d.URLChanged
	summary.StatusChanged = d.StatusChanged

	if d.BodyChanged {
		summary.TotalChanges++
	}
	if d.URLChanged {
		summary.TotalChanges++
	}
	if d.StatusChanged {
		summary.TotalChanges++
	}

	return summary
}

// IsEmpty returns true if there are no changes.
func (d *DiffResult) IsEmpty() bool {
	return len(d.HeaderChanges) == 0 && !d.BodyChanged && !d.URLChanged && !d.StatusChanged
}
