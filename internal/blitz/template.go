package blitz

import (
	"fmt"
	"strings"
)

// ParseMarkers interprets a specification describing marker delimiters.
// Examples: "{{}}",  "§§", "{{ }}" (space-separated).
func ParseMarkers(spec string) (Markers, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return Markers{Open: "{{", Close: "}}"}, nil
	}

	// Space-separated format
	if strings.Contains(spec, " ") {
		parts := strings.Fields(spec)
		if len(parts) != 2 {
			return Markers{}, fmt.Errorf("space-separated markers must contain exactly two tokens")
		}
		return Markers{Open: parts[0], Close: parts[1]}, nil
	}

	// Single string format (split in half)
	if len(spec)%2 != 0 {
		return Markers{}, fmt.Errorf("marker spec %q must have even length or be space-separated", spec)
	}
	half := len(spec) / 2
	return Markers{Open: spec[:half], Close: spec[half:]}, nil
}

// ParseRequest parses an HTTP request template and identifies insertion points.
func ParseRequest(raw string, markers Markers) (*Request, error) {
	if markers.Open == "" || markers.Close == "" {
		return nil, fmt.Errorf("markers must not be empty")
	}

	var positions []Position
	cursor := 0

	for cursor < len(raw) {
		start := strings.Index(raw[cursor:], markers.Open)
		if start == -1 {
			break
		}
		start += cursor

		end := strings.Index(raw[start+len(markers.Open):], markers.Close)
		if end == -1 {
			return nil, fmt.Errorf("unclosed marker starting at offset %d", start)
		}
		end += start + len(markers.Open)

		content := raw[start+len(markers.Open) : end]
		name := strings.TrimSpace(content)

		positions = append(positions, Position{
			Index:   len(positions),
			Name:    name,
			Default: content, // Preserve original content (with whitespace)
		})

		cursor = end + len(markers.Close)
	}

	return &Request{
		Raw:       raw,
		Positions: positions,
		Markers:   markers,
	}, nil
}

// Render replaces positions in the template with the provided payloads.
// payloadMap maps position indices to their payload values.
func (r *Request) Render(payloadMap map[int]string) string {
	result := r.Raw

	// Replace in reverse order to maintain correct offsets
	for i := len(r.Positions) - 1; i >= 0; i-- {
		pos := r.Positions[i]

		// Determine replacement value
		replacement := pos.Default
		if payload, ok := payloadMap[pos.Index]; ok {
			replacement = payload
		}

		// Find this position's marker in the template
		needle := r.Markers.Open + pos.Default + r.Markers.Close

		// Replace the first occurrence (from the end due to reverse iteration)
		lastIdx := strings.LastIndex(result, needle)
		if lastIdx != -1 {
			result = result[:lastIdx] + replacement + result[lastIdx+len(needle):]
		}
	}

	return result
}

// RenderSingle replaces a single position with a payload, leaving others at defaults.
func (r *Request) RenderSingle(positionIdx int, payload string) string {
	payloadMap := map[int]string{positionIdx: payload}
	return r.Render(payloadMap)
}

// RenderAll replaces all positions with the same payload.
func (r *Request) RenderAll(payload string) string {
	payloadMap := make(map[int]string, len(r.Positions))
	for _, pos := range r.Positions {
		payloadMap[pos.Index] = payload
	}
	return r.Render(payloadMap)
}

// RenderDefault returns the request with all markers replaced by their defaults.
func (r *Request) RenderDefault() string {
	return r.Render(nil)
}

// CountPositions returns the number of insertion points.
func (r *Request) CountPositions() int {
	return len(r.Positions)
}
