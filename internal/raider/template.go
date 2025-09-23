package raider

import (
	"fmt"
	"strings"
)

// Markers defines the delimiters used to mark payload insertion points.
type Markers struct {
	Open  string
	Close string
}

// ParseMarkers interprets a specification describing the opening and closing
// marker delimiters. The default markers are "{{" and "}}".
func ParseMarkers(spec string) (Markers, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return Markers{Open: "{{", Close: "}}"}, nil
	}
	if strings.Contains(spec, " ") {
		parts := strings.Fields(spec)
		if len(parts) != 2 {
			return Markers{}, fmt.Errorf("positions must contain exactly two markers")
		}
		return Markers{Open: parts[0], Close: parts[1]}, nil
	}
	if len(spec)%2 != 0 {
		return Markers{}, fmt.Errorf("positions marker %q must have even length or be two space separated tokens", spec)
	}
	half := len(spec) / 2
	return Markers{Open: spec[:half], Close: spec[half:]}, nil
}

// Position describes a placeholder found in the request template.
type Position struct {
	Index   int
	Name    string
	Default string
}

type segment struct {
	literal  string
	position int
}

// Template represents a parsed request template with tracked payload
// placeholders.
type Template struct {
	segments  []segment
	positions []Position
}

// Positions returns the placeholders discovered in the template.
func (t *Template) Positions() []Position {
	result := make([]Position, len(t.positions))
	copy(result, t.positions)
	return result
}

// RenderWith replaces the placeholder at the provided index with the supplied
// payload while leaving other placeholders at their default values.
func (t *Template) RenderWith(position int, payload string) string {
	var builder strings.Builder
	for _, seg := range t.segments {
		if seg.position < 0 {
			builder.WriteString(seg.literal)
			continue
		}
		pos := t.positions[seg.position]
		if pos.Index == position {
			builder.WriteString(payload)
		} else {
			builder.WriteString(pos.Default)
		}
	}
	return builder.String()
}

// RenderDefault returns the template with all placeholders replaced by their
// default values.
func (t *Template) RenderDefault() string {
	var builder strings.Builder
	for _, seg := range t.segments {
		if seg.position < 0 {
			builder.WriteString(seg.literal)
		} else {
			builder.WriteString(t.positions[seg.position].Default)
		}
	}
	return builder.String()
}

// ParseTemplate identifies the insertion points in the provided request
// template according to the supplied marker delimiters.
func ParseTemplate(input string, markers Markers) (*Template, error) {
	if markers.Open == "" || markers.Close == "" {
		return nil, fmt.Errorf("markers must not be empty")
	}

	var segments []segment
	var positions []Position
	cursor := 0
	for cursor < len(input) {
		start := strings.Index(input[cursor:], markers.Open)
		if start == -1 {
			segments = append(segments, segment{literal: input[cursor:], position: -1})
			break
		}
		start += cursor
		if start > cursor {
			segments = append(segments, segment{literal: input[cursor:start], position: -1})
		}
		end := strings.Index(input[start+len(markers.Open):], markers.Close)
		if end == -1 {
			return nil, fmt.Errorf("unclosed marker starting at offset %d", start)
		}
		end += start + len(markers.Open)
		name := input[start+len(markers.Open) : end]
		trimmed := strings.TrimSpace(name)
		pos := Position{Index: len(positions), Name: trimmed, Default: name}
		positions = append(positions, pos)
		segments = append(segments, segment{position: len(positions) - 1})
		cursor = end + len(markers.Close)
	}

	return &Template{segments: segments, positions: positions}, nil
}
