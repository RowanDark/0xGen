package main

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"
)

func TestNewBuilder(t *testing.T) {
	t.Parallel()

	b := NewBuilder()
	if b == nil {
		t.Fatal("NewBuilder returned nil")
	}
	if b.graph == nil {
		t.Fatal("Builder graph is nil")
	}
	if b.graph.Nodes == nil {
		t.Fatal("Graph nodes map is nil")
	}
	if b.graph.Edges == nil {
		t.Fatal("Graph edges slice is nil")
	}
}

func TestBuilderAddRequestNilRequest(t *testing.T) {
	t.Parallel()

	b := NewBuilder()
	err := b.AddRequest(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil request, got nil")
	}
}

func TestBuilderAddRequestNilResponse(t *testing.T) {
	t.Parallel()

	b := NewBuilder()
	req := &http.Request{
		URL: mustParseURL("https://example.com/page"),
	}

	err := b.AddRequest(req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should create the source node but no edges
	graph := b.GetGraph()
	if len(graph.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(graph.Nodes))
	}
	if len(graph.Edges) != 0 {
		t.Fatalf("expected 0 edges, got %d", len(graph.Edges))
	}
}

func TestBuilderAddRequestSimpleHTML(t *testing.T) {
	t.Parallel()

	b := NewBuilder()
	reqURL := mustParseURL("https://example.com/page")
	req := &http.Request{URL: reqURL}

	htmlContent := `<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
	<a href="/about">About</a>
	<a href="https://example.com/contact">Contact</a>
	<a href="https://external.com/link">External</a>
</body>
</html>`

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(bytes.NewBufferString(htmlContent)),
		Request:    req,
	}

	err := b.AddRequest(req, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	graph := b.GetGraph()
	// Should have: source page + 3 links = 4 nodes
	if len(graph.Nodes) != 4 {
		t.Fatalf("expected 4 nodes, got %d", len(graph.Nodes))
	}

	// Should have 3 edges (from page to each link)
	if len(graph.Edges) != 3 {
		t.Fatalf("expected 3 edges, got %d", len(graph.Edges))
	}

	// Verify edges point to correct targets
	sourceID := normalizeURL("https://example.com/page")
	aboutID := normalizeURL("https://example.com/about")
	contactID := normalizeURL("https://example.com/contact")
	externalID := normalizeURL("https://external.com/link")

	edgeTargets := make(map[string]bool)
	for _, edge := range graph.Edges {
		if edge.From != sourceID {
			t.Errorf("expected edge from %s, got %s", sourceID, edge.From)
		}
		edgeTargets[edge.To] = true
	}

	expectedTargets := []string{aboutID, contactID, externalID}
	for _, target := range expectedTargets {
		if !edgeTargets[target] {
			t.Errorf("missing edge to %s", target)
		}
	}
}

func TestBuilderAddRequestRelativeURLs(t *testing.T) {
	t.Parallel()

	b := NewBuilder()
	reqURL := mustParseURL("https://example.com/section/page.html")
	req := &http.Request{URL: reqURL}

	htmlContent := `<!DOCTYPE html>
<html>
<body>
	<a href="other.html">Relative</a>
	<a href="/root.html">Root Relative</a>
	<a href="../parent.html">Parent</a>
	<a href="./same.html">Same Dir</a>
</body>
</html>`

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(bytes.NewBufferString(htmlContent)),
		Request:    req,
	}

	err := b.AddRequest(req, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	graph := b.GetGraph()

	// Check that all URLs were resolved correctly
	expectedURLs := map[string]bool{
		"https://example.com/section/page.html": true,  // source
		"https://example.com/section/other.html": true, // relative
		"https://example.com/root.html":          true, // root relative
		"https://example.com/parent.html":        true, // parent
		"https://example.com/section/same.html":  true, // same dir
	}

	for id := range graph.Nodes {
		// Normalize for comparison
		found := false
		for expectedURL := range expectedURLs {
			if normalizeURL(expectedURL) == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("unexpected node URL: %s", id)
		}
	}

	if len(graph.Nodes) != 5 {
		t.Fatalf("expected 5 nodes, got %d", len(graph.Nodes))
	}
}

func TestBuilderAddRequestIgnoresInvalidSchemes(t *testing.T) {
	t.Parallel()

	b := NewBuilder()
	reqURL := mustParseURL("https://example.com/page")
	req := &http.Request{URL: reqURL}

	htmlContent := `<!DOCTYPE html>
<html>
<body>
	<a href="javascript:alert('xss')">JS</a>
	<a href="mailto:test@example.com">Email</a>
	<a href="tel:+1234567890">Phone</a>
	<a href="data:text/plain,hello">Data</a>
	<a href="https://example.com/valid">Valid</a>
</body>
</html>`

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(bytes.NewBufferString(htmlContent)),
		Request:    req,
	}

	err := b.AddRequest(req, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	graph := b.GetGraph()

	// Should only have source + valid link = 2 nodes
	if len(graph.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(graph.Nodes))
	}

	// Should only have 1 edge (to valid link)
	if len(graph.Edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(graph.Edges))
	}
}

func TestBuilderAddRequestDeduplicatesLinks(t *testing.T) {
	t.Parallel()

	b := NewBuilder()
	reqURL := mustParseURL("https://example.com/page")
	req := &http.Request{URL: reqURL}

	htmlContent := `<!DOCTYPE html>
<html>
<body>
	<a href="/about">About 1</a>
	<a href="/about">About 2</a>
	<a href="/about">About 3</a>
	<a href="/contact">Contact</a>
</body>
</html>`

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(bytes.NewBufferString(htmlContent)),
		Request:    req,
	}

	err := b.AddRequest(req, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	graph := b.GetGraph()

	// Should have: source + about + contact = 3 nodes
	if len(graph.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(graph.Nodes))
	}

	// Should have 2 unique edges (one to /about, one to /contact)
	// Note: Current implementation may create multiple edges to same target
	// This is acceptable for weighted graphs
	if len(graph.Edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(graph.Edges))
	}
}

func TestBuilderAddRequestSkipsNonHTMLResponses(t *testing.T) {
	t.Parallel()

	b := NewBuilder()
	reqURL := mustParseURL("https://example.com/api/data")
	req := &http.Request{URL: reqURL}

	jsonContent := `{"key": "value"}`

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(jsonContent)),
		Request:    req,
	}

	err := b.AddRequest(req, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	graph := b.GetGraph()

	// Should only create source node, no edges
	if len(graph.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(graph.Nodes))
	}
	if len(graph.Edges) != 0 {
		t.Fatalf("expected 0 edges, got %d", len(graph.Edges))
	}
}

func TestBuilderAddRequestSkipsErrorResponses(t *testing.T) {
	t.Parallel()

	b := NewBuilder()
	reqURL := mustParseURL("https://example.com/page")
	req := &http.Request{URL: reqURL}

	htmlContent := `<html><body><a href="/link">Link</a></body></html>`

	resp := &http.Response{
		StatusCode: http.StatusNotFound,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(bytes.NewBufferString(htmlContent)),
		Request:    req,
	}

	err := b.AddRequest(req, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	graph := b.GetGraph()

	// Should only create source node, no edges due to 404 status
	if len(graph.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(graph.Nodes))
	}
	if len(graph.Edges) != 0 {
		t.Fatalf("expected 0 edges, got %d", len(graph.Edges))
	}
}

func TestBuilderAddRequestParsesResourceLinks(t *testing.T) {
	t.Parallel()

	b := NewBuilder()
	reqURL := mustParseURL("https://example.com/page.html")
	req := &http.Request{URL: reqURL}

	htmlContent := `<!DOCTYPE html>
<html>
<head>
	<link rel="stylesheet" href="/style.css">
	<script src="/script.js"></script>
</head>
<body>
	<img src="/image.png" alt="Image">
</body>
</html>`

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(bytes.NewBufferString(htmlContent)),
		Request:    req,
	}

	err := b.AddRequest(req, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	graph := b.GetGraph()

	// Should have: source + style.css + script.js + image.png = 4 nodes
	if len(graph.Nodes) != 4 {
		t.Fatalf("expected 4 nodes, got %d", len(graph.Nodes))
	}

	// Should have 3 edges
	if len(graph.Edges) != 3 {
		t.Fatalf("expected 3 edges, got %d", len(graph.Edges))
	}
}

func TestResolveHTMLLink(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		base     string
		href     string
		expected string
	}{
		{
			name:     "absolute URL",
			base:     "https://example.com/page",
			href:     "https://other.com/path",
			expected: "https://other.com/path",
		},
		{
			name:     "relative path",
			base:     "https://example.com/section/page",
			href:     "other",
			expected: "https://example.com/section/other",
		},
		{
			name:     "root relative",
			base:     "https://example.com/section/page",
			href:     "/root",
			expected: "https://example.com/root",
		},
		{
			name:     "parent directory",
			base:     "https://example.com/section/sub/page",
			href:     "../parent",
			expected: "https://example.com/section/parent",
		},
		{
			name:     "same directory",
			base:     "https://example.com/section/page",
			href:     "./same",
			expected: "https://example.com/section/same",
		},
		{
			name:     "javascript scheme",
			base:     "https://example.com/page",
			href:     "javascript:alert('xss')",
			expected: "",
		},
		{
			name:     "mailto scheme",
			base:     "https://example.com/page",
			href:     "mailto:test@example.com",
			expected: "",
		},
		{
			name:     "empty href",
			base:     "https://example.com/page",
			href:     "",
			expected: "",
		},
		{
			name:     "whitespace href",
			base:     "https://example.com/page",
			href:     "  ",
			expected: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			base := mustParseURL(tt.base)
			result := resolveHTMLLink(base, tt.href)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestNormalizeURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "removes fragment",
			input:    "https://example.com/page#section",
			expected: "https://example.com/page",
		},
		{
			name:     "removes trailing slash",
			input:    "https://example.com/page/",
			expected: "https://example.com/page",
		},
		{
			name:     "preserves root slash",
			input:    "https://example.com/",
			expected: "https://example.com/",
		},
		{
			name:     "preserves query",
			input:    "https://example.com/page?key=value",
			expected: "https://example.com/page?key=value",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := normalizeURL(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
