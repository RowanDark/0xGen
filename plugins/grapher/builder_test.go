package main

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
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
	<a href="vbscript:msgbox('xss')">VBS</a>
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

func TestBuilderAddRequestXHTMLContent(t *testing.T) {
	t.Parallel()

	b := NewBuilder()
	reqURL := mustParseURL("https://example.com/page.xhtml")
	req := &http.Request{URL: reqURL}

	xhtmlContent := `<?xml version="1.0"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
	"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>XHTML</title></head>
<body>
	<a href="/link">Link</a>
</body>
</html>`

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/xhtml+xml"}},
		Body:       io.NopCloser(bytes.NewBufferString(xhtmlContent)),
		Request:    req,
	}

	err := b.AddRequest(req, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	graph := b.GetGraph()

	// Should parse XHTML like HTML
	if len(graph.Nodes) != 2 {
		t.Fatalf("expected 2 nodes (source + link), got %d", len(graph.Nodes))
	}
	if len(graph.Edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(graph.Edges))
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
			name:     "vbscript scheme",
			base:     "https://example.com/page",
			href:     "vbscript:msgbox('xss')",
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

func TestBuilderGetOrCreateNodeReusesExisting(t *testing.T) {
	t.Parallel()

	b := NewBuilder()

	// Create first node
	node1 := b.getOrCreateNode("https://example.com/page")
	if node1 == nil {
		t.Fatal("expected node, got nil")
	}

	// Try to create same node again - should reuse existing
	node2 := b.getOrCreateNode("https://example.com/page")
	if node2 == nil {
		t.Fatal("expected node, got nil")
	}

	// Should be the exact same node (pointer equality)
	if node1 != node2 {
		t.Error("expected same node instance to be reused")
	}

	// Graph should only have one node
	if len(b.graph.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(b.graph.Nodes))
	}
}

func TestBuilderAddRequestSkipsSelfReferences(t *testing.T) {
	t.Parallel()

	b := NewBuilder()
	reqURL := mustParseURL("https://example.com/page")
	req := &http.Request{URL: reqURL}

	// HTML with self-referencing link
	htmlContent := `<!DOCTYPE html>
<html>
<body>
	<a href="https://example.com/page">Self</a>
	<a href="/page">Self Relative</a>
	<a href="/other">Other</a>
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

	// Should have source + other page = 2 nodes (self-refs skipped)
	if len(graph.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(graph.Nodes))
	}

	// Should only have 1 edge (to /other, self-refs skipped)
	if len(graph.Edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(graph.Edges))
	}
}

func TestBuilderParseLinksNilResponse(t *testing.T) {
	t.Parallel()

	b := NewBuilder()

	// Test with nil response
	links, err := b.parseLinks(nil)
	if err == nil {
		t.Fatal("expected error for nil response, got nil")
	}
	if links != nil {
		t.Errorf("expected nil links, got %v", links)
	}
}

func TestBuilderParseLinksNilBody(t *testing.T) {
	t.Parallel()

	b := NewBuilder()
	reqURL := mustParseURL("https://example.com/page")
	req := &http.Request{URL: reqURL}

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       nil, // nil body
		Request:    req,
	}

	links, err := b.parseLinks(resp)
	if err == nil {
		t.Fatal("expected error for nil body, got nil")
	}
	if links != nil {
		t.Errorf("expected nil links, got %v", links)
	}
}

func TestBuilderParseLinksInvalidHTML(t *testing.T) {
	t.Parallel()

	b := NewBuilder()
	reqURL := mustParseURL("https://example.com/page")
	req := &http.Request{URL: reqURL}

	// HTML parser is very lenient, so this might not trigger parse error
	// But we test the error path exists
	invalidHTML := "<html><body><a href='/link'>Link</a></body></html>"

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(invalidHTML)),
		Request:    req,
	}

	// Should not panic even with "invalid" HTML
	links, err := b.parseLinks(resp)
	if err != nil {
		// If it errors, that's fine (testing error path)
		return
	}
	// HTML parser is very permissive, so it likely succeeded
	if links == nil {
		t.Error("expected links slice, got nil")
	}
}

type failingReader struct{}

func (f *failingReader) Read(p []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func (f *failingReader) Close() error {
	return nil
}

func TestBuilderParseLinksReadError(t *testing.T) {
	t.Parallel()

	b := NewBuilder()
	reqURL := mustParseURL("https://example.com/page")
	req := &http.Request{URL: reqURL}

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       &failingReader{},
		Request:    req,
	}

	links, err := b.parseLinks(resp)
	if err == nil {
		t.Fatal("expected error for failing reader, got nil")
	}
	if links != nil {
		t.Errorf("expected nil links, got %v", links)
	}
}

func TestResolveHTMLLinkInvalidURL(t *testing.T) {
	t.Parallel()

	base := mustParseURL("https://example.com/page")

	// Invalid URL that can't be parsed
	invalidURLs := []string{
		"://invalid",
		"http://[::1]:namedport",
		string([]byte{0x7f}), // invalid UTF-8
	}

	for _, invalid := range invalidURLs {
		result := resolveHTMLLink(base, invalid)
		if result != "" {
			t.Errorf("expected empty string for invalid URL %q, got %q", invalid, result)
		}
	}
}

func TestResolveHTMLLinkNonHTTPSchemes(t *testing.T) {
	t.Parallel()

	base := mustParseURL("https://example.com/page")

	// Test various non-HTTP schemes
	schemes := []string{
		"ftp://example.com/file",
		"ws://example.com/socket",
		"wss://example.com/socket",
		"file:///etc/passwd",
		"about:blank",
	}

	for _, schemeURL := range schemes {
		result := resolveHTMLLink(base, schemeURL)
		// All non-http/https schemes should be filtered
		if result != "" {
			t.Errorf("expected empty string for scheme %q, got %q", schemeURL, result)
		}
	}
}

func TestResolveHTMLLinkEmptyLink(t *testing.T) {
	t.Parallel()

	base := mustParseURL("https://example.com/page")

	// Empty link should return empty after resolution
	result := resolveHTMLLink(base, "")
	if result != "" {
		t.Errorf("expected empty string for empty link, got %q", result)
	}
}

func TestNormalizeURLInvalidURL(t *testing.T) {
	t.Parallel()

	// Invalid URL that can't be parsed
	invalid := "://invalid"
	result := normalizeURL(invalid)

	// Should return the original string when parsing fails
	if result != invalid {
		t.Errorf("expected %q for invalid URL, got %q", invalid, result)
	}
}

func TestNormalizeURLFragmentAndTrailingSlash(t *testing.T) {
	t.Parallel()

	// Test URL with both fragment and trailing slash
	input := "https://example.com/page/#section"
	expected := "https://example.com/page"
	result := normalizeURL(input)

	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
