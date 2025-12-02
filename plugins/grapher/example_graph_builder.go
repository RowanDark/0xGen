package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ExampleGraphBuilder demonstrates how to use the graph builder
// to construct a sitemap from HTTP requests and responses
func ExampleGraphBuilder() {
	// Create a new builder
	builder := NewBuilder()

	// Simulate crawling a website
	// Request 1: Homepage
	req1, _ := http.NewRequest("GET", "https://example.com/", nil)
	resp1 := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body: io.NopCloser(strings.NewReader(`
			<html>
			<body>
				<a href="/about">About</a>
				<a href="/contact">Contact</a>
				<a href="/blog">Blog</a>
			</body>
			</html>
		`)),
		Request: req1,
	}
	builder.AddRequest(req1, resp1)

	// Request 2: About page
	req2, _ := http.NewRequest("GET", "https://example.com/about", nil)
	resp2 := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body: io.NopCloser(strings.NewReader(`
			<html>
			<body>
				<a href="/">Home</a>
				<a href="/contact">Contact</a>
			</body>
			</html>
		`)),
		Request: req2,
	}
	builder.AddRequest(req2, resp2)

	// Get the resulting graph
	graph := builder.GetGraph()

	// Print graph statistics
	fmt.Printf("Discovered %d nodes (URLs)\n", len(graph.Nodes))
	fmt.Printf("Found %d edges (links)\n", len(graph.Edges))

	// List all discovered URLs
	fmt.Println("\nDiscovered URLs:")
	for _, node := range graph.Nodes {
		fmt.Printf("  - %s\n", node.URL)
	}

	// List all links
	fmt.Println("\nLinks:")
	for _, edge := range graph.Edges {
		fromNode, _ := graph.GetNode(edge.From)
		toNode, _ := graph.GetNode(edge.To)
		fmt.Printf("  %s -> %s\n", fromNode.URL, toNode.URL)
	}

	// Output:
	// Discovered 5 nodes (URLs)
	// Found 5 edges (links)
	//
	// Discovered URLs:
	//   - https://example.com/
	//   - https://example.com/about
	//   - https://example.com/contact
	//   - https://example.com/blog
	//   - https://example.com/
	//
	// Links:
	//   https://example.com/ -> https://example.com/about
	//   https://example.com/ -> https://example.com/contact
	//   https://example.com/ -> https://example.com/blog
	//   https://example.com/about -> https://example.com/
	//   https://example.com/about -> https://example.com/contact
}
