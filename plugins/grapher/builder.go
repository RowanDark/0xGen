package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/html"
)

// Node represents a URL node in the graph
type Node struct {
	ID  string
	URL string
}

// Edge represents a connection between two nodes
type Edge struct {
	From   string
	To     string
	Type   string
	Weight int
}

// Graph holds the complete graph structure
type Graph struct {
	Nodes map[string]*Node
	Edges []*Edge
	mu    sync.RWMutex
}

// NewGraph creates a new empty graph
func NewGraph() *Graph {
	return &Graph{
		Nodes: make(map[string]*Node),
		Edges: make([]*Edge, 0),
	}
}

// AddNode adds a node to the graph if it doesn't exist
func (g *Graph) AddNode(node *Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.Nodes[node.ID]; !exists {
		g.Nodes[node.ID] = node
	}
}

// AddEdge adds an edge to the graph
func (g *Graph) AddEdge(edge *Edge) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Edges = append(g.Edges, edge)
}

// GetNode retrieves a node by ID
func (g *Graph) GetNode(id string) (*Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	node, exists := g.Nodes[id]
	return node, exists
}

// Builder constructs graphs from HTTP requests and responses
type Builder struct {
	graph *Graph
	mu    sync.Mutex
}

// NewBuilder creates a new graph builder
func NewBuilder() *Builder {
	return &Builder{
		graph: NewGraph(),
	}
}

// GetGraph returns the underlying graph
func (b *Builder) GetGraph() *Graph {
	return b.graph
}

// AddRequest processes an HTTP request/response pair and adds it to the graph
func (b *Builder) AddRequest(req *http.Request, resp *http.Response) error {
	if req == nil || req.URL == nil {
		return fmt.Errorf("request or URL is nil")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Extract source node from request URL
	sourceNode := b.getOrCreateNode(req.URL.String())

	// Only parse response if it exists and is successful
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil
	}

	// Only parse HTML responses
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "application/xhtml") {
		return nil
	}

	// Parse response for links
	links, err := b.parseLinks(resp)
	if err != nil {
		// Log error but don't fail completely
		return nil
	}

	// Create edges for each discovered link
	for _, link := range links {
		if link == "" || link == req.URL.String() {
			// Skip empty links and self-references
			continue
		}

		targetNode := b.getOrCreateNode(link)

		// Create edge
		edge := &Edge{
			From:   sourceNode.ID,
			To:     targetNode.ID,
			Type:   "link",
			Weight: 1,
		}

		// Add to graph
		b.graph.AddEdge(edge)
	}

	return nil
}

// getOrCreateNode retrieves an existing node or creates a new one
func (b *Builder) getOrCreateNode(urlStr string) *Node {
	// Use the URL as the ID (normalized)
	id := normalizeURL(urlStr)

	if node, exists := b.graph.GetNode(id); exists {
		return node
	}

	node := &Node{
		ID:  id,
		URL: urlStr,
	}
	b.graph.AddNode(node)
	return node
}

// parseLinks extracts and resolves all links from an HTML response
func (b *Builder) parseLinks(resp *http.Response) ([]string, error) {
	if resp == nil || resp.Body == nil {
		return nil, fmt.Errorf("response or body is nil")
	}

	// Read the body (it will be consumed, so we need to be careful)
	// In a real implementation, you might want to use a TeeReader to preserve the body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	defer resp.Body.Close()

	// Parse HTML
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("parse html: %w", err)
	}

	var links []string
	seen := make(map[string]struct{})

	// Extract all links
	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					// Resolve relative URLs to absolute
					absoluteURL := resolveHTMLLink(resp.Request.URL, attr.Val)
					if absoluteURL != "" {
						// Deduplicate links
						if _, exists := seen[absoluteURL]; !exists {
							seen[absoluteURL] = struct{}{}
							links = append(links, absoluteURL)
						}
					}
				}
			}
		}

		// Also check for other link sources like img src, script src, etc.
		if n.Type == html.ElementNode {
			switch n.Data {
			case "img", "script":
				for _, attr := range n.Attr {
					if attr.Key == "src" {
						absoluteURL := resolveHTMLLink(resp.Request.URL, attr.Val)
						if absoluteURL != "" {
							if _, exists := seen[absoluteURL]; !exists {
								seen[absoluteURL] = struct{}{}
								links = append(links, absoluteURL)
							}
						}
					}
				}
			case "link":
				for _, attr := range n.Attr {
					if attr.Key == "href" {
						absoluteURL := resolveHTMLLink(resp.Request.URL, attr.Val)
						if absoluteURL != "" {
							if _, exists := seen[absoluteURL]; !exists {
								seen[absoluteURL] = struct{}{}
								links = append(links, absoluteURL)
							}
						}
					}
				}
			}
		}

		// Recursively process child nodes
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(doc)

	return links, nil
}

// resolveHTMLLink converts a potentially relative URL to an absolute URL based on the base URL
func resolveHTMLLink(base *url.URL, href string) string {
	if base == nil || href == "" {
		return ""
	}

	// Trim whitespace
	href = strings.TrimSpace(href)
	if href == "" {
		return ""
	}

	// Skip invalid schemes
	if strings.HasPrefix(href, "javascript:") ||
		strings.HasPrefix(href, "mailto:") ||
		strings.HasPrefix(href, "tel:") ||
		strings.HasPrefix(href, "data:") {
		return ""
	}

	// Parse the href
	parsed, err := url.Parse(href)
	if err != nil {
		return ""
	}

	// Resolve to absolute URL
	absolute := base.ResolveReference(parsed)

	// Only return HTTP/HTTPS URLs
	if absolute.Scheme != "http" && absolute.Scheme != "https" {
		return ""
	}

	return absolute.String()
}

// normalizeURL normalizes a URL for use as a node ID
func normalizeURL(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	// Remove fragment
	parsed.Fragment = ""

	// Normalize by removing trailing slash for consistency
	path := parsed.Path
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		parsed.Path = strings.TrimSuffix(path, "/")
	}

	return parsed.String()
}
