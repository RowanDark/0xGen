package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RowanDark/0xgen/internal/atlas"
)

// Expected benchmark results:
// BenchmarkXSSModule_SingleTarget         ~100-500 ops    ~8-15ms/op     ~2-4MB/op
// BenchmarkXSSModule_100Targets           ~1-5 ops        ~800ms-1.5s/op ~250-400MB/op
// BenchmarkXSSModule_VulnerableTarget     ~50-200 ops     ~5-10ms/op     ~2-3MB/op
// BenchmarkXSSModule_ReflectedDetection   ~100-300 ops    ~5-10ms/op     ~2-3MB/op
// BenchmarkXSSModule_ParallelScanning     ~500-2000 ops   ~1-3ms/op      ~500KB-2MB/op

// BenchmarkXSSModule_SingleTarget benchmarks scanning a single non-vulnerable target.
func BenchmarkXSSModule_SingleTarget(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>Search results</body></html>"))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?q=test",
		Method:     "GET",
		Parameters: map[string]string{"q": "test"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkXSSModule_100Targets benchmarks scanning 100 unique targets.
func BenchmarkXSSModule_100Targets(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>Page content</body></html>"))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)

	// Create 100 unique targets
	targets := make([]*atlas.ScanTarget, 100)
	for i := 0; i < 100; i++ {
		targets[i] = &atlas.ScanTarget{
			URL:        fmt.Sprintf("%s/page%d?q=test", server.URL, i),
			Method:     "GET",
			Parameters: map[string]string{"q": "test"},
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, target := range targets {
			module.Scan(context.Background(), target)
		}
	}
}

// BenchmarkXSSModule_VulnerableTarget benchmarks scanning a vulnerable target.
func BenchmarkXSSModule_VulnerableTarget(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		// Vulnerable: reflects input without sanitization
		w.Write([]byte(fmt.Sprintf("<html><body>Search results for: %s</body></html>", query)))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?q=test",
		Method:     "GET",
		Parameters: map[string]string{"q": "test"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkXSSModule_ReflectedDetection benchmarks reflected XSS detection specifically.
func BenchmarkXSSModule_ReflectedDetection(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		search := r.URL.Query().Get("search")
		// Reflect the parameter value
		response := fmt.Sprintf(`
			<html>
			<head><title>Search</title></head>
			<body>
				<h1>Search Results</h1>
				<p>You searched for: %s</p>
			</body>
			</html>
		`, search)
		w.Write([]byte(response))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?search=test",
		Method:     "GET",
		Parameters: map[string]string{"search": "test"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkXSSModule_MultipleParameters benchmarks scanning with multiple parameters.
func BenchmarkXSSModule_MultipleParameters(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>Results</body></html>"))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:    server.URL + "?q=test&category=all&sort=relevance&page=1",
		Method: "GET",
		Parameters: map[string]string{
			"q":        "test",
			"category": "all",
			"sort":     "relevance",
			"page":     "1",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkXSSModule_HTMLContextDetection benchmarks detection in HTML context.
func BenchmarkXSSModule_HTMLContextDetection(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		// Vulnerable HTML context
		html := fmt.Sprintf(`
			<html>
			<body>
				<div class="user-profile">
					<h2>Welcome, %s!</h2>
				</div>
			</body>
			</html>
		`, name)
		w.Write([]byte(html))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?name=user",
		Method:     "GET",
		Parameters: map[string]string{"name": "user"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkXSSModule_ScriptContextDetection benchmarks detection in script context.
func BenchmarkXSSModule_ScriptContextDetection(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callback := r.URL.Query().Get("callback")
		// Vulnerable script context (JSONP-like)
		script := fmt.Sprintf(`
			<html>
			<head>
				<script>
					var callback = '%s';
					processCallback(callback);
				</script>
			</head>
			<body></body>
			</html>
		`, callback)
		w.Write([]byte(script))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?callback=myFunction",
		Method:     "GET",
		Parameters: map[string]string{"callback": "myFunction"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkXSSModule_NonVulnerableTarget benchmarks scanning properly sanitized target.
func BenchmarkXSSModule_NonVulnerableTarget(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		// Properly sanitized
		sanitized := strings.ReplaceAll(query, "<", "&lt;")
		sanitized = strings.ReplaceAll(sanitized, ">", "&gt;")
		w.Write([]byte(fmt.Sprintf("<html><body>Search: %s</body></html>", sanitized)))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?q=test",
		Method:     "GET",
		Parameters: map[string]string{"q": "test"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkXSSModule_ParallelScanning benchmarks parallel scanning of multiple targets.
func BenchmarkXSSModule_ParallelScanning(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>Content</body></html>"))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)

	// Create diverse targets
	targets := make([]*atlas.ScanTarget, 10)
	for i := 0; i < 10; i++ {
		targets[i] = &atlas.ScanTarget{
			URL:        fmt.Sprintf("%s/page%d?q=test", server.URL, i),
			Method:     "GET",
			Parameters: map[string]string{"q": "test"},
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			target := targets[i%len(targets)]
			module.Scan(context.Background(), target)
			i++
		}
	})
}
