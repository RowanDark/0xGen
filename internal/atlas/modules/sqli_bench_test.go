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
// BenchmarkSQLiModule_SingleTarget        ~100-500 ops    ~10-20ms/op    ~3-5MB/op
// BenchmarkSQLiModule_100Targets          ~1-5 ops        ~1-2s/op       ~300-500MB/op
// BenchmarkSQLiModule_VulnerableTarget    ~50-200 ops     ~5-10ms/op     ~2-4MB/op
// BenchmarkSQLiModule_NonVulnerableTarget ~100-500 ops    ~10-20ms/op    ~3-5MB/op
// BenchmarkSQLiModule_MultipleParameters  ~50-200 ops     ~15-30ms/op    ~5-10MB/op

// BenchmarkSQLiModule_SingleTarget benchmarks scanning a single non-vulnerable target.
func BenchmarkSQLiModule_SingleTarget(b *testing.B) {
	// Setup test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("User not found"))
	}))
	defer server.Close()

	module := NewSQLiModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?id=1",
		Method:     "GET",
		Parameters: map[string]string{"id": "1"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkSQLiModule_100Targets benchmarks scanning 100 unique targets.
func BenchmarkSQLiModule_100Targets(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewSQLiModule(atlas.NewNopLogger(), nil)

	// Create 100 unique targets
	targets := make([]*atlas.ScanTarget, 100)
	for i := 0; i < 100; i++ {
		targets[i] = &atlas.ScanTarget{
			URL:        fmt.Sprintf("%s/page%d?id=1", server.URL, i),
			Method:     "GET",
			Parameters: map[string]string{"id": "1"},
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

// BenchmarkSQLiModule_VulnerableTarget benchmarks scanning a vulnerable target.
func BenchmarkSQLiModule_VulnerableTarget(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("id")
		if strings.Contains(query, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("SQL syntax error near '" + query + "'"))
			return
		}
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewSQLiModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?id=1",
		Method:     "GET",
		Parameters: map[string]string{"id": "1"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkSQLiModule_NonVulnerableTarget benchmarks scanning a non-vulnerable target.
func BenchmarkSQLiModule_NonVulnerableTarget(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewSQLiModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?id=1",
		Method:     "GET",
		Parameters: map[string]string{"id": "1"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkSQLiModule_MultipleParameters benchmarks scanning targets with multiple parameters.
func BenchmarkSQLiModule_MultipleParameters(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewSQLiModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:    server.URL + "?id=1&name=test&category=product&sort=asc&limit=10",
		Method: "GET",
		Parameters: map[string]string{
			"id":       "1",
			"name":     "test",
			"category": "product",
			"sort":     "asc",
			"limit":    "10",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkSQLiModule_ErrorBasedDetection benchmarks error-based SQLi detection specifically.
func BenchmarkSQLiModule_ErrorBasedDetection(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("id")
		if strings.Contains(query, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("MySQL error: You have an error in your SQL syntax"))
			return
		}
		w.Write([]byte("User: John Doe"))
	}))
	defer server.Close()

	module := NewSQLiModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?id=1",
		Method:     "GET",
		Parameters: map[string]string{"id": "1"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkSQLiModule_BooleanBasedDetection benchmarks boolean-based SQLi detection specifically.
func BenchmarkSQLiModule_BooleanBasedDetection(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("id")
		if strings.Contains(query, "OR '1'='1") {
			w.Write([]byte("User 1\nUser 2\nUser 3\nUser 4\nUser 5"))
			return
		}
		if strings.Contains(query, "OR '1'='2") {
			w.Write([]byte(""))
			return
		}
		w.Write([]byte("User 1"))
	}))
	defer server.Close()

	module := NewSQLiModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?id=1",
		Method:     "GET",
		Parameters: map[string]string{"id": "1"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkSQLiModule_ParallelScanning benchmarks parallel scanning of multiple targets.
func BenchmarkSQLiModule_ParallelScanning(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewSQLiModule(atlas.NewNopLogger(), nil)

	// Create diverse targets
	targets := make([]*atlas.ScanTarget, 10)
	for i := 0; i < 10; i++ {
		targets[i] = &atlas.ScanTarget{
			URL:        fmt.Sprintf("%s/page%d?id=1", server.URL, i),
			Method:     "GET",
			Parameters: map[string]string{"id": "1"},
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
