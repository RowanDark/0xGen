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
// BenchmarkSSRFModule_SingleTarget        ~100-300 ops    ~10-20ms/op    ~2-4MB/op
// BenchmarkSSRFModule_100Targets          ~1-3 ops        ~1-2s/op       ~200-400MB/op
// BenchmarkSSRFModule_VulnerableTarget    ~50-150 ops     ~10-15ms/op    ~2-4MB/op
// BenchmarkSSRFModule_CloudMetadata       ~100-300 ops    ~5-10ms/op     ~1-3MB/op
// BenchmarkSSRFModule_ParallelScanning    ~500-1500 ops   ~2-5ms/op      ~1-3MB/op

// BenchmarkSSRFModule_SingleTarget benchmarks scanning a single non-vulnerable target.
func BenchmarkSSRFModule_SingleTarget(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("File not found"))
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?url=http://example.com",
		Method:     "GET",
		Parameters: map[string]string{"url": "http://example.com"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkSSRFModule_100Targets benchmarks scanning 100 unique targets.
func BenchmarkSSRFModule_100Targets(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)

	// Create 100 unique targets
	targets := make([]*atlas.ScanTarget, 100)
	for i := 0; i < 100; i++ {
		targets[i] = &atlas.ScanTarget{
			URL:        fmt.Sprintf("%s/fetch%d?url=http://example.com", server.URL, i),
			Method:     "GET",
			Parameters: map[string]string{"url": "http://example.com"},
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

// BenchmarkSSRFModule_VulnerableTarget benchmarks scanning a vulnerable target.
func BenchmarkSSRFModule_VulnerableTarget(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetURL := r.URL.Query().Get("url")
		// Simulate SSRF - reflect metadata-like content
		if strings.Contains(targetURL, "169.254.169.254") {
			w.Write([]byte(`{
				"accountId": "123456789012",
				"region": "us-east-1",
				"availabilityZone": "us-east-1a"
			}`))
			return
		}
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?url=http://example.com",
		Method:     "GET",
		Parameters: map[string]string{"url": "http://example.com"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkSSRFModule_CloudMetadataDetection benchmarks cloud metadata SSRF detection.
func BenchmarkSSRFModule_CloudMetadataDetection(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		if strings.Contains(url, "169.254.169.254") {
			// Simulate AWS metadata response
			w.Write([]byte(`{
				"Code": "Success",
				"LastUpdated": "2024-01-01T00:00:00Z",
				"Type": "AWS-HMAC",
				"AccessKeyId": "ASIATESTACCESSKEY",
				"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"Token": "IQoJb3JpZ2luX2VjEBAaDGV1LXdlc3QtMiJH..."
			}`))
			return
		}
		w.Write([]byte("Not found"))
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?url=http://example.com",
		Method:     "GET",
		Parameters: map[string]string{"url": "http://example.com"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkSSRFModule_LocalFileAccess benchmarks local file access SSRF detection.
func BenchmarkSSRFModule_LocalFileAccess(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("file")
		if strings.HasPrefix(url, "file://") {
			// Simulate file disclosure
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"))
			return
		}
		w.Write([]byte("Invalid file"))
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?file=document.txt",
		Method:     "GET",
		Parameters: map[string]string{"file": "document.txt"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkSSRFModule_MultipleParameters benchmarks scanning with multiple URL parameters.
func BenchmarkSSRFModule_MultipleParameters(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:    server.URL + "?url=http://example.com&callback=http://api.example.com&webhook=http://hooks.example.com",
		Method: "GET",
		Parameters: map[string]string{
			"url":      "http://example.com",
			"callback": "http://api.example.com",
			"webhook":  "http://hooks.example.com",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkSSRFModule_NonVulnerableTarget benchmarks scanning properly validated target.
func BenchmarkSSRFModule_NonVulnerableTarget(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetURL := r.URL.Query().Get("url")
		// Simulate proper validation - reject internal URLs
		if strings.Contains(targetURL, "169.254") || strings.Contains(targetURL, "localhost") || strings.Contains(targetURL, "127.0.0.1") {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid URL"))
			return
		}
		w.Write([]byte("Content fetched successfully"))
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?url=http://example.com",
		Method:     "GET",
		Parameters: map[string]string{"url": "http://example.com"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkSSRFModule_InternalNetworkDetection benchmarks internal network access detection.
func BenchmarkSSRFModule_InternalNetworkDetection(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		if strings.Contains(url, "192.168.") || strings.Contains(url, "10.") || strings.Contains(url, "172.16.") {
			// Simulate internal network response
			w.Write([]byte(`{
				"service": "internal-api",
				"version": "1.0",
				"endpoints": ["/admin", "/config", "/users"]
			}`))
			return
		}
		w.Write([]byte("External resource"))
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?url=http://example.com",
		Method:     "GET",
		Parameters: map[string]string{"url": "http://example.com"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		module.Scan(context.Background(), target)
	}
}

// BenchmarkSSRFModule_ParallelScanning benchmarks parallel scanning of multiple targets.
func BenchmarkSSRFModule_ParallelScanning(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)

	// Create diverse targets
	targets := make([]*atlas.ScanTarget, 10)
	for i := 0; i < 10; i++ {
		targets[i] = &atlas.ScanTarget{
			URL:        fmt.Sprintf("%s/fetch%d?url=http://example.com", server.URL, i),
			Method:     "GET",
			Parameters: map[string]string{"url": "http://example.com"},
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
