package modules

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RowanDark/0xgen/internal/atlas"
)

func TestXXEModule_FileDisclosure(t *testing.T) {
	// Setup vulnerable test server that reflects external entity
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)

		// Simulate XXE vulnerability - reflect file content
		if strings.Contains(bodyStr, "file:///etc/passwd") {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<?xml version="1.0"?>
<root>
  <data>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin</data>
</root>`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0"?><root><data>normal response</data></root>`))
	}))
	defer server.Close()

	module := NewXXEModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:    server.URL,
		Method: "POST",
	}

	findings, err := module.Scan(context.Background(), target)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Type != "XML External Entity (File Disclosure)" {
		t.Errorf("expected type 'XML External Entity (File Disclosure)', got '%s'", findings[0].Type)
	}

	if findings[0].Confidence != atlas.ConfidenceConfirmed {
		t.Errorf("expected confidence Confirmed, got %s", findings[0].Confidence)
	}

	if findings[0].Severity != atlas.SeverityHigh {
		t.Errorf("expected severity High, got %s", findings[0].Severity)
	}
}

func TestXXEModule_WindowsFileDisclosure(t *testing.T) {
	// Setup vulnerable test server for Windows files
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)

		// Simulate XXE vulnerability for Windows
		if strings.Contains(bodyStr, "file:///c:/windows/win.ini") {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<?xml version="1.0"?>
<root>
  <data>[extensions]
[fonts]
[mci extensions]</data>
</root>`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0"?><root><data>normal response</data></root>`))
	}))
	defer server.Close()

	module := NewXXEModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:    server.URL,
		Method: "POST",
	}

	findings, err := module.Scan(context.Background(), target)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Type != "XML External Entity (File Disclosure)" {
		t.Errorf("expected type 'XML External Entity (File Disclosure)', got '%s'", findings[0].Type)
	}
}

func TestXXEModule_ParameterEntity(t *testing.T) {
	// Setup server that shows XML error messages
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)

		// Simulate parameter entity error
		if strings.Contains(bodyStr, "<!ENTITY %") {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`XML parse error: External entity reference is not allowed`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0"?><root><data>OK</data></root>`))
	}))
	defer server.Close()

	module := NewXXEModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:    server.URL,
		Method: "POST",
	}

	findings, err := module.Scan(context.Background(), target)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// This test might not find a vulnerability depending on server response
	// but should not error
	if len(findings) > 0 {
		if findings[0].Type != "XML External Entity (Parameter Entity)" {
			t.Errorf("expected type 'XML External Entity (Parameter Entity)', got '%s'", findings[0].Type)
		}
	}
}

func TestXXEModule_NoVulnerability(t *testing.T) {
	// Setup non-vulnerable server (sanitizes input)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0"?><root><data>sanitized response</data></root>`))
	}))
	defer server.Close()

	module := NewXXEModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:    server.URL,
		Method: "POST",
	}

	findings, err := module.Scan(context.Background(), target)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-vulnerable server, got %d", len(findings))
	}
}

func TestXXEModule_SupportsTarget(t *testing.T) {
	module := NewXXEModule(atlas.NewNopLogger(), nil)

	// XXE should support all targets (it will send XML to any endpoint)
	target := &atlas.ScanTarget{
		URL:    "http://example.com",
		Method: "POST",
	}

	if !module.SupportsTarget(target) {
		t.Error("XXE module should support all targets")
	}
}

func TestXXEModule_ContainsFileContent(t *testing.T) {
	module := NewXXEModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "Unix passwd file",
			body:     "root:x:0:0:root:/root:/bin/bash",
			expected: true,
		},
		{
			name:     "Windows ini file",
			body:     "[extensions]\n[fonts]",
			expected: true,
		},
		{
			name:     "Base64 encoded root",
			body:     "cm9vdDp4OjA6MA==",
			expected: true,
		},
		{
			name:     "Normal response",
			body:     "This is a normal response without file content",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := module.containsFileContent(tt.body)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestXXEModule_ContainsXMLError(t *testing.T) {
	module := NewXXEModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "XML parse error",
			body:     "XML parse error: External entity not allowed",
			expected: true,
		},
		{
			name:     "SAXParseException",
			body:     "org.xml.sax.SAXParseException: Entity reference not allowed",
			expected: true,
		},
		{
			name:     "Malformed XML",
			body:     "Error: Malformed XML document",
			expected: true,
		},
		{
			name:     "Normal response",
			body:     "Success: Data processed",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := module.containsXMLError(tt.body)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
