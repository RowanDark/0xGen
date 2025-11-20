package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/atlas"
)

func TestCmdIModule_ErrorBased_LSOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		// Simulate command injection with ls output
		if strings.Contains(cmd, "ls") || strings.Contains(cmd, "dir") {
			w.Write([]byte("total 48\ndrwxr-xr-x 2 root root 4096 Nov 20 12:00 bin\n-rw-r--r-- 1 root root 1234 Nov 20 12:00 file.txt"))
		} else {
			w.Write([]byte("Normal response"))
		}
	}))
	defer server.Close()

	module := NewCmdIModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?cmd=test",
		Method:     "GET",
		Parameters: map[string]string{"cmd": "test"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect command injection with ls output")
	}

	if findings[0].Type != "Command Injection" {
		t.Errorf("expected type 'Command Injection', got '%s'", findings[0].Type)
	}

	if findings[0].Confidence != atlas.ConfidenceConfirmed {
		t.Errorf("expected confidence Confirmed, got %s", findings[0].Confidence)
	}
}

func TestCmdIModule_ErrorBased_WhoamiOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		if strings.Contains(cmd, "whoami") {
			w.Write([]byte("root"))
		} else {
			w.Write([]byte("Normal response"))
		}
	}))
	defer server.Close()

	module := NewCmdIModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?cmd=test",
		Method:     "GET",
		Parameters: map[string]string{"cmd": "test"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect command injection with whoami output")
	}
}

func TestCmdIModule_ErrorBased_WindowsPaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		if strings.Contains(cmd, "dir") {
			w.Write([]byte("Volume in drive C:\\ has no label\nDirectory of C:\\Windows"))
		} else {
			w.Write([]byte("Normal response"))
		}
	}))
	defer server.Close()

	module := NewCmdIModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?cmd=test",
		Method:     "GET",
		Parameters: map[string]string{"cmd": "test"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect command injection with Windows paths")
	}
}

func TestCmdIModule_TimeBased_Sleep(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		// Simulate time-based command injection
		if strings.Contains(cmd, "sleep 3") || strings.Contains(cmd, "timeout 3") {
			time.Sleep(3 * time.Second)
		}
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewCmdIModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?cmd=test",
		Method:     "GET",
		Parameters: map[string]string{"cmd": "test"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect time-based command injection")
	}

	if findings[0].Type != "Command Injection (Time-based)" {
		t.Errorf("expected type 'Command Injection (Time-based)', got '%s'", findings[0].Type)
	}
}

func TestCmdIModule_BlindWithOAST(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server executes command but doesn't reflect output (blind)
		w.Write([]byte("Request processed"))
	}))
	defer server.Close()

	mockOAST := &mockOASTClient{hasInteractions: true}
	module := NewCmdIModule(atlas.NewNopLogger(), mockOAST)

	target := &atlas.ScanTarget{
		URL:        server.URL + "?cmd=test",
		Method:     "GET",
		Parameters: map[string]string{"cmd": "test"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect blind command injection via OAST")
	}

	if findings[0].Type != "Command Injection (Blind)" {
		t.Errorf("expected type 'Command Injection (Blind)', got '%s'", findings[0].Type)
	}
}

func TestCmdIModule_NoOASTInteraction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Normal response"))
	}))
	defer server.Close()

	mockOAST := &mockOASTClient{hasInteractions: false}
	module := NewCmdIModule(atlas.NewNopLogger(), mockOAST)

	target := &atlas.ScanTarget{
		URL:        server.URL + "?cmd=test",
		Method:     "GET",
		Parameters: map[string]string{"cmd": "test"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should not detect blind command injection without OAST interaction
	for _, f := range findings {
		if f.Type == "Command Injection (Blind)" {
			t.Error("false positive: detected blind command injection without OAST interaction")
		}
	}
}

func TestCmdIModule_IsCommandOutput(t *testing.T) {
	module := NewCmdIModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "ls output with total",
			body:     "total 48\ndrwxr-xr-x 2 root root 4096",
			expected: true,
		},
		{
			name:     "Directory listing",
			body:     "drwxr-xr-x 2 user user 4096 Nov 20 12:00 documents",
			expected: true,
		},
		{
			name:     "whoami output - root",
			body:     "root",
			expected: true,
		},
		{
			name:     "whoami output - administrator",
			body:     "administrator",
			expected: true,
		},
		{
			name:     "Windows dir output",
			body:     "Volume in drive C has no label",
			expected: true,
		},
		{
			name:     "Unix path",
			body:     "File located at /bin/bash",
			expected: true,
		},
		{
			name:     "Windows path",
			body:     "File located at C:\\Windows\\System32",
			expected: true,
		},
		{
			name:     "Normal response",
			body:     "This is a normal webpage content",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := module.isCommandOutput(tt.body)
			if result != tt.expected {
				t.Errorf("expected %v, got %v for body: %s", tt.expected, result, tt.body)
			}
		})
	}
}

func TestCmdIModule_CommandSeparators(t *testing.T) {
	tests := []struct {
		name      string
		separator string
	}{
		{"Semicolon separator", ";"},
		{"Pipe separator", "|"},
		{"Ampersand separator", "&"},
		{"Backtick substitution", "`"},
		{"Dollar substitution", "$"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cmd := r.URL.Query().Get("cmd")
				if strings.Contains(cmd, tt.separator) {
					w.Write([]byte("total 48\ndrwxr-xr-x 2 root root 4096"))
				} else {
					w.Write([]byte("Normal response"))
				}
			}))
			defer server.Close()

			module := NewCmdIModule(atlas.NewNopLogger(), nil)
			target := &atlas.ScanTarget{
				URL:        server.URL + "?cmd=test",
				Method:     "GET",
				Parameters: map[string]string{"cmd": "test"},
			}

			findings, err := module.Scan(context.Background(), target)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			if len(findings) == 0 {
				t.Errorf("expected to detect command injection with %s separator", tt.separator)
			}
		})
	}
}

func TestCmdIModule_SupportsTarget(t *testing.T) {
	module := NewCmdIModule(atlas.NewNopLogger(), nil)

	// Command injection should support all targets
	target := &atlas.ScanTarget{
		URL:    "http://example.com",
		Method: "GET",
	}

	if !module.SupportsTarget(target) {
		t.Error("Command injection module should support all targets")
	}
}

func TestCmdIModule_ExtractParameters(t *testing.T) {
	module := NewCmdIModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:        "http://example.com?cmd=ls&arg=-la",
		Method:     "GET",
		Parameters: map[string]string{"exec": "whoami"},
	}

	params := module.extractParameters(target)

	if len(params) != 3 {
		t.Errorf("expected 3 parameters, got %d", len(params))
	}

	if params["cmd"] != "ls" {
		t.Errorf("expected cmd=ls, got %s", params["cmd"])
	}

	if params["arg"] != "-la" {
		t.Errorf("expected arg=-la, got %s", params["arg"])
	}

	if params["exec"] != "whoami" {
		t.Errorf("expected exec=whoami, got %s", params["exec"])
	}
}

func TestCmdIModule_GetParamLocation(t *testing.T) {
	module := NewCmdIModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		target   *atlas.ScanTarget
		param    string
		expected atlas.ParamLocation
	}{
		{
			name: "Query parameter",
			target: &atlas.ScanTarget{
				URL:    "http://test.com?cmd=ls",
				Method: "GET",
			},
			param:    "cmd",
			expected: atlas.ParamLocationQuery,
		},
		{
			name: "POST body parameter",
			target: &atlas.ScanTarget{
				URL:    "http://test.com",
				Method: "POST",
			},
			param:    "command",
			expected: atlas.ParamLocationBody,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := module.getParamLocation(tt.target, tt.param)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestCmdIModule_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewCmdIModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?cmd=test",
		Method:     "GET",
		Parameters: map[string]string{"cmd": "test"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings, err := module.Scan(ctx, target)

	if err == nil {
		t.Error("expected context cancellation error")
	}

	if len(findings) > 0 {
		t.Errorf("expected 0 findings after cancellation, got %d", len(findings))
	}
}

func TestCmdIModule_MultipleParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd1 := r.URL.Query().Get("cmd1")
		cmd2 := r.URL.Query().Get("cmd2")

		if strings.Contains(cmd1, "ls") {
			w.Write([]byte("total 48\ndrwxr-xr-x 2 root root 4096"))
			return
		}
		if strings.Contains(cmd2, "whoami") {
			w.Write([]byte("root"))
			return
		}
		w.Write([]byte("Normal response"))
	}))
	defer server.Close()

	module := NewCmdIModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?cmd1=test1&cmd2=test2",
		Method:     "GET",
		Parameters: map[string]string{"cmd1": "test1", "cmd2": "test2"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect command injection in both parameters
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (one per parameter), got %d", len(findings))
	}
}

func TestCmdIModule_NoFalsePositive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This is a normal webpage with no command output"))
	}))
	defer server.Close()

	module := NewCmdIModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?cmd=test",
		Method:     "GET",
		Parameters: map[string]string{"cmd": "test"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("false positive detected: got %d findings for non-vulnerable endpoint", len(findings))
	}
}

func TestCmdIModule_NoParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Static page"))
	}))
	defer server.Close()

	module := NewCmdIModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:    server.URL,
		Method: "GET",
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for page without parameters, got %d", len(findings))
	}
}

func TestCmdIModule_POSTRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if err := r.ParseForm(); err == nil {
				command := r.FormValue("command")
				if strings.Contains(command, "ls") {
					w.Write([]byte("total 48\ndrwxr-xr-x 2 root root 4096"))
					return
				}
			}
		}
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewCmdIModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL,
		Method:     "POST",
		Parameters: map[string]string{"command": "test"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect command injection in POST request")
	}
}
