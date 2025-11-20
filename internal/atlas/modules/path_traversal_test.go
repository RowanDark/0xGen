package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RowanDark/0xgen/internal/atlas"
)

func TestPathTraversalModule_UnixPasswd(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		// Simulate path traversal vulnerability
		if strings.Contains(file, "passwd") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"))
		} else {
			w.Write([]byte("Normal content"))
		}
	}))
	defer server.Close()

	module := NewPathTraversalModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?file=test.txt",
		Method:     "GET",
		Parameters: map[string]string{"file": "test.txt"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect path traversal to /etc/passwd")
	}

	if findings[0].Type != "Path Traversal" {
		t.Errorf("expected type 'Path Traversal', got '%s'", findings[0].Type)
	}

	if findings[0].Confidence != atlas.ConfidenceConfirmed {
		t.Errorf("expected confidence Confirmed, got %s", findings[0].Confidence)
	}
}

func TestPathTraversalModule_WindowsWinIni(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if strings.Contains(file, "win.ini") {
			w.Write([]byte("[fonts]\n[extensions]\n[mci extensions]\n"))
		} else {
			w.Write([]byte("Normal content"))
		}
	}))
	defer server.Close()

	module := NewPathTraversalModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?file=test.txt",
		Method:     "GET",
		Parameters: map[string]string{"file": "test.txt"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect path traversal to win.ini")
	}
}

func TestPathTraversalModule_IsFileContent(t *testing.T) {
	module := NewPathTraversalModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		body     string
		payload  string
		expected bool
	}{
		{
			name:     "Unix passwd with root entry",
			body:     "root:x:0:0:root:/root:/bin/bash",
			payload:  "../../../etc/passwd",
			expected: true,
		},
		{
			name:     "Unix passwd with daemon entry",
			body:     "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
			payload:  "../../../etc/passwd",
			expected: true,
		},
		{
			name:     "Unix passwd with bash shell",
			body:     "user:x:1000:1000:User:/home/user:/bin/bash",
			payload:  "../../../etc/passwd",
			expected: true,
		},
		{
			name:     "Unix passwd with nologin",
			body:     "nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin",
			payload:  "../../../etc/passwd",
			expected: true,
		},
		{
			name:     "Windows win.ini with fonts",
			body:     "[fonts]\n[extensions]\n[mci extensions]",
			payload:  "..\\..\\..\\windows\\win.ini",
			expected: true,
		},
		{
			name:     "Windows win.ini with extensions",
			body:     "[extensions]\nwav=wmplayer.exe ^.wav",
			payload:  "..\\..\\..\\windows\\win.ini",
			expected: true,
		},
		{
			name:     "Windows win.ini with mci",
			body:     "[mci extensions]\naif=MPEGVideo",
			payload:  "..\\..\\..\\windows\\win.ini",
			expected: true,
		},
		{
			name:     "Normal content - not file",
			body:     "This is a normal webpage content",
			payload:  "../../../etc/passwd",
			expected: false,
		},
		{
			name:     "False positive - contains root but not passwd format",
			body:     "Welcome root user to our application",
			payload:  "../../../etc/passwd",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := module.isFileContent(tt.body, tt.payload)
			if result != tt.expected {
				t.Errorf("expected %v, got %v for body: %s", tt.expected, result, tt.body)
			}
		})
	}
}

func TestPathTraversalModule_GetFileProof(t *testing.T) {
	module := NewPathTraversalModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		body     string
		payload  string
		expected string
	}{
		{
			name:     "Unix passwd file",
			body:     "root:x:0:0",
			payload:  "../../../etc/passwd",
			expected: "File content detected: /etc/passwd (Unix password file)",
		},
		{
			name:     "Windows win.ini file",
			body:     "[fonts]",
			payload:  "..\\..\\..\\windows\\win.ini",
			expected: "File content detected: win.ini (Windows configuration file)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := module.getFileProof(tt.body, tt.payload)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestPathTraversalModule_UnixVariations(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"Basic dot-dot-slash", "../../../etc/passwd"},
		{"Dot-slash bypass", "..././..././..././etc/passwd"},
		{"Double slash bypass", "....//....//....//etc/passwd"},
		{"Absolute path", "/etc/passwd"},
		{"Deep traversal", "../../../../../../etc/passwd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				file := r.URL.Query().Get("file")
				if strings.Contains(file, "passwd") {
					w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
				} else {
					w.Write([]byte("Normal content"))
				}
			}))
			defer server.Close()

			module := NewPathTraversalModule(atlas.NewNopLogger(), nil)
			target := &atlas.ScanTarget{
				URL:        server.URL + "?file=test.txt",
				Method:     "GET",
				Parameters: map[string]string{"file": "test.txt"},
			}

			findings, err := module.Scan(context.Background(), target)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			if len(findings) == 0 {
				t.Errorf("expected to detect path traversal with payload: %s", tt.payload)
			}
		})
	}
}

func TestPathTraversalModule_WindowsVariations(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"Basic backslash traversal", "..\\..\\..\\windows\\win.ini"},
		{"Deep traversal", "..\\..\\..\\..\\..\\windows\\win.ini"},
		{"Absolute path", "c:\\windows\\win.ini"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				file := r.URL.Query().Get("file")
				if strings.Contains(file, "win.ini") {
					w.Write([]byte("[fonts]\n[extensions]\n"))
				} else {
					w.Write([]byte("Normal content"))
				}
			}))
			defer server.Close()

			module := NewPathTraversalModule(atlas.NewNopLogger(), nil)
			target := &atlas.ScanTarget{
				URL:        server.URL + "?file=test.txt",
				Method:     "GET",
				Parameters: map[string]string{"file": "test.txt"},
			}

			findings, err := module.Scan(context.Background(), target)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			if len(findings) == 0 {
				t.Errorf("expected to detect path traversal with payload: %s", tt.payload)
			}
		})
	}
}

func TestPathTraversalModule_EncodingVariations(t *testing.T) {
	tests := []struct {
		name        string
		encoding    string
		shouldMatch bool
	}{
		{"URL encoded", "%2e%2e%2f", true},
		{"Single encoded", "%2F", true},
		{"Double encoded", "%252F", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				file := r.URL.Query().Get("file")
				// Simulate vulnerability with encoding bypass
				if strings.Contains(file, tt.encoding) || strings.Contains(file, "passwd") {
					w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
				} else {
					w.Write([]byte("Normal content"))
				}
			}))
			defer server.Close()

			module := NewPathTraversalModule(atlas.NewNopLogger(), nil)
			target := &atlas.ScanTarget{
				URL:        server.URL + "?file=test.txt",
				Method:     "GET",
				Parameters: map[string]string{"file": "test.txt"},
			}

			findings, err := module.Scan(context.Background(), target)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			if tt.shouldMatch && len(findings) == 0 {
				t.Errorf("expected to detect path traversal with encoding: %s", tt.encoding)
			}
		})
	}
}

func TestPathTraversalModule_SupportsTarget(t *testing.T) {
	module := NewPathTraversalModule(atlas.NewNopLogger(), nil)

	// Path traversal should support all targets
	target := &atlas.ScanTarget{
		URL:    "http://example.com",
		Method: "GET",
	}

	if !module.SupportsTarget(target) {
		t.Error("Path traversal module should support all targets")
	}
}

func TestPathTraversalModule_ExtractParameters(t *testing.T) {
	module := NewPathTraversalModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:        "http://example.com?file=test.txt&path=/home/user",
		Method:     "GET",
		Parameters: map[string]string{"dir": "/var/www"},
	}

	params := module.extractParameters(target)

	if len(params) != 3 {
		t.Errorf("expected 3 parameters, got %d", len(params))
	}

	if params["file"] != "test.txt" {
		t.Errorf("expected file=test.txt, got %s", params["file"])
	}

	if params["path"] != "/home/user" {
		t.Errorf("expected path=/home/user, got %s", params["path"])
	}

	if params["dir"] != "/var/www" {
		t.Errorf("expected dir=/var/www, got %s", params["dir"])
	}
}

func TestPathTraversalModule_GetParamLocation(t *testing.T) {
	module := NewPathTraversalModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		target   *atlas.ScanTarget
		param    string
		expected atlas.ParamLocation
	}{
		{
			name: "Query parameter",
			target: &atlas.ScanTarget{
				URL:    "http://test.com?file=test.txt",
				Method: "GET",
			},
			param:    "file",
			expected: atlas.ParamLocationQuery,
		},
		{
			name: "POST body parameter",
			target: &atlas.ScanTarget{
				URL:    "http://test.com",
				Method: "POST",
			},
			param:    "filename",
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

func TestPathTraversalModule_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewPathTraversalModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?file=test.txt",
		Method:     "GET",
		Parameters: map[string]string{"file": "test.txt"},
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

func TestPathTraversalModule_MultipleParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file1 := r.URL.Query().Get("file1")
		file2 := r.URL.Query().Get("file2")

		if strings.Contains(file1, "passwd") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
			return
		}
		if strings.Contains(file2, "win.ini") {
			w.Write([]byte("[fonts]\n[extensions]\n"))
			return
		}
		w.Write([]byte("Normal content"))
	}))
	defer server.Close()

	module := NewPathTraversalModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?file1=test1.txt&file2=test2.txt",
		Method:     "GET",
		Parameters: map[string]string{"file1": "test1.txt", "file2": "test2.txt"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect path traversal in both parameters
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (one per parameter), got %d", len(findings))
	}
}

func TestPathTraversalModule_NoFalsePositive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This is a normal webpage with no sensitive file content"))
	}))
	defer server.Close()

	module := NewPathTraversalModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?file=test.txt",
		Method:     "GET",
		Parameters: map[string]string{"file": "test.txt"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("false positive detected: got %d findings for non-vulnerable endpoint", len(findings))
	}
}

func TestPathTraversalModule_NoParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Static page"))
	}))
	defer server.Close()

	module := NewPathTraversalModule(atlas.NewNopLogger(), nil)
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

func TestPathTraversalModule_POSTRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if err := r.ParseForm(); err == nil {
				filename := r.FormValue("filename")
				if strings.Contains(filename, "passwd") {
					w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
					return
				}
			}
		}
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewPathTraversalModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL,
		Method:     "POST",
		Parameters: map[string]string{"filename": "test.txt"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect path traversal in POST request")
	}
}

func TestPathTraversalModule_NullByteInjection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		// Simulate null byte vulnerability (older systems)
		if strings.Contains(file, "%00") && strings.Contains(file, "passwd") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
		} else {
			w.Write([]byte("Normal content"))
		}
	}))
	defer server.Close()

	module := NewPathTraversalModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?file=test.txt",
		Method:     "GET",
		Parameters: map[string]string{"file": "test.txt"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("expected to detect path traversal with null byte injection")
	}
}
