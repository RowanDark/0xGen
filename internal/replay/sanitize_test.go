package replay

import "testing"

func TestSanitizeHeaders(t *testing.T) {
	headers := map[string][]string{
		"Authorization": {"Bearer secret-token"},
		"Content-Type":  {"application/json"},
	}
	cleaned := SanitizeHeaders(headers)
	if cleaned["Authorization"][0] != "[REDACTED]" {
		t.Fatalf("authorization header not redacted: %v", cleaned["Authorization"])
	}
	if cleaned["Content-Type"][0] != "application/json" {
		t.Fatalf("content-type header changed: %v", cleaned["Content-Type"])
	}
}

func TestSanitizeCookieValue(t *testing.T) {
	value := "session-token"
	sanitized := SanitizeCookieValue(value)
	if sanitized == value || sanitized == "" {
		t.Fatalf("expected hashed cookie value, got %q", sanitized)
	}
	again := SanitizeCookieValue(value)
	if sanitized != again {
		t.Fatalf("sanitization not deterministic: %q vs %q", sanitized, again)
	}
}

func TestSanitizeBody(t *testing.T) {
	body := []byte("token=abcdef12345&other=value")
	sanitized := SanitizeBody(body)
	if string(sanitized) == string(body) {
		t.Fatalf("body not sanitised: %s", sanitized)
	}
	if want := "token=[REDACTED]&other=value"; string(sanitized) != want {
		t.Fatalf("unexpected sanitised body: %s", sanitized)
	}
}
