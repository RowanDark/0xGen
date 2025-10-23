package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerExportsMetrics(t *testing.T) {
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()

	Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "# HELP oxg_rpc_requests_total") {
		t.Fatalf("expected oxg metrics to be exported, got %q", body)
	}
	if strings.Contains(body, "oxg_rpc_requests_total") {
		t.Fatalf("unexpected legacy metrics exported: %q", body)
	}
}
