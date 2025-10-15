package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerExportsPrimaryAndLegacyMetrics(t *testing.T) {
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()

	Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "# HELP oxg_rpc_requests_total") {
		t.Fatalf("expected oxg metrics to be exported, got %q", body)
	}
	if !strings.Contains(body, "# HELP glyph_rpc_requests_total") {
		t.Fatalf("expected glyph legacy metrics to be exported, got %q", body)
	}
}
