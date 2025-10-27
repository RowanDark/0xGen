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
	required := []string{
		"# HELP oxg_rpc_requests_total",
		"# HELP oxg_plugin_queue_dropped_total",
		"# HELP oxg_plugin_event_failures_total",
		"# HELP oxg_plugin_errors_total",
	}
	for _, metric := range required {
		if !strings.Contains(body, metric) {
			t.Fatalf("expected metric %q to be exported, got %q", metric, body)
		}
	}
}
