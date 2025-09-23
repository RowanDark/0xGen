package raider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEngineRespectsRateLimit(t *testing.T) {
	var times []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		times = append(times, time.Now())
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	markers, err := ParseMarkers("{{}}")
	if err != nil {
		t.Fatalf("parse markers: %v", err)
	}

	template := "POST " + srv.URL + " HTTP/1.1\nContent-Type: text/plain\n\nvalue={{seed}}"
	tpl, err := ParseTemplate(template, markers)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}

	payloads := []string{"1", "2", "3", "4"}
	limit := 2.0 // 2 requests per second

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	engine := NewEngine(tpl, payloads, WithConcurrency(4), WithRateLimit(limit))
	if err := engine.Run(ctx, func(Result) error { return nil }); err != nil {
		t.Fatalf("engine run failed: %v", err)
	}

	if len(times) != len(payloads) {
		t.Fatalf("expected %d requests, got %d", len(payloads), len(times))
	}

	if len(times) >= 2 {
		total := times[len(times)-1].Sub(times[0])
		expected := time.Duration(float64(len(times)-1) / limit * float64(time.Second))
		if total+100*time.Millisecond < expected {
			t.Fatalf("requests completed too quickly: got %v, expected at least %v", total, expected)
		}
	}
}
