package oast

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/logging"
	"github.com/RowanDark/0xgen/internal/oast/local"
)

// testEventBus implements EventBus for testing.
type testEventBus struct {
	events []interface{}
}

func (b *testEventBus) Publish(eventType string, data interface{}) {
	b.events = append(b.events, data)
}

func testLogger() *logging.AuditLogger {
	return logging.MustNewAuditLogger("oast-test", logging.WithWriter(io.Discard))
}

// startClientInBackground starts the client server in a goroutine and returns a cancel function.
func startClientInBackground(t *testing.T, client *Client) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		if err := client.Start(ctx); err != nil {
			// Ignore errors from context cancellation
		}
	}()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	return ctx, cancel
}

func TestNewClient_Disabled(t *testing.T) {
	cfg := Config{
		Mode: ModeDisabled,
	}

	client, err := NewClient(cfg, &testEventBus{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client.IsEnabled() {
		t.Error("client should be disabled")
	}

	if client.GetMode() != ModeDisabled {
		t.Errorf("expected mode %s, got %s", ModeDisabled, client.GetMode())
	}
}

func TestNewClient_Local(t *testing.T) {
	cfg := Config{
		Mode: ModeLocal,
		Port: 0,
		Host: "localhost",
	}

	client, err := NewClient(cfg, &testEventBus{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !client.IsEnabled() {
		t.Error("client should be enabled")
	}

	if client.GetMode() != ModeLocal {
		t.Errorf("expected mode %s, got %s", ModeLocal, client.GetMode())
	}

	if client.GetStorage() == nil {
		t.Error("storage should be initialized")
	}

	if client.GetURLBuilder() == nil {
		t.Error("URL builder should be initialized")
	}
}

func TestNewClient_UnsupportedMode(t *testing.T) {
	tests := []struct {
		name string
		mode Mode
	}{
		{"selfhosted", ModeSelfHosted},
		{"cloud", ModeCloud},
		{"unknown", Mode("unknown")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Mode: tt.mode}
			_, err := NewClient(cfg, &testEventBus{}, testLogger())
			if err == nil {
				t.Errorf("expected error for mode %s", tt.mode)
			}
		})
	}
}

func TestClient_StartStop(t *testing.T) {
	cfg := Config{
		Mode: ModeLocal,
		Port: 0,
		Host: "localhost",
	}

	client, err := NewClient(cfg, &testEventBus{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in goroutine (Start blocks until context is cancelled)
	errCh := make(chan error, 1)
	go func() {
		errCh <- client.Start(ctx)
	}()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	// Verify port is assigned
	port := client.GetPort()
	if port == 0 {
		t.Error("port should be assigned after start")
	}

	// Verify base URL is set
	baseURL := client.GetBaseURL()
	if baseURL == "" {
		t.Error("base URL should be set after start")
	}

	// Stop server by cancelling context
	cancel()

	// Wait for server to stop
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("server did not stop in time")
	}
}

func TestClient_StartStop_Disabled(t *testing.T) {
	cfg := Config{Mode: ModeDisabled}

	client, err := NewClient(cfg, &testEventBus{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()

	// Start should be no-op for disabled mode
	if err := client.Start(ctx); err != nil {
		t.Errorf("start should not error when disabled: %v", err)
	}

	// Stop should be no-op
	if err := client.Stop(ctx); err != nil {
		t.Errorf("stop should not error when disabled: %v", err)
	}
}

func TestClient_GenerateCallback(t *testing.T) {
	cfg := Config{
		Mode: ModeLocal,
		Port: 0,
		Host: "localhost",
	}

	client, err := NewClient(cfg, &testEventBus{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := startClientInBackground(t, client)
	defer cancel()

	callback, err := client.GenerateCallback(ctx, "test-123")
	if err != nil {
		t.Fatalf("failed to generate callback: %v", err)
	}

	if callback.ID == "" {
		t.Error("callback ID should not be empty")
	}

	if callback.URL == "" {
		t.Error("callback URL should not be empty")
	}

	if callback.TestID != "test-123" {
		t.Errorf("expected test ID 'test-123', got '%s'", callback.TestID)
	}

	if callback.Created.IsZero() {
		t.Error("callback created time should be set")
	}
}

func TestClient_GenerateCallbackWithPath(t *testing.T) {
	cfg := Config{
		Mode: ModeLocal,
		Port: 0,
		Host: "localhost",
	}

	client, err := NewClient(cfg, &testEventBus{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := startClientInBackground(t, client)
	defer cancel()

	callback, err := client.GenerateCallbackWithPath(ctx, "test-456", "/ssrf")
	if err != nil {
		t.Fatalf("failed to generate callback: %v", err)
	}

	if callback.ID == "" {
		t.Error("callback ID should not be empty")
	}

	// URL should contain the path
	if callback.URL == "" {
		t.Error("callback URL should not be empty")
	}
}

func TestClient_GenerateCallback_Disabled(t *testing.T) {
	cfg := Config{Mode: ModeDisabled}

	client, err := NewClient(cfg, &testEventBus{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	_, err = client.GenerateCallback(ctx, "test")
	if err == nil {
		t.Error("expected error when generating callback with disabled client")
	}
}

func TestClient_CheckInteractions(t *testing.T) {
	cfg := Config{
		Mode: ModeLocal,
		Port: 0,
		Host: "localhost",
	}

	client, err := NewClient(cfg, &testEventBus{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := startClientInBackground(t, client)
	defer cancel()

	// Generate callback
	callback, err := client.GenerateCallback(ctx, "test-check")
	if err != nil {
		t.Fatalf("failed to generate callback: %v", err)
	}

	// Check for interactions (should be empty)
	interactions, err := client.CheckInteractions(ctx, callback.ID)
	if err != nil {
		t.Fatalf("failed to check interactions: %v", err)
	}

	if len(interactions) != 0 {
		t.Errorf("expected 0 interactions, got %d", len(interactions))
	}
}

func TestClient_HasInteraction(t *testing.T) {
	cfg := Config{
		Mode: ModeLocal,
		Port: 0,
		Host: "localhost",
	}

	client, err := NewClient(cfg, &testEventBus{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := startClientInBackground(t, client)
	defer cancel()

	// Generate callback
	callback, err := client.GenerateCallback(ctx, "test-has")
	if err != nil {
		t.Fatalf("failed to generate callback: %v", err)
	}

	// Check if interaction exists (should be false)
	has, err := client.HasInteraction(ctx, callback.ID)
	if err != nil {
		t.Fatalf("failed to check interaction: %v", err)
	}

	if has {
		t.Error("should not have interaction yet")
	}
}

func TestClient_WaitForInteraction_Timeout(t *testing.T) {
	cfg := Config{
		Mode:    ModeLocal,
		Port:    0,
		Host:    "localhost",
		Timeout: 1,
	}

	client, err := NewClient(cfg, &testEventBus{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := startClientInBackground(t, client)
	defer cancel()

	// Generate callback
	callback, err := client.GenerateCallback(ctx, "test-timeout")
	if err != nil {
		t.Fatalf("failed to generate callback: %v", err)
	}

	// Wait should timeout
	start := time.Now()
	_, err = client.WaitForInteraction(ctx, callback.ID, 200*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected timeout error")
	}

	// Should have waited approximately the timeout duration
	if elapsed < 150*time.Millisecond {
		t.Errorf("waited too short: %v", elapsed)
	}
}

func TestClient_WaitForInteraction_ContextCanceled(t *testing.T) {
	cfg := Config{
		Mode: ModeLocal,
		Port: 0,
		Host: "localhost",
	}

	client, err := NewClient(cfg, &testEventBus{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	serverCtx, serverCancel := startClientInBackground(t, client)
	defer serverCancel()

	// Generate callback
	callback, err := client.GenerateCallback(serverCtx, "test-cancel")
	if err != nil {
		t.Fatalf("failed to generate callback: %v", err)
	}

	// Create cancelable context
	cancelCtx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	// Wait should be canceled
	_, err = client.WaitForInteraction(cancelCtx, callback.ID, 5*time.Second)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestClient_GetInteractionsByTestID(t *testing.T) {
	cfg := Config{
		Mode: ModeLocal,
		Port: 0,
		Host: "localhost",
	}

	client, err := NewClient(cfg, &testEventBus{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := startClientInBackground(t, client)
	defer cancel()

	// Get interactions by test ID (should be empty initially)
	interactions, err := client.GetInteractionsByTestID(ctx, "test-id-123")
	if err != nil {
		t.Fatalf("failed to get interactions: %v", err)
	}

	if len(interactions) != 0 {
		t.Errorf("expected 0 interactions, got %d", len(interactions))
	}
}

func TestClient_GetStats(t *testing.T) {
	cfg := Config{
		Mode: ModeLocal,
		Port: 0,
		Host: "localhost",
	}

	client, err := NewClient(cfg, &testEventBus{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, cancel := startClientInBackground(t, client)
	defer cancel()

	stats, err := client.GetStats()
	if err != nil {
		t.Fatalf("failed to get stats: %v", err)
	}

	if stats.TotalInteractions != 0 {
		t.Errorf("expected 0 total interactions, got %d", stats.TotalInteractions)
	}
}

func TestClient_Disabled_Operations(t *testing.T) {
	cfg := Config{Mode: ModeDisabled}

	client, err := NewClient(cfg, &testEventBus{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()

	// All operations should return errors when disabled
	_, err = client.GenerateCallback(ctx, "test")
	if err == nil {
		t.Error("GenerateCallback should error when disabled")
	}

	_, err = client.GenerateCallbackWithPath(ctx, "test", "/path")
	if err == nil {
		t.Error("GenerateCallbackWithPath should error when disabled")
	}

	_, err = client.CheckInteractions(ctx, "id")
	if err == nil {
		t.Error("CheckInteractions should error when disabled")
	}

	_, err = client.HasInteraction(ctx, "id")
	if err == nil {
		t.Error("HasInteraction should error when disabled")
	}

	_, err = client.WaitForInteraction(ctx, "id", time.Second)
	if err == nil {
		t.Error("WaitForInteraction should error when disabled")
	}

	_, err = client.GetInteractionsByTestID(ctx, "test")
	if err == nil {
		t.Error("GetInteractionsByTestID should error when disabled")
	}

	_, err = client.GetStats()
	if err == nil {
		t.Error("GetStats should error when disabled")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Mode != ModeLocal {
		t.Errorf("expected mode %s, got %s", ModeLocal, cfg.Mode)
	}

	if cfg.Port != 0 {
		t.Errorf("expected port 0, got %d", cfg.Port)
	}

	if cfg.Host != "localhost" {
		t.Errorf("expected host localhost, got %s", cfg.Host)
	}

	if cfg.Timeout != 5 {
		t.Errorf("expected timeout 5, got %d", cfg.Timeout)
	}
}

func TestClient_WithInteraction(t *testing.T) {
	cfg := Config{
		Mode: ModeLocal,
		Port: 0,
		Host: "localhost",
	}

	client, err := NewClient(cfg, &testEventBus{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := startClientInBackground(t, client)
	defer cancel()

	// Generate callback
	callback, err := client.GenerateCallback(ctx, "test-with-interaction")
	if err != nil {
		t.Fatalf("failed to generate callback: %v", err)
	}

	// Manually store an interaction
	storage := client.GetStorage()
	interaction := &local.Interaction{
		ID:        callback.ID,
		Timestamp: time.Now(),
		Method:    "GET",
		Path:      "/callback/" + callback.ID,
		ClientIP:  "127.0.0.1",
	}
	storage.Store(interaction)

	// Now check for interaction
	interactions, err := client.CheckInteractions(ctx, callback.ID)
	if err != nil {
		t.Fatalf("failed to check interactions: %v", err)
	}

	if len(interactions) != 1 {
		t.Errorf("expected 1 interaction, got %d", len(interactions))
	}

	// HasInteraction should return true
	has, err := client.HasInteraction(ctx, callback.ID)
	if err != nil {
		t.Fatalf("failed to check has interaction: %v", err)
	}

	if !has {
		t.Error("should have interaction")
	}
}

func TestClient_WaitForInteraction_WithInteraction(t *testing.T) {
	cfg := Config{
		Mode: ModeLocal,
		Port: 0,
		Host: "localhost",
	}

	client, err := NewClient(cfg, &testEventBus{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := startClientInBackground(t, client)
	defer cancel()

	// Generate callback
	callback, err := client.GenerateCallback(ctx, "test-wait-with")
	if err != nil {
		t.Fatalf("failed to generate callback: %v", err)
	}

	// Store interaction in background
	storage := client.GetStorage()
	go func() {
		time.Sleep(100 * time.Millisecond)
		interaction := &local.Interaction{
			ID:        callback.ID,
			Timestamp: time.Now(),
			Method:    "GET",
			Path:      "/callback/" + callback.ID,
			ClientIP:  "127.0.0.1",
		}
		storage.Store(interaction)
	}()

	// Wait should succeed
	interaction, err := client.WaitForInteraction(ctx, callback.ID, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to wait for interaction: %v", err)
	}

	if interaction == nil {
		t.Error("interaction should not be nil")
	}

	if interaction.ID != callback.ID {
		t.Errorf("expected ID %s, got %s", callback.ID, interaction.ID)
	}
}
