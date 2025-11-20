package atlas

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestLevel_String(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarn, "WARN"},
		{LevelError, "ERROR"},
		{Level(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.level.String()
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestNewSimpleLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewSimpleLogger(&buf, LevelDebug)

	if logger == nil {
		t.Fatal("expected non-nil logger")
	}

	// Test that logger writes to the buffer
	logger.Info("test message")
	output := buf.String()

	if !strings.Contains(output, "test message") {
		t.Errorf("expected output to contain 'test message', got: %s", output)
	}

	if !strings.Contains(output, "INFO") {
		t.Errorf("expected output to contain 'INFO', got: %s", output)
	}
}

func TestSimpleLogger_WithPrefix(t *testing.T) {
	var buf bytes.Buffer
	logger := NewSimpleLogger(&buf, LevelDebug)
	prefixedLogger := logger.WithPrefix("TEST")

	prefixedLogger.Info("message")
	output := buf.String()

	if !strings.Contains(output, "[TEST]") {
		t.Errorf("expected output to contain '[TEST]', got: %s", output)
	}
}

func TestSimpleLogger_Debug(t *testing.T) {
	var buf bytes.Buffer
	logger := NewSimpleLogger(&buf, LevelDebug)

	logger.Debug("debug message")
	output := buf.String()

	if !strings.Contains(output, "DEBUG") {
		t.Errorf("expected DEBUG level, got: %s", output)
	}

	if !strings.Contains(output, "debug message") {
		t.Errorf("expected 'debug message', got: %s", output)
	}
}

func TestSimpleLogger_Info(t *testing.T) {
	var buf bytes.Buffer
	logger := NewSimpleLogger(&buf, LevelInfo)

	logger.Info("info message")
	output := buf.String()

	if !strings.Contains(output, "INFO") {
		t.Errorf("expected INFO level, got: %s", output)
	}

	if !strings.Contains(output, "info message") {
		t.Errorf("expected 'info message', got: %s", output)
	}
}

func TestSimpleLogger_Warn(t *testing.T) {
	var buf bytes.Buffer
	logger := NewSimpleLogger(&buf, LevelWarn)

	logger.Warn("warning message")
	output := buf.String()

	if !strings.Contains(output, "WARN") {
		t.Errorf("expected WARN level, got: %s", output)
	}

	if !strings.Contains(output, "warning message") {
		t.Errorf("expected 'warning message', got: %s", output)
	}
}

func TestSimpleLogger_Error(t *testing.T) {
	var buf bytes.Buffer
	logger := NewSimpleLogger(&buf, LevelError)

	logger.Error("error message")
	output := buf.String()

	if !strings.Contains(output, "ERROR") {
		t.Errorf("expected ERROR level, got: %s", output)
	}

	if !strings.Contains(output, "error message") {
		t.Errorf("expected 'error message', got: %s", output)
	}
}

func TestSimpleLogger_MinLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := NewSimpleLogger(&buf, LevelWarn)

	// Debug and Info should be filtered out
	logger.Debug("debug message")
	logger.Info("info message")

	output := buf.String()
	if strings.Contains(output, "debug message") {
		t.Error("debug message should be filtered by min level")
	}
	if strings.Contains(output, "info message") {
		t.Error("info message should be filtered by min level")
	}

	// Warn and Error should pass through
	logger.Warn("warn message")
	logger.Error("error message")

	output = buf.String()
	if !strings.Contains(output, "warn message") {
		t.Error("warn message should pass through")
	}
	if !strings.Contains(output, "error message") {
		t.Error("error message should pass through")
	}
}

func TestSimpleLogger_KeyValues(t *testing.T) {
	var buf bytes.Buffer
	logger := NewSimpleLogger(&buf, LevelInfo)

	logger.Info("test message", "key1", "value1", "key2", 42)
	output := buf.String()

	if !strings.Contains(output, "test message") {
		t.Errorf("expected 'test message' in output, got: %s", output)
	}

	if !strings.Contains(output, "key1=value1") {
		t.Errorf("expected 'key1=value1' in output, got: %s", output)
	}

	if !strings.Contains(output, "key2=42") {
		t.Errorf("expected 'key2=42' in output, got: %s", output)
	}
}

func TestSimpleLogger_Timestamp(t *testing.T) {
	var buf bytes.Buffer
	logger := NewSimpleLogger(&buf, LevelInfo)

	before := time.Now()
	logger.Info("message")
	after := time.Now()

	output := buf.String()

	// Output should contain a timestamp
	if !strings.Contains(output, "INFO") {
		t.Errorf("expected INFO level in output: %s", output)
	}

	// Check that timestamp is reasonable (just verify it has the year)
	year := before.Format("2006")
	if !strings.Contains(output, year) {
		t.Errorf("expected timestamp with year %s in output: %s", year, output)
	}

	_ = after // Use after to avoid unused variable
}

func TestSimpleLogger_ConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	logger := NewSimpleLogger(&buf, LevelInfo)

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			logger.Info("message", "id", id)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	output := buf.String()
	// Should have 10 INFO entries
	count := strings.Count(output, "INFO")
	if count != 10 {
		t.Errorf("expected 10 INFO entries, got %d", count)
	}
}

func TestNopLogger_Debug(t *testing.T) {
	logger := NewNopLogger()
	// Should not panic
	logger.Debug("debug message")
}

func TestNopLogger_Info(t *testing.T) {
	logger := NewNopLogger()
	// Should not panic
	logger.Info("info message")
}

func TestNopLogger_Warn(t *testing.T) {
	logger := NewNopLogger()
	// Should not panic
	logger.Warn("warn message")
}

func TestNopLogger_Error(t *testing.T) {
	logger := NewNopLogger()
	// Should not panic
	logger.Error("error message")
}

func TestNopLogger_AllMethods(t *testing.T) {
	logger := NewNopLogger()

	// All methods should not panic
	logger.Debug("debug")
	logger.Info("info")
	logger.Warn("warn")
	logger.Error("error")
}

func TestNopLogger_Concurrent(t *testing.T) {
	logger := NewNopLogger()

	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func(id int) {
			logger.Info("message %d", id)
			logger.Error("error %d", id)
			logger.Debug("debug %d", id)
			logger.Warn("warn %d", id)
			done <- true
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}
	// Should complete without panic
}
