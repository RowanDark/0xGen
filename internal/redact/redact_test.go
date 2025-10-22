package redact

import (
	"reflect"
	"testing"
)

func TestMapAppliesNeverPersistMask(t *testing.T) {
	input := map[string]any{
		"api_token":     "super-secret-value",
		"nested":        []any{"token=abc123456789"},
		"never_persist": []any{"api_token", "missing"},
	}
	masked := Map(input)
	if _, exists := masked["never_persist"]; exists {
		t.Fatalf("never_persist key should be removed")
	}
	if val, ok := masked["api_token"].(string); !ok || val != "[REDACTED_SECRET]" {
		t.Fatalf("expected api_token to be masked, got %#v", masked["api_token"])
	}
	nested, ok := masked["nested"].([]any)
	if !ok || len(nested) != 1 {
		t.Fatalf("expected nested slice to be preserved, got %#v", masked["nested"])
	}
	if item, _ := nested[0].(string); item != "token=[REDACTED_SECRET]" {
		t.Fatalf("expected nested value to be redacted, got %q", item)
	}
}

func TestMapStringAppliesNeverPersistMask(t *testing.T) {
	input := map[string]string{
		"api_token":     "super-secret-value",
		"another_field": "ok",
		"never_persist": "api_token, missing",
	}
	masked := MapString(input)
	if _, exists := masked["never_persist"]; exists {
		t.Fatalf("never_persist key should be removed")
	}
	if val := masked["api_token"]; val != "[REDACTED_SECRET]" {
		t.Fatalf("expected api_token to be masked, got %q", val)
	}
	if val := masked["another_field"]; val != "ok" {
		t.Fatalf("unexpected value for another_field: %q", val)
	}
}

func TestMapNilAndEmpty(t *testing.T) {
	if got := Map(nil); got != nil {
		t.Fatalf("expected nil input to return nil, got %#v", got)
	}
	if got := Map(map[string]any{}); got != nil {
		t.Fatalf("expected empty map to return nil, got %#v", got)
	}
	if got := MapString(nil); got != nil {
		t.Fatalf("expected nil string map to return nil, got %#v", got)
	}
	if got := MapString(map[string]string{}); got != nil {
		t.Fatalf("expected empty string map to return nil, got %#v", got)
	}
}

func TestSliceRedactsValues(t *testing.T) {
	out := Slice([]string{"token=secretvalue123456", "  "})
	expected := []string{"token=[REDACTED_SECRET]", "  "}
	if !reflect.DeepEqual(out, expected) {
		t.Fatalf("expected %v, got %v", expected, out)
	}
}
