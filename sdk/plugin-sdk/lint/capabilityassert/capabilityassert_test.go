package capabilityassert_test

import (
	"testing"

	"github.com/RowanDark/Glyph/sdk/plugin-sdk/lint/capabilityassert"
)

func TestRun(t *testing.T) {
	diags, err := capabilityassert.Run([]string{"./testdata/src/a"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(diags) != 4 {
		t.Fatalf("expected 4 diagnostics, got %d", len(diags))
	}
}
