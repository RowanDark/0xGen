package capabilityassert_test

import (
	"testing"

	"github.com/RowanDark/0xgen/sdk/plugin-sdk/lint/capabilityassert"
)

func TestRun(t *testing.T) {
	diags, err := capabilityassert.Run([]string{"./testdata/src/..."})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(diags) != 8 {
		t.Fatalf("expected 8 diagnostics, got %d", len(diags))
	}
}
