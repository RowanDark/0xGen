package capabilityassert_test

import (
	"testing"

	"github.com/RowanDark/Glyph/sdk/plugin-sdk/lint/capabilityassert"
)

func TestRun(t *testing.T) {
        diags, err := capabilityassert.Run([]string{"./testdata/src/..."})
        if err != nil {
                t.Fatalf("Run: %v", err)
        }
        if len(diags) != 6 {
                t.Fatalf("expected 6 diagnostics, got %d", len(diags))
        }
}
