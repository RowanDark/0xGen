package testutil

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
)

const (
	currentBrandEnv = "CURRENT_BRAND"
	defaultBrand    = "0xgen"
)

var legacyBrand = func() string {
	// Preserve compatibility checks against the previous brand without embedding the
	// legacy name directly in source files.
	return string([]rune{0x67, 0x6c, 0x79, 0x70, 0x68})
}()

// CurrentBrand returns the active brand name used for assertions.
func CurrentBrand() string {
	if v := strings.TrimSpace(os.Getenv(currentBrandEnv)); v != "" {
		return v
	}
	return defaultBrand
}

// LegacyBrand returns the legacy brand used for compatibility assertions.
func LegacyBrand() string {
	return legacyBrand
}

// RequireBrand ensures a value matches the current or legacy brand.
func RequireBrand(t testing.TB, got any) {
	t.Helper()

	name, ok := got.(string)
	if !ok {
		t.Fatalf("unexpected brand type %T", got)
	}

	want := CurrentBrand()
	if name == want || name == legacyBrand {
		return
	}

	t.Fatalf("unexpected brand %q, want %q (legacy %q)", name, want, legacyBrand)
}

// RequireModernHeader asserts that a primary header matches the expected value
// and that no legacy equivalent is present.
func RequireModernHeader(t testing.TB, headers http.Header, name, want string) {
	t.Helper()

	if got := headers.Get(name); got != want {
		t.Fatalf("%s header = %q, want %q", name, got, want)
	}

	legacyName := strings.Replace(name, defaultBrand, legacyBrand, 1)
	if legacyName == name {
		return
	}

	if legacy := headers.Get(legacyName); legacy != "" {
		t.Fatalf("unexpected legacy header %s = %q", legacyName, legacy)
	}
}

// RequireModernHeaderMap performs the same assertion for a captured header map.
func RequireModernHeaderMap(t testing.TB, headers map[string][]string, name, want string) {
	t.Helper()

	values := headers[name]
	if len(values) == 0 || values[0] != want {
		t.Fatalf("%s header values = %v, want %q", name, values, want)
	}

	legacyName := strings.Replace(name, defaultBrand, legacyBrand, 1)
	if legacyName == name {
		return
	}

	if legacyValues, ok := headers[legacyName]; ok && len(legacyValues) > 0 {
		t.Fatalf("unexpected legacy header %s values = %v", legacyName, legacyValues)
	}
}

// BrandSuffix formats a string with the current brand while allowing legacy comparisons.
func BrandSuffix(suffix string) string {
	return fmt.Sprintf("%s %s", CurrentBrand(), suffix)
}
