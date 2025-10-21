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
	legacyBrand     = "Glyph"
)

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

// LegacyHeaderName converts a modern header name to its legacy equivalent.
func LegacyHeaderName(name string) string {
	if !strings.Contains(name, defaultBrand) {
		return name
	}
	return strings.Replace(name, defaultBrand, legacyBrand, 1)
}

// RequireHeaderWithLegacy asserts that a primary header matches the expected value
// and validates any legacy equivalent if present.
func RequireHeaderWithLegacy(t testing.TB, headers http.Header, name, want string) {
	t.Helper()

	if got := headers.Get(name); got != want {
		t.Fatalf("%s header = %q, want %q", name, got, want)
	}

	legacyName := LegacyHeaderName(name)
	if legacyName == name {
		return
	}

	if legacy := headers.Get(legacyName); legacy != "" && legacy != want {
		t.Fatalf("%s header = %q, want %q", legacyName, legacy, want)
	}
}

// RequireHeaderMapWithLegacy performs the same assertion for a captured header map.
func RequireHeaderMapWithLegacy(t testing.TB, headers map[string][]string, name, want string) {
	t.Helper()

	values := headers[name]
	if len(values) == 0 || values[0] != want {
		t.Fatalf("%s header values = %v, want %q", name, values, want)
	}

	legacyName := LegacyHeaderName(name)
	if legacyName == name {
		return
	}

	if legacyValues, ok := headers[legacyName]; ok {
		if len(legacyValues) == 0 || legacyValues[0] != want {
			t.Fatalf("%s header values = %v, want %q", legacyName, legacyValues, want)
		}
	}
}

// BrandSuffix formats a string with the current brand while allowing legacy comparisons.
func BrandSuffix(suffix string) string {
	return fmt.Sprintf("%s %s", CurrentBrand(), suffix)
}
