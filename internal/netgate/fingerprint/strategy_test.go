package fingerprint

import (
	"crypto/tls"
	"fmt"
	"testing"
)

func TestDefaultStrategyAddsHTTP3Protocol(t *testing.T) {
	strategy := DefaultStrategy()
	cfg := strategy.TLSConfigForHost("example.com", &tls.Config{})
	if !containsProto(cfg.NextProtos, "h3") {
		t.Fatalf("expected h3 in NextProtos, got %v", cfg.NextProtos)
	}
	if !containsProto(cfg.NextProtos, "h2") {
		t.Fatalf("expected h2 in NextProtos, got %v", cfg.NextProtos)
	}
}

func TestStrategyRotationToggle(t *testing.T) {
	strategy := DefaultStrategy()
	initial := uniqueProfiles(strategy, 5)
	if len(initial) != 1 {
		t.Fatalf("expected a single profile before rotation, got %d", len(initial))
	}
	strategy.EnableRotation(true)
	rotated := uniqueProfiles(strategy, 8)
	if len(rotated) <= 1 {
		t.Fatalf("expected rotation to produce multiple profiles, got %v", rotated)
	}
}

func containsProto(list []string, proto string) bool {
	for _, v := range list {
		if v == proto {
			return true
		}
	}
	return false
}

func uniqueProfiles(strategy *Strategy, count int) map[string]struct{} {
	profiles := make(map[string]struct{})
	for i := 0; i < count; i++ {
		host := fmt.Sprintf("host-%d.example.com", i)
		profile := strategy.profileForHost(host)
		if profile.Name != "" {
			profiles[profile.Name] = struct{}{}
		}
	}
	return profiles
}
