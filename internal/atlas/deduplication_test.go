package atlas

import (
	"strings"
	"testing"
)

func TestDeduplicator_Deduplicate(t *testing.T) {
	dedup := NewDeduplicator()

	finding1 := &Finding{
		Type:      "SQL Injection (Error-based)",
		URL:       "http://example.com/user?id=1",
		Parameter: "id",
		Location:  ParamLocationQuery,
		Method:    "GET",
		Proof:     "SQL error detected",
	}

	finding2 := &Finding{
		Type:      "SQL Injection (Error-based)",
		URL:       "http://example.com/user?id=2", // Different param value
		Parameter: "id",
		Location:  ParamLocationQuery,
		Method:    "GET",
		Proof:     "SQL error detected again",
	}

	// First finding should be unique
	result1, isDup := dedup.Deduplicate(finding1)
	if isDup {
		t.Error("First finding should not be a duplicate")
	}
	if result1 != finding1 {
		t.Error("First finding should be returned as-is")
	}

	// Second finding should be duplicate (same URL path + param)
	result2, isDup := dedup.Deduplicate(finding2)
	if !isDup {
		t.Error("Second finding should be a duplicate")
	}

	// Should have only 1 unique finding
	unique := dedup.GetUniqueFindings()
	if len(unique) != 1 {
		t.Errorf("expected 1 unique finding, got %d", len(unique))
	}

	// Check occurrence count
	if result2.Metadata == nil {
		t.Fatal("Metadata should be set on merged finding")
	}
	count, ok := result2.Metadata["occurrence_count"].(int)
	if !ok || count != 1 {
		t.Errorf("expected occurrence_count=1, got %v", count)
	}
}

func TestDeduplicator_DifferentParameters(t *testing.T) {
	dedup := NewDeduplicator()

	finding1 := &Finding{
		Type:      "SQL Injection (Error-based)",
		URL:       "http://example.com/user",
		Parameter: "id",
		Location:  ParamLocationQuery,
		Method:    "GET",
	}

	finding2 := &Finding{
		Type:      "SQL Injection (Error-based)",
		URL:       "http://example.com/user",
		Parameter: "name", // Different parameter
		Location:  ParamLocationQuery,
		Method:    "GET",
	}

	dedup.Deduplicate(finding1)
	_, isDup := dedup.Deduplicate(finding2)

	// Different parameters should not be duplicates
	if isDup {
		t.Error("Findings with different parameters should not be duplicates")
	}

	unique := dedup.GetUniqueFindings()
	if len(unique) != 2 {
		t.Errorf("expected 2 unique findings, got %d", len(unique))
	}
}

func TestDeduplicator_ConfidenceUpgrade(t *testing.T) {
	dedup := NewDeduplicator()

	finding1 := &Finding{
		Type:       "SQL Injection (Error-based)",
		URL:        "http://example.com/user?id=1",
		Parameter:  "id",
		Location:   ParamLocationQuery,
		Method:     "GET",
		Confidence: ConfidenceTentative,
		Proof:      "Possible SQL error",
	}

	finding2 := &Finding{
		Type:       "SQL Injection (Error-based)",
		URL:        "http://example.com/user?id=2",
		Parameter:  "id",
		Location:   ParamLocationQuery,
		Method:     "GET",
		Confidence: ConfidenceConfirmed,
		Proof:      "Confirmed SQL injection",
	}

	dedup.Deduplicate(finding1)
	result, _ := dedup.Deduplicate(finding2)

	// Confidence should be upgraded to Confirmed
	if result.Confidence != ConfidenceConfirmed {
		t.Errorf("expected Confirmed confidence, got %s", result.Confidence)
	}

	// Proof should contain the confirmed finding's proof
	if !strings.Contains(result.Proof, finding2.Proof) {
		t.Error("Proof should contain confirmed finding's proof")
	}
}

func TestDeduplicator_GetUniqueFindings_Sorted(t *testing.T) {
	dedup := NewDeduplicator()

	// Add findings with different severities
	findings := []*Finding{
		{
			ID:         "1",
			Type:       "XSS",
			URL:        "http://example.com/1",
			Parameter:  "q",
			Location:   ParamLocationQuery,
			Method:     "GET",
			Severity:   SeverityLow,
			Confidence: ConfidenceFirm,
		},
		{
			ID:         "2",
			Type:       "SQLi",
			URL:        "http://example.com/2",
			Parameter:  "id",
			Location:   ParamLocationQuery,
			Method:     "GET",
			Severity:   SeverityCritical,
			Confidence: ConfidenceConfirmed,
		},
		{
			ID:         "3",
			Type:       "SSRF",
			URL:        "http://example.com/3",
			Parameter:  "url",
			Location:   ParamLocationQuery,
			Method:     "GET",
			Severity:   SeverityHigh,
			Confidence: ConfidenceTentative,
		},
	}

	for _, f := range findings {
		dedup.Deduplicate(f)
	}

	sorted := dedup.GetUniqueFindings()

	// Should be sorted by severity (Critical > High > Low)
	if len(sorted) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(sorted))
	}

	if sorted[0].Severity != SeverityCritical {
		t.Errorf("first finding should be Critical, got %s", sorted[0].Severity)
	}

	if sorted[1].Severity != SeverityHigh {
		t.Errorf("second finding should be High, got %s", sorted[1].Severity)
	}

	if sorted[2].Severity != SeverityLow {
		t.Errorf("third finding should be Low, got %s", sorted[2].Severity)
	}
}

func TestDeduplicator_PayloadTracking(t *testing.T) {
	dedup := NewDeduplicator()

	finding1 := &Finding{
		Type:      "SQL Injection (Error-based)",
		URL:       "http://example.com/user",
		Parameter: "id",
		Location:  ParamLocationQuery,
		Method:    "GET",
		Payload:   "' OR 1=1--",
	}

	finding2 := &Finding{
		Type:      "SQL Injection (Error-based)",
		URL:       "http://example.com/user",
		Parameter: "id",
		Location:  ParamLocationQuery,
		Method:    "GET",
		Payload:   "' UNION SELECT NULL--",
	}

	dedup.Deduplicate(finding1)
	result, _ := dedup.Deduplicate(finding2)

	// Should track multiple payloads
	if result.Metadata == nil {
		t.Fatal("Metadata should be set")
	}

	payloads, ok := result.Metadata["payloads"].([]string)
	if !ok {
		t.Fatal("Payloads should be tracked in metadata")
	}

	if len(payloads) != 1 {
		t.Errorf("expected 1 additional payload, got %d", len(payloads))
	}
}

func TestDeduplicator_Count(t *testing.T) {
	dedup := NewDeduplicator()

	if dedup.Count() != 0 {
		t.Error("New deduplicator should have count 0")
	}

	finding := &Finding{
		Type:      "SQL Injection (Error-based)",
		URL:       "http://example.com/user",
		Parameter: "id",
		Location:  ParamLocationQuery,
		Method:    "GET",
	}

	dedup.Deduplicate(finding)

	if dedup.Count() != 1 {
		t.Errorf("expected count 1, got %d", dedup.Count())
	}
}

func TestDeduplicator_Clear(t *testing.T) {
	dedup := NewDeduplicator()

	finding := &Finding{
		Type:      "SQL Injection (Error-based)",
		URL:       "http://example.com/user",
		Parameter: "id",
		Location:  ParamLocationQuery,
		Method:    "GET",
	}

	dedup.Deduplicate(finding)
	dedup.Clear()

	if dedup.Count() != 0 {
		t.Error("Clear should reset count to 0")
	}

	unique := dedup.GetUniqueFindings()
	if len(unique) != 0 {
		t.Error("Clear should remove all findings")
	}
}
