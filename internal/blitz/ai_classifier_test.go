package blitz

import (
	"testing"
	"time"
)

func TestAIClassifier_ClassifySQLError(t *testing.T) {
	classifier := NewAIClassifier()

	result := &FuzzResult{
		Payload: "' OR 1=1--",
		Response: MessageSnapshot{
			Body: "You have an error in your SQL syntax; check the manual...",
		},
		StatusCode: 500,
		Timestamp:  time.Now(),
	}

	classifications := classifier.Classify(result)

	if len(classifications) == 0 {
		t.Fatal("Expected at least one classification")
	}

	found := false
	for _, c := range classifications {
		if c.Category == ClassCategorySQLError {
			found = true
			if c.CWE != "CWE-89" {
				t.Errorf("Expected CWE-89, got %s", c.CWE)
			}
			if c.Confidence < 0.8 {
				t.Errorf("Expected high confidence, got %.2f", c.Confidence)
			}
		}
	}

	if !found {
		t.Error("Expected SQL error classification")
	}
}

func TestAIClassifier_ClassifyXSS(t *testing.T) {
	classifier := NewAIClassifier()

	result := &FuzzResult{
		Payload: "<script>alert(1)</script>",
		Response: MessageSnapshot{
			Body: "Your comment: <script>alert(1)</script> was posted",
		},
		StatusCode: 200,
		Timestamp:  time.Now(),
	}

	classifications := classifier.Classify(result)

	found := false
	for _, c := range classifications {
		if c.Category == ClassCategoryXSSReflection {
			found = true
			if c.CWE != "CWE-79" {
				t.Errorf("Expected CWE-79, got %s", c.CWE)
			}
		}
	}

	if !found {
		t.Error("Expected XSS reflection classification")
	}
}

func TestAIClassifier_ClassifyCommandExecution(t *testing.T) {
	classifier := NewAIClassifier()

	result := &FuzzResult{
		Payload: "; whoami",
		Response: MessageSnapshot{
			Body: "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
		},
		StatusCode: 200,
		Timestamp:  time.Now(),
	}

	classifications := classifier.Classify(result)

	found := false
	for _, c := range classifications {
		if c.Category == ClassCategoryCmdExecution {
			found = true
			if c.Severity != "critical" {
				t.Errorf("Expected critical severity, got %s", c.Severity)
			}
		}
	}

	if !found {
		t.Error("Expected command execution classification")
	}
}

func TestAIClassifier_ClassifyWithContext(t *testing.T) {
	classifier := NewAIClassifier()

	result := &FuzzResult{
		Payload: "' OR 1=1--",
		Response: MessageSnapshot{
			Body: "SQL syntax error near ' OR 1=1--",
		},
		StatusCode: 500,
		Timestamp:  time.Now(),
	}

	classifications := classifier.ClassifyWithContext(result, result.Payload)

	if len(classifications) == 0 {
		t.Fatal("Expected classifications")
	}

	// Should have slightly higher confidence when payload is reflected
	for _, c := range classifications {
		if c.Confidence == 0 {
			t.Error("Expected non-zero confidence")
		}
	}
}

func TestAIClassifier_GetTopClassification(t *testing.T) {
	classifier := NewAIClassifier()

	classifications := []Classification{
		{Category: ClassCategorySQLError, Confidence: 0.95},
		{Category: ClassCategoryErrorMessage, Confidence: 0.70},
	}

	top := classifier.GetTopClassification(classifications)

	if top == nil {
		t.Fatal("Expected top classification")
	}

	if top.Category != ClassCategorySQLError {
		t.Errorf("Expected SQL error as top, got %s", top.Category)
	}

	if top.Confidence != 0.95 {
		t.Errorf("Expected confidence 0.95, got %.2f", top.Confidence)
	}
}

func TestAIClassifier_NoClassificationForCleanResponse(t *testing.T) {
	classifier := NewAIClassifier()

	result := &FuzzResult{
		Payload: "test",
		Response: MessageSnapshot{
			Body: "Welcome to our site! Everything is working normally.",
		},
		StatusCode: 200,
		Timestamp:  time.Now(),
	}

	classifications := classifier.Classify(result)

	if len(classifications) > 0 {
		t.Errorf("Expected no classifications for clean response, got %d", len(classifications))
	}
}

func TestAIClassifier_SensitiveDataDetection(t *testing.T) {
	classifier := NewAIClassifier()

	result := &FuzzResult{
		Payload: "test",
		Response: MessageSnapshot{
			Body: "User email: john.doe@example.com, SSN: 123-45-6789",
		},
		StatusCode: 200,
		Timestamp:  time.Now(),
	}

	classifications := classifier.Classify(result)

	if len(classifications) == 0 {
		t.Fatal("Expected sensitive data classification")
	}

	foundEmail := false
	foundSSN := false

	for _, c := range classifications {
		if c.Category == ClassCategorySensitiveData {
			if contains([]string{c.Evidence}, "@") {
				foundEmail = true
			}
			if contains([]string{c.Evidence}, "123-45-6789") {
				foundSSN = true
			}
		}
	}

	if !foundEmail && !foundSSN {
		t.Error("Expected email or SSN detection")
	}
}
