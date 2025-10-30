package replay

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
)

func TestOrderFindingsRespectsManifest(t *testing.T) {
	first := findings.Finding{ID: "01HV7RCFF0J1AY7P5Z9Q4C1100", Version: findings.SchemaVersion, Plugin: "seer", Type: "a", Message: "msg", Severity: findings.SeverityHigh, DetectedAt: findings.NewTimestamp(time.Unix(1700, 0).UTC())}
	second := findings.Finding{ID: "01HV7RCFF0J1AY7P5Z9Q4C1101", Version: findings.SchemaVersion, Plugin: "seer", Type: "b", Message: "msg", Severity: findings.SeverityLow, DetectedAt: findings.NewTimestamp(time.Unix(1701, 0).UTC())}

	ordered := OrderFindings([]findings.Finding{first, second}, []string{"01HV7RCFF0J1AY7P5Z9Q4C1101", "01HV7RCFF0J1AY7P5Z9Q4C1100"})
	if len(ordered) != 2 {
		t.Fatalf("unexpected length: %d", len(ordered))
	}
	if ordered[0].ID != "01HV7RCFF0J1AY7P5Z9Q4C1101" || ordered[1].ID != "01HV7RCFF0J1AY7P5Z9Q4C1100" {
		t.Fatalf("unexpected order: %v", []string{ordered[0].ID, ordered[1].ID})
	}
}

func TestComputeFindingsDigest(t *testing.T) {
	first := findings.Finding{ID: "01HV7RCFF0J1AY7P5Z9Q4C1100", Version: findings.SchemaVersion, Plugin: "seer", Type: "a", Message: "msg", Severity: findings.SeverityHigh, DetectedAt: findings.NewTimestamp(time.Unix(1700, 0).UTC())}
	second := findings.Finding{ID: "01HV7RCFF0J1AY7P5Z9Q4C1101", Version: findings.SchemaVersion, Plugin: "seer", Type: "b", Message: "msg", Severity: findings.SeverityLow, DetectedAt: findings.NewTimestamp(time.Unix(1701, 0).UTC())}

	digestA, err := ComputeFindingsDigest([]findings.Finding{first, second}, []string{"01HV7RCFF0J1AY7P5Z9Q4C1101", "01HV7RCFF0J1AY7P5Z9Q4C1100"}, "sha256")
	if err != nil {
		t.Fatalf("ComputeFindingsDigest failed: %v", err)
	}
	digestB, err := ComputeFindingsDigest([]findings.Finding{second, first}, []string{"01HV7RCFF0J1AY7P5Z9Q4C1101", "01HV7RCFF0J1AY7P5Z9Q4C1100"}, "sha256")
	if err != nil {
		t.Fatalf("ComputeFindingsDigest failed: %v", err)
	}
	if digestA != digestB {
		t.Fatalf("expected stable digest, got %q vs %q", digestA, digestB)
	}
	if _, err := ComputeFindingsDigest([]findings.Finding{first}, nil, "md5"); err == nil {
		t.Fatalf("expected error for unsupported algorithm")
	}
}

func TestWriteFindings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	first := findings.Finding{ID: "01HV7RCFF0J1AY7P5Z9Q4C1100", Version: findings.SchemaVersion, Plugin: "seer", Type: "a", Message: "msg", Severity: findings.SeverityHigh, DetectedAt: findings.NewTimestamp(time.Unix(1700, 0).UTC())}
	second := findings.Finding{ID: "01HV7RCFF0J1AY7P5Z9Q4C1101", Version: findings.SchemaVersion, Plugin: "seer", Type: "b", Message: "msg", Severity: findings.SeverityLow, DetectedAt: findings.NewTimestamp(time.Unix(1701, 0).UTC())}

	if err := WriteFindings(path, []findings.Finding{first, second}); err != nil {
		t.Fatalf("WriteFindings failed: %v", err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open written findings: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var ids []string
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		var record findings.Finding
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode finding: %v", err)
		}
		ids = append(ids, record.ID)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan findings: %v", err)
	}
	if len(ids) != 2 || ids[0] != "01HV7RCFF0J1AY7P5Z9Q4C1100" || ids[1] != "01HV7RCFF0J1AY7P5Z9Q4C1101" {
		t.Fatalf("unexpected ids: %v", ids)
	}
}
