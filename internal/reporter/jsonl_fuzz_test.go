package reporter

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzJSONLReadAll(f *testing.F) {
	valid := []byte("{\"id\":\"01HZXK4QAZ3ZKAB1Y7P5Z9Q4C4\",\"plugin\":\"p\",\"type\":\"t\",\"message\":\"m\",\"severity\":\"low\",\"detected_at\":\"2024-01-01T00:00:00Z\"}\n")
	f.Add(valid)
	f.Add([]byte("\n"))
	f.Add([]byte("{bad json}\n"))
	f.Add(append(valid, valid...))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "fuzz.jsonl")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Skip()
		}

		reporter := NewJSONL(path)
		defer func() {
			_ = reporter.Close()
		}()

		_, _ = reporter.ReadAll()
	})
}
