package runner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
)

type recordingEmitter struct {
	mu       sync.Mutex
	findings []findings.Finding
}

func (r *recordingEmitter) Emit(f findings.Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.findings = append(r.findings, f)
}

func (r *recordingEmitter) All() []findings.Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]findings.Finding, len(r.findings))
	copy(out, r.findings)
	return out
}

func buildBinary(t *testing.T, program string) string {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	if err := os.WriteFile(source, []byte(program), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	binary := executablePath(dir, "plugin")
	cmd := exec.Command("go", "build", "-o", binary, source)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build binary: %v\noutput: %s", err, output)
	}
	return binary
}

func TestSupervisorTerminatesOnTimeout(t *testing.T) {
	program := `package main
import (
        "time"
)
func main() {
        for {
                time.Sleep(50 * time.Millisecond)
        }
}`
	binary := buildBinary(t, program)
	emitter := &recordingEmitter{}
	now := time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC)
	supervisor := NewSupervisor(WithEmitter(emitter), WithClock(func() time.Time { return now }))

	result, err := supervisor.RunTask(context.Background(), Task{
		ID:       "timeout-test",
		PluginID: "sleepy",
		Config: Config{
			Binary: binary,
			Limits: Limits{WallTime: 200 * time.Millisecond},
		},
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	if result.Termination == nil {
		t.Fatalf("expected termination details (error: %v)", err)
	}
	if result.Termination.Reason != TerminationReasonTimeout {
		t.Fatalf("unexpected termination reason: %s", result.Termination.Reason)
	}

	findings := emitter.All()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.Plugin != "sleepy" {
		t.Fatalf("unexpected finding plugin: %s", finding.Plugin)
	}
	if finding.Type != terminationFindingType {
		t.Fatalf("unexpected finding type: %s", finding.Type)
	}
	if got := finding.Metadata[metaTerminationReasonKey]; got != string(TerminationReasonTimeout) {
		t.Fatalf("unexpected metadata reason: %s", got)
	}
	if detail := finding.Metadata[metaTerminationDetailKey]; !strings.Contains(detail, "wall time") {
		t.Fatalf("unexpected termination detail: %s", detail)
	}
	if !finding.DetectedAt.Time().Equal(now) {
		t.Fatalf("unexpected detected timestamp: %s", finding.DetectedAt.Time())
	}
}

func TestSupervisorTerminatesOnMemoryLimit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("memory limits are not enforced on Windows runners")
	}
	program := `package main
func main() {
        chunks := make([][]byte, 0)
        for {
                chunk := make([]byte, 32<<20)
                for i := range chunk {
                        chunk[i] = byte(i)
                }
                chunks = append(chunks, chunk)
        }
}`
	binary := buildBinary(t, program)
	emitter := &recordingEmitter{}
	supervisor := NewSupervisor(WithEmitter(emitter), WithClock(func() time.Time { return time.Now().UTC() }))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := supervisor.RunTask(ctx, Task{
		ID:       "memory-test",
		PluginID: "hog",
		Config: Config{
			Binary: binary,
			Limits: Limits{MemoryBytes: 768 << 20},
		},
	})
	if err == nil {
		t.Fatal("expected error from memory constrained plugin")
	}
	if result.Termination == nil {
		t.Fatalf("expected termination details (error: %v)", err)
	}
	if result.Termination.Reason != TerminationReasonMemoryLimit {
		t.Fatalf("unexpected termination reason: %s", result.Termination.Reason)
	}
	if result.Termination.MemoryUsage == 0 {
		t.Fatalf("expected memory usage to be recorded")
	}

	findings := emitter.All()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if got := findings[0].Metadata[metaTerminationReasonKey]; got != string(TerminationReasonMemoryLimit) {
		t.Fatalf("unexpected termination reason metadata: %s", got)
	}
}

func TestSupervisorAllowsNormalCompletion(t *testing.T) {
	program := `package main
import "fmt"
func main() {
        fmt.Println("ok")
}`
	binary := buildBinary(t, program)
	emitter := &recordingEmitter{}
	supervisor := NewSupervisor(WithEmitter(emitter))

	result, err := supervisor.RunTask(context.Background(), Task{
		ID:       "normal",
		PluginID: "friendly",
		Config:   Config{Binary: binary},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Termination != nil {
		t.Fatalf("expected no termination, got %+v", result.Termination)
	}
	if len(emitter.All()) != 0 {
		t.Fatalf("expected no findings to be emitted")
	}
}

func TestSupervisorRespectsTaskTimeout(t *testing.T) {
	program := `package main
import "time"
func main() {
        for {
                time.Sleep(20 * time.Millisecond)
        }
}`
	binary := buildBinary(t, program)
	emitter := &recordingEmitter{}
	supervisor := NewSupervisor(WithEmitter(emitter))

	result, err := supervisor.RunTask(context.Background(), Task{
		ID:       "rpc-timeout",
		PluginID: "timeout",
		Config: Config{
			Binary: binary,
			Limits: Limits{WallTime: time.Second},
		},
		Timeout: 100 * time.Millisecond,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	if result.Termination == nil {
		t.Fatalf("expected termination details")
	}
	if result.Termination.Reason != TerminationReasonTimeout {
		t.Fatalf("unexpected termination reason: %s", result.Termination.Reason)
	}
	if len(emitter.All()) == 0 {
		t.Fatalf("expected termination finding to be emitted")
	}
}

func TestSupervisorHandlesPluginCrash(t *testing.T) {
	program := `package main
func main() {
        panic("boom")
}`
	binary := buildBinary(t, program)
	emitter := &recordingEmitter{}
	supervisor := NewSupervisor(WithEmitter(emitter))

	result, err := supervisor.RunTask(context.Background(), Task{
		ID:       "crash",
		PluginID: "crashy",
		Config:   Config{Binary: binary},
	})
	if err == nil {
		t.Fatal("expected crashy plugin to return an error")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected exit error, got %T", err)
	}
	if result.Termination != nil {
		t.Fatalf("expected no sandbox termination, got %+v", result.Termination)
	}
	if len(emitter.All()) != 0 {
		t.Fatalf("expected no findings to be emitted for crash")
	}
}
