//go:build !windows

package runner

import (
	"context"
	"syscall"
	"testing"
	"time"
)

// TestSupervisorDoesNotAlterParentRlimits guards against the regression
// where plugin resource limits were applied to the 0xgen process itself
// (via startWithLimits) instead of to the sandboxed child. Limits must be
// enforced inside the sandbox helper only; the daemon's own rlimits must be
// left untouched by a limited plugin run.
func TestSupervisorDoesNotAlterParentRlimits(t *testing.T) {
	var cpuBefore, memBefore syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CPU, &cpuBefore); err != nil {
		t.Fatalf("get baseline cpu rlimit: %v", err)
	}
	if err := syscall.Getrlimit(syscall.RLIMIT_AS, &memBefore); err != nil {
		t.Fatalf("get baseline memory rlimit: %v", err)
	}

	program := `package main
import "fmt"
func main() {
        fmt.Println("ok")
}`
	binary := buildBinary(t, program)
	sandbox := buildSandbox(t)
	supervisor := NewSupervisor()

	result, err := supervisor.RunTask(context.Background(), Task{
		ID:       "rlimit-isolation",
		PluginID: "friendly",
		Config: Config{
			Binary:        binary,
			SandboxBinary: sandbox,
			Limits: Limits{
				CPUSeconds:  5,
				MemoryBytes: 2 << 30, // generous: Go's runtime reserves virtual
				// address space well beyond actual usage, so RLIMIT_AS must
				// stay high for even a trivial binary to avoid tripping it.
			},
		},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Termination != nil {
		t.Fatalf("expected no termination, got %+v", result.Termination)
	}

	var cpuAfter, memAfter syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CPU, &cpuAfter); err != nil {
		t.Fatalf("get post-run cpu rlimit: %v", err)
	}
	if err := syscall.Getrlimit(syscall.RLIMIT_AS, &memAfter); err != nil {
		t.Fatalf("get post-run memory rlimit: %v", err)
	}

	if cpuAfter != cpuBefore {
		t.Fatalf("parent RLIMIT_CPU changed: before=%+v after=%+v", cpuBefore, cpuAfter)
	}
	if memAfter != memBefore {
		t.Fatalf("parent RLIMIT_AS changed: before=%+v after=%+v", memBefore, memAfter)
	}
}
