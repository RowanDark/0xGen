//go:build !windows

package runner

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
)

var limitMu sync.Mutex

func startWithLimits(cmd *exec.Cmd, lim Limits) error {
	limitMu.Lock()
	defer limitMu.Unlock()

	var (
		cpuOrig syscall.Rlimit
		memOrig syscall.Rlimit
		cpuSet  bool
		memSet  bool
	)

	if lim.CPUSeconds > 0 {
		if err := syscall.Getrlimit(syscall.RLIMIT_CPU, &cpuOrig); err != nil {
			return fmt.Errorf("get cpu limit: %w", err)
		}
		newLimit := syscall.Rlimit{Cur: lim.CPUSeconds, Max: lim.CPUSeconds}
		if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &newLimit); err != nil {
			return fmt.Errorf("set cpu limit: %w", err)
		}
		cpuSet = true
	}

	if lim.MemoryBytes > 0 {
		if err := syscall.Getrlimit(syscall.RLIMIT_AS, &memOrig); err != nil {
			return fmt.Errorf("get memory limit: %w", err)
		}
		newLimit := syscall.Rlimit{Cur: lim.MemoryBytes, Max: lim.MemoryBytes}
		if err := syscall.Setrlimit(syscall.RLIMIT_AS, &newLimit); err != nil {
			return fmt.Errorf("set memory limit: %w", err)
		}
		memSet = true
	}

	startErr := cmd.Start()

	if cpuSet {
		_ = syscall.Setrlimit(syscall.RLIMIT_CPU, &cpuOrig)
	}
	if memSet {
		_ = syscall.Setrlimit(syscall.RLIMIT_AS, &memOrig)
	}

	return startErr
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	// Negative PID targets the process group.
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
