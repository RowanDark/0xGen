//go:build windows

package runner

import (
	"os/exec"
	"sync"
)

var limitMu sync.Mutex

func startWithLimits(cmd *exec.Cmd, _ Limits) error {
	limitMu.Lock()
	defer limitMu.Unlock()
	return cmd.Start()
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
