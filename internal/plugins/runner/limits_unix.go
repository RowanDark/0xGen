//go:build !windows

package runner

import (
	"os/exec"
	"syscall"
)

// Resource limits (RLIMIT_CPU, RLIMIT_AS) are applied inside the sandbox
// helper child process (see sandboxcmd/main.go), never on this process.
// Applying them here would rate-limit or OOM-kill the daemon itself: once
// an unprivileged process lowers its own hard limit it can never raise it
// back, and while a limit is in effect it caps every goroutine in the
// process, not just the plugin being started.

func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	// Negative PID targets the process group.
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
