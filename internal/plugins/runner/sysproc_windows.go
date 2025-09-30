//go:build windows

package runner

import "os/exec"

func configureSysProc(cmd *exec.Cmd) {
	// Windows does not support process groups in the same way as POSIX systems.
	// The default configuration is sufficient for our sandbox.
}
