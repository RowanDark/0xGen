//go:build windows

package runner

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
)

func classifyTermination(err error, lim Limits) *Termination {
	if errors.Is(err, context.DeadlineExceeded) {
		detail := "plugin exceeded wall time limit"
		if lim.WallTime > 0 {
			detail = fmt.Sprintf("plugin exceeded wall time limit of %s", lim.WallTime)
		}
		return &Termination{
			Reason:    TerminationReasonTimeout,
			Detail:    detail,
			WallLimit: lim.WallTime,
		}
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return nil
	}

	// Windows runners do not currently enforce CPU or memory limits for plugins, so
	// we conservatively report no structured termination reason beyond wall time.
	if exitErr.ExitCode() != 0 && lim.WallTime > 0 {
		return &Termination{
			Reason:    TerminationReasonTimeout,
			Detail:    fmt.Sprintf("plugin exited with status %d after wall time enforcement", exitErr.ExitCode()),
			WallLimit: lim.WallTime,
		}
	}

	return nil
}
