//go:build !windows

package runner

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"syscall"
	"time"
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

	usage, _ := exitErr.ProcessState.SysUsage().(*syscall.Rusage)
	if lim.MemoryBytes > 0 && usage != nil {
		rss := rssFromRusage(usage)
		if rss >= lim.MemoryBytes {
			detail := fmt.Sprintf("plugin exceeded memory limit (%d bytes >= %d bytes)", rss, lim.MemoryBytes)
			return &Termination{
				Reason:      TerminationReasonMemoryLimit,
				Detail:      detail,
				MemoryLimit: lim.MemoryBytes,
				MemoryUsage: rss,
			}
		}
	}
	if lim.CPUSeconds > 0 && usage != nil {
		cpu := cpuFromRusage(usage)
		limit := time.Duration(lim.CPUSeconds) * time.Second
		if cpu >= limit {
			detail := fmt.Sprintf("plugin exceeded CPU time limit (%s >= %s)", cpu, limit)
			return &Termination{
				Reason:   TerminationReasonCPULimit,
				Detail:   detail,
				CPULimit: limit,
				CPUUsage: cpu,
			}
		}
	}

	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		return nil
	}
	if lim.MemoryBytes > 0 && status.Exited() && status.ExitStatus() == 2 {
		rss := uint64(0)
		if usage != nil {
			rss = rssFromRusage(usage)
		}
		detail := fmt.Sprintf("plugin exited with non-zero status under memory pressure (limit %d bytes)", lim.MemoryBytes)
		return &Termination{
			Reason:      TerminationReasonMemoryLimit,
			Detail:      detail,
			MemoryLimit: lim.MemoryBytes,
			MemoryUsage: rss,
		}
	}
	if status.Signaled() {
		reason := TerminationReasonKilled
		detail := fmt.Sprintf("plugin terminated by signal %s", status.Signal())
		if status.Signal() == syscall.SIGKILL && lim.MemoryBytes > 0 {
			reason = TerminationReasonMemoryLimit
			detail = fmt.Sprintf("plugin killed after exceeding memory limit (%d bytes)", lim.MemoryBytes)
		}
		if status.Signal() == syscall.SIGXCPU && lim.CPUSeconds > 0 {
			reason = TerminationReasonCPULimit
			limit := time.Duration(lim.CPUSeconds) * time.Second
			detail = fmt.Sprintf("plugin killed after exceeding CPU time limit (%s)", limit)
		}
		return &Termination{
			Reason:      reason,
			Detail:      detail,
			MemoryLimit: lim.MemoryBytes,
			CPULimit:    time.Duration(lim.CPUSeconds) * time.Second,
		}
	}
	return nil
}

func rssFromRusage(usage *syscall.Rusage) uint64 {
	if usage == nil {
		return 0
	}
	rss := uint64(usage.Maxrss)
	switch runtime.GOOS {
	case "darwin":
		// Darwin already reports bytes.
	default:
		rss *= 1024 // Linux reports kilobytes.
	}
	return rss
}

func cpuFromRusage(usage *syscall.Rusage) time.Duration {
	if usage == nil {
		return 0
	}
	user := time.Duration(usage.Utime.Sec)*time.Second + time.Duration(usage.Utime.Usec)*time.Microsecond
	sys := time.Duration(usage.Stime.Sec)*time.Second + time.Duration(usage.Stime.Usec)*time.Microsecond
	return user + sys
}
