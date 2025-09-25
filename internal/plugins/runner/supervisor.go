package runner

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
)

const (
	terminationFindingType        = "glyph.supervisor.termination"
	metaTerminationReasonKey      = "sandbox.termination_reason"
	metaTerminationDetailKey      = "sandbox.termination_detail"
	metaTerminationTaskIDKey      = "sandbox.task_id"
	metaTerminationMemoryLimitKey = "sandbox.memory_limit_bytes"
	metaTerminationMemoryUsageKey = "sandbox.memory_usage_bytes"
	metaTerminationCPULimitKey    = "sandbox.cpu_limit"
	metaTerminationCPUUsageKey    = "sandbox.cpu_usage"
	metaTerminationWallLimitKey   = "sandbox.wall_time_limit"
)

type findingsEmitter interface {
	Emit(findings.Finding)
}

// TerminationReason captures the high level supervisor reason for stopping a plugin.
type TerminationReason string

const (
	TerminationReasonNone        TerminationReason = ""
	TerminationReasonTimeout     TerminationReason = "timeout"
	TerminationReasonMemoryLimit TerminationReason = "memory_limit"
	TerminationReasonCPULimit    TerminationReason = "cpu_limit"
	TerminationReasonKilled      TerminationReason = "killed"
)

// Termination summarises why the supervisor stopped a plugin task.
type Termination struct {
	Reason      TerminationReason
	Detail      string
	WallLimit   time.Duration
	MemoryLimit uint64
	MemoryUsage uint64
	CPULimit    time.Duration
	CPUUsage    time.Duration
}

// Task encapsulates a plugin execution request handled by the supervisor.
type Task struct {
	ID       string
	PluginID string
	Config   Config
	Timeout  time.Duration
}

// Result captures the outcome of a supervisor task execution.
type Result struct {
	Termination *Termination
}

// Supervisor orchestrates plugin execution and enforces sandbox policies.
type Supervisor struct {
	emitter findingsEmitter
	clock   func() time.Time
}

// SupervisorOption configures the supervisor.
type SupervisorOption func(*Supervisor)

// WithEmitter configures a findings emitter used to record sandbox terminations.
func WithEmitter(emitter findingsEmitter) SupervisorOption {
	return func(s *Supervisor) {
		s.emitter = emitter
	}
}

// WithClock overrides the time source used when emitting findings.
func WithClock(clock func() time.Time) SupervisorOption {
	return func(s *Supervisor) {
		if clock != nil {
			s.clock = clock
		}
	}
}

// NewSupervisor constructs a new supervisor instance.
func NewSupervisor(opts ...SupervisorOption) *Supervisor {
	s := &Supervisor{clock: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// RunTask executes the provided task, enforcing any configured limits. The returned result
// contains termination details when the sandbox stops the plugin. The method returns the
// underlying execution error (if any) so callers can propagate failures upstream.
func (s *Supervisor) RunTask(ctx context.Context, task Task) (Result, error) {
	if strings.TrimSpace(task.PluginID) == "" {
		return Result{}, errors.New("task requires plugin id")
	}
	cfg := task.Config
	if task.Timeout > 0 {
		if cfg.Limits.WallTime == 0 || task.Timeout < cfg.Limits.WallTime {
			cfg.Limits.WallTime = task.Timeout
		}
	}
	taskCtx := ctx
	if taskCtx == nil {
		taskCtx = context.Background()
	}
	if task.Timeout > 0 {
		var cancel context.CancelFunc
		taskCtx, cancel = context.WithTimeout(taskCtx, task.Timeout)
		defer cancel()
	}

	err := Run(taskCtx, cfg)
	if err == nil {
		return Result{}, nil
	}

	termination := classifyTermination(err, cfg.Limits)
	if termination != nil {
		s.logTermination(task, *termination)
		return Result{Termination: termination}, err
	}
	return Result{}, err
}

func (s *Supervisor) logTermination(task Task, term Termination) {
	if s.emitter == nil {
		return
	}
	pluginID := strings.TrimSpace(task.PluginID)
	if pluginID == "" {
		return
	}
	metadata := map[string]string{
		metaTerminationReasonKey: string(term.Reason),
	}
	if taskID := strings.TrimSpace(task.ID); taskID != "" {
		metadata[metaTerminationTaskIDKey] = taskID
	}
	if detail := strings.TrimSpace(term.Detail); detail != "" {
		metadata[metaTerminationDetailKey] = detail
	}
	if term.MemoryLimit > 0 {
		metadata[metaTerminationMemoryLimitKey] = strconv.FormatUint(term.MemoryLimit, 10)
	}
	if term.MemoryUsage > 0 {
		metadata[metaTerminationMemoryUsageKey] = strconv.FormatUint(term.MemoryUsage, 10)
	}
	if term.CPULimit > 0 {
		metadata[metaTerminationCPULimitKey] = term.CPULimit.String()
	}
	if term.CPUUsage > 0 {
		metadata[metaTerminationCPUUsageKey] = term.CPUUsage.String()
	}
	if term.WallLimit > 0 {
		metadata[metaTerminationWallLimitKey] = term.WallLimit.String()
	}

	finding := findings.Finding{
		Version:    findings.SchemaVersion,
		ID:         findings.NewID(),
		Plugin:     pluginID,
		Type:       terminationFindingType,
		Message:    fmt.Sprintf("plugin terminated (%s)", string(term.Reason)),
		Severity:   findings.SeverityHigh,
		DetectedAt: findings.NewTimestamp(s.clock().UTC()),
		Metadata:   metadata,
	}
	s.emitter.Emit(finding)
}

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
