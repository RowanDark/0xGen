package runner

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
	"github.com/RowanDark/0xgen/internal/observability/tracing"
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
	attrs := map[string]any{
		"glyph.task.id":       strings.TrimSpace(task.ID),
		"glyph.plugin.id":     strings.TrimSpace(task.PluginID),
		"glyph.runner.binary": cfg.Binary,
	}
	if cfg.Limits.CPUSeconds > 0 {
		attrs["glyph.runner.cpu_seconds"] = cfg.Limits.CPUSeconds
	}
	if cfg.Limits.MemoryBytes > 0 {
		attrs["glyph.runner.memory_bytes"] = cfg.Limits.MemoryBytes
	}
	if cfg.Limits.WallTime > 0 {
		attrs["glyph.runner.wall_time"] = cfg.Limits.WallTime.String()
	}
	spanCtx, span := tracing.StartSpan(taskCtx, "plugin.supervisor.task", tracing.WithSpanKind(tracing.SpanKindInternal), tracing.WithAttributes(attrs))
	status := tracing.StatusOK
	statusMsg := ""
	defer func() {
		if span == nil {
			return
		}
		span.EndWithStatus(status, statusMsg)
	}()
	taskCtx = spanCtx
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
		span.RecordError(err)
		span.SetAttribute("glyph.task.termination", string(termination.Reason))
		if detail := strings.TrimSpace(termination.Detail); detail != "" {
			span.SetAttribute("glyph.task.detail", detail)
		}
		status = tracing.StatusError
		statusMsg = "plugin terminated"
		s.logTermination(task, *termination)
		return Result{Termination: termination}, err
	}
	span.RecordError(err)
	status = tracing.StatusError
	statusMsg = "plugin execution error"
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
