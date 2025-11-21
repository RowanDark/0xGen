package scheduler

import (
	"time"
)

// Schedule represents a scheduled scan configuration.
type Schedule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Enabled     bool      `json:"enabled"`
	CronExpr    string    `json:"cron_expr"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	LastRun     *time.Time `json:"last_run,omitempty"`
	NextRun     *time.Time `json:"next_run,omitempty"`

	// Scan configuration
	Target      string            `json:"target"`
	Template    string            `json:"template,omitempty"`
	ScanType    string            `json:"scan_type"` // blitz, raider, full
	Options     map[string]string `json:"options,omitempty"`

	// Actions to perform after scan
	Actions []Action `json:"actions,omitempty"`
}

// Action represents an action to perform after a scan.
type Action struct {
	Type   ActionType        `json:"type"`
	Config map[string]string `json:"config,omitempty"`
}

// ActionType specifies the type of post-scan action.
type ActionType string

const (
	ActionReport      ActionType = "report"
	ActionNotify      ActionType = "notify"
	ActionCompare     ActionType = "compare"
	ActionWebhook     ActionType = "webhook"
	ActionSetBaseline ActionType = "set_baseline"
)

// ScheduleStatus represents the current status of a schedule.
type ScheduleStatus struct {
	Schedule    Schedule
	IsRunning   bool
	LastRunTime *time.Time
	LastError   string
	RunCount    int
}

// CronExpression represents a parsed cron expression.
type CronExpression struct {
	Minute     string // 0-59 or *
	Hour       string // 0-23 or *
	DayOfMonth string // 1-31 or *
	Month      string // 1-12 or *
	DayOfWeek  string // 0-7 or * (0 and 7 are Sunday)
}

// Workflow represents an automated workflow definition.
type Workflow struct {
	ID          string             `yaml:"-" json:"id"`
	Name        string             `yaml:"name" json:"name"`
	Description string             `yaml:"description" json:"description"`
	Enabled     bool               `yaml:"-" json:"enabled"`
	Trigger     WorkflowTrigger    `yaml:"trigger" json:"trigger"`
	Steps       []WorkflowStep     `yaml:"steps" json:"steps"`
	Variables   map[string]string  `yaml:"variables,omitempty" json:"variables,omitempty"`
	CreatedAt   time.Time          `yaml:"-" json:"created_at"`
	UpdatedAt   time.Time          `yaml:"-" json:"updated_at"`
}

// WorkflowTrigger defines when a workflow should run.
type WorkflowTrigger struct {
	Schedule string `yaml:"schedule,omitempty" json:"schedule,omitempty"` // Cron expression
	Webhook  bool   `yaml:"webhook,omitempty" json:"webhook,omitempty"`   // Enable webhook trigger
	Manual   bool   `yaml:"manual,omitempty" json:"manual,omitempty"`     // Allow manual trigger
}

// WorkflowStep represents a single step in a workflow.
type WorkflowStep struct {
	Name      string            `yaml:"name" json:"name"`
	Action    string            `yaml:"action" json:"action"` // scan, compare, notify, report
	Condition string            `yaml:"condition,omitempty" json:"condition,omitempty"`
	Config    map[string]string `yaml:"config,omitempty" json:"config,omitempty"`
}

// WorkflowExecution represents a workflow execution instance.
type WorkflowExecution struct {
	ID          string                  `json:"id"`
	WorkflowID  string                  `json:"workflow_id"`
	Status      WorkflowExecutionStatus `json:"status"`
	StartedAt   time.Time               `json:"started_at"`
	CompletedAt *time.Time              `json:"completed_at,omitempty"`
	Steps       []StepExecution         `json:"steps"`
	Error       string                  `json:"error,omitempty"`
	Context     map[string]interface{}  `json:"context,omitempty"` // Shared context between steps
}

// StepExecution represents the execution of a single workflow step.
type StepExecution struct {
	StepName    string     `json:"step_name"`
	Status      StepStatus `json:"status"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
	Output      map[string]interface{} `json:"output,omitempty"`
}

// WorkflowExecutionStatus represents the status of a workflow execution.
type WorkflowExecutionStatus string

const (
	ExecutionStatusPending   WorkflowExecutionStatus = "pending"
	ExecutionStatusRunning   WorkflowExecutionStatus = "running"
	ExecutionStatusCompleted WorkflowExecutionStatus = "completed"
	ExecutionStatusFailed    WorkflowExecutionStatus = "failed"
	ExecutionStatusCancelled WorkflowExecutionStatus = "cancelled"
)

// StepStatus represents the status of a step execution.
type StepStatus string

const (
	StepStatusPending   StepStatus = "pending"
	StepStatusRunning   StepStatus = "running"
	StepStatusCompleted StepStatus = "completed"
	StepStatusFailed    StepStatus = "failed"
	StepStatusSkipped   StepStatus = "skipped"
)
