package scheduler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

const (
	schedulesDir = "schedules"
	workflowsDir = "workflows"
)

// Storage manages persistent storage of schedules and workflows.
type Storage struct {
	configDir string
}

// NewStorage creates a new Storage instance.
func NewStorage(configDir string) (*Storage, error) {
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("get home directory: %w", err)
		}
		configDir = filepath.Join(home, ".0xgen")
	}

	s := &Storage{
		configDir: configDir,
	}

	// Create necessary directories
	if err := s.ensureDirectories(); err != nil {
		return nil, err
	}

	return s, nil
}

// ensureDirectories creates required directories if they don't exist.
func (s *Storage) ensureDirectories() error {
	dirs := []string{
		filepath.Join(s.configDir, schedulesDir),
		filepath.Join(s.configDir, workflowsDir),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}

	return nil
}

// SaveSchedule persists a schedule to disk.
func (s *Storage) SaveSchedule(schedule *Schedule) error {
	if schedule.ID == "" {
		schedule.ID = ulid.Make().String()
	}

	if schedule.CreatedAt.IsZero() {
		schedule.CreatedAt = time.Now().UTC()
	}
	schedule.UpdatedAt = time.Now().UTC()

	data, err := json.MarshalIndent(schedule, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal schedule: %w", err)
	}

	filename := filepath.Join(s.configDir, schedulesDir, schedule.ID+".json")
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("write schedule file: %w", err)
	}

	return nil
}

// LoadSchedule loads a schedule by ID.
func (s *Storage) LoadSchedule(id string) (*Schedule, error) {
	filename := filepath.Join(s.configDir, schedulesDir, id+".json")

	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("schedule not found: %s", id)
		}
		return nil, fmt.Errorf("read schedule file: %w", err)
	}

	var schedule Schedule
	if err := json.Unmarshal(data, &schedule); err != nil {
		return nil, fmt.Errorf("unmarshal schedule: %w", err)
	}

	return &schedule, nil
}

// ListSchedules returns all schedules.
func (s *Storage) ListSchedules() ([]*Schedule, error) {
	dir := filepath.Join(s.configDir, schedulesDir)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read schedules directory: %w", err)
	}

	var schedules []*Schedule
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		id := strings.TrimSuffix(entry.Name(), ".json")
		schedule, err := s.LoadSchedule(id)
		if err != nil {
			// Skip invalid files
			continue
		}

		schedules = append(schedules, schedule)
	}

	// Sort by creation time (newest first)
	sort.Slice(schedules, func(i, j int) bool {
		return schedules[i].CreatedAt.After(schedules[j].CreatedAt)
	})

	return schedules, nil
}

// DeleteSchedule deletes a schedule by ID.
func (s *Storage) DeleteSchedule(id string) error {
	filename := filepath.Join(s.configDir, schedulesDir, id+".json")

	if err := os.Remove(filename); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("schedule not found: %s", id)
		}
		return fmt.Errorf("delete schedule file: %w", err)
	}

	return nil
}

// FindScheduleByName finds a schedule by name (case-insensitive).
func (s *Storage) FindScheduleByName(name string) (*Schedule, error) {
	schedules, err := s.ListSchedules()
	if err != nil {
		return nil, err
	}

	nameLower := strings.ToLower(name)
	for _, schedule := range schedules {
		if strings.ToLower(schedule.Name) == nameLower {
			return schedule, nil
		}
	}

	return nil, fmt.Errorf("schedule not found: %s", name)
}

// SaveWorkflow persists a workflow to disk.
func (s *Storage) SaveWorkflow(workflow *Workflow) error {
	if workflow.ID == "" {
		workflow.ID = ulid.Make().String()
	}

	if workflow.CreatedAt.IsZero() {
		workflow.CreatedAt = time.Now().UTC()
	}
	workflow.UpdatedAt = time.Now().UTC()

	data, err := json.MarshalIndent(workflow, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal workflow: %w", err)
	}

	filename := filepath.Join(s.configDir, workflowsDir, workflow.ID+".json")
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("write workflow file: %w", err)
	}

	return nil
}

// LoadWorkflow loads a workflow by ID.
func (s *Storage) LoadWorkflow(id string) (*Workflow, error) {
	filename := filepath.Join(s.configDir, workflowsDir, id+".json")

	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("workflow not found: %s", id)
		}
		return nil, fmt.Errorf("read workflow file: %w", err)
	}

	var workflow Workflow
	if err := json.Unmarshal(data, &workflow); err != nil {
		return nil, fmt.Errorf("unmarshal workflow: %w", err)
	}

	return &workflow, nil
}

// ListWorkflows returns all workflows.
func (s *Storage) ListWorkflows() ([]*Workflow, error) {
	dir := filepath.Join(s.configDir, workflowsDir)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read workflows directory: %w", err)
	}

	var workflows []*Workflow
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		id := strings.TrimSuffix(entry.Name(), ".json")
		workflow, err := s.LoadWorkflow(id)
		if err != nil {
			// Skip invalid files
			continue
		}

		workflows = append(workflows, workflow)
	}

	// Sort by creation time (newest first)
	sort.Slice(workflows, func(i, j int) bool {
		return workflows[i].CreatedAt.After(workflows[j].CreatedAt)
	})

	return workflows, nil
}

// DeleteWorkflow deletes a workflow by ID.
func (s *Storage) DeleteWorkflow(id string) error {
	filename := filepath.Join(s.configDir, workflowsDir, id+".json")

	if err := os.Remove(filename); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("workflow not found: %s", id)
		}
		return fmt.Errorf("delete workflow file: %w", err)
	}

	return nil
}

// FindWorkflowByName finds a workflow by name (case-insensitive).
func (s *Storage) FindWorkflowByName(name string) (*Workflow, error) {
	workflows, err := s.ListWorkflows()
	if err != nil {
		return nil, err
	}

	nameLower := strings.ToLower(name)
	for _, workflow := range workflows {
		if strings.ToLower(workflow.Name) == nameLower {
			return workflow, nil
		}
	}

	return nil, fmt.Errorf("workflow not found: %s", name)
}
