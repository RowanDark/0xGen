package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Manager manages scheduled scans and workflows.
type Manager struct {
	storage       *Storage
	activeJobs    map[string]*activeJob
	mu            sync.RWMutex
	stopChan      chan struct{}
	wg            sync.WaitGroup
	checkInterval time.Duration
}

// activeJob represents a running job.
type activeJob struct {
	scheduleID string
	cancelFunc context.CancelFunc
	ticker     *time.Ticker
}

// NewManager creates a new scheduler manager.
func NewManager(storage *Storage) *Manager {
	return &Manager{
		storage:       storage,
		activeJobs:    make(map[string]*activeJob),
		stopChan:      make(chan struct{}),
		checkInterval: 1 * time.Minute, // Check every minute
	}
}

// Start starts the scheduler manager.
func (m *Manager) Start() error {
	m.wg.Add(1)
	go m.run()
	return nil
}

// Stop stops the scheduler manager.
func (m *Manager) Stop() {
	close(m.stopChan)

	// Cancel all active jobs
	m.mu.Lock()
	for _, job := range m.activeJobs {
		if job.ticker != nil {
			job.ticker.Stop()
		}
		if job.cancelFunc != nil {
			job.cancelFunc()
		}
	}
	m.mu.Unlock()

	m.wg.Wait()
}

// run is the main scheduler loop.
func (m *Manager) run() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	// Initial check
	m.checkSchedules()

	for {
		select {
		case <-ticker.C:
			m.checkSchedules()
		case <-m.stopChan:
			return
		}
	}
}

// checkSchedules checks all enabled schedules and runs those that are due.
func (m *Manager) checkSchedules() {
	schedules, err := m.storage.ListSchedules()
	if err != nil {
		// Log error but continue
		return
	}

	now := time.Now().UTC()
	for _, schedule := range schedules {
		if !schedule.Enabled {
			continue
		}

		// Check if schedule is due to run
		if m.shouldRun(schedule, now) {
			m.runSchedule(schedule)
		}
	}
}

// shouldRun checks if a schedule should run at the given time.
func (m *Manager) shouldRun(schedule *Schedule, now time.Time) bool {
	// Parse cron expression
	cron, err := ParseCronExpression(schedule.CronExpr)
	if err != nil {
		return false
	}

	// Calculate next run if not set
	if schedule.NextRun == nil {
		nextRun, err := CalculateNextRun(cron, now.Add(-1*time.Minute))
		if err != nil {
			return false
		}
		schedule.NextRun = &nextRun
		m.storage.SaveSchedule(schedule)
	}

	// Check if it's time to run
	if schedule.NextRun != nil && !schedule.NextRun.After(now) {
		return true
	}

	return false
}

// runSchedule executes a scheduled scan.
func (m *Manager) runSchedule(schedule *Schedule) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Don't run if already running
	if _, running := m.activeJobs[schedule.ID]; running {
		return
	}

	// Update last run and calculate next run
	now := time.Now().UTC()
	schedule.LastRun = &now

	cron, err := ParseCronExpression(schedule.CronExpr)
	if err == nil {
		nextRun, err := CalculateNextRun(cron, now)
		if err == nil {
			schedule.NextRun = &nextRun
		}
	}

	m.storage.SaveSchedule(schedule)

	// Start the scan in a goroutine
	ctx, cancel := context.WithCancel(context.Background())
	m.activeJobs[schedule.ID] = &activeJob{
		scheduleID: schedule.ID,
		cancelFunc: cancel,
	}

	m.wg.Add(1)
	go func(sched *Schedule) {
		defer m.wg.Done()
		defer func() {
			m.mu.Lock()
			delete(m.activeJobs, sched.ID)
			m.mu.Unlock()
		}()

		// Execute the scan
		m.executeScan(ctx, sched)
	}(schedule)
}

// executeScan executes a scan for a schedule.
func (m *Manager) executeScan(ctx context.Context, schedule *Schedule) {
	// This is a placeholder - actual scan execution would be implemented here
	// In a real implementation, this would:
	// 1. Build scan command based on schedule.ScanType, schedule.Target, schedule.Template
	// 2. Execute the scan
	// 3. Process results
	// 4. Execute any configured actions (report, notify, etc.)

	// For now, just log that we would run it
	fmt.Printf("Would execute scan: %s (target: %s, type: %s)\n",
		schedule.Name, schedule.Target, schedule.ScanType)

	// Execute actions
	for _, action := range schedule.Actions {
		m.executeAction(ctx, schedule, action)
	}
}

// executeAction executes a post-scan action.
func (m *Manager) executeAction(ctx context.Context, schedule *Schedule, action Action) {
	switch action.Type {
	case ActionReport:
		// Generate report
		fmt.Printf("Action: Generate report for %s\n", schedule.Name)
	case ActionNotify:
		// Send notification
		fmt.Printf("Action: Send notification for %s\n", schedule.Name)
	case ActionCompare:
		// Compare with baseline
		fmt.Printf("Action: Compare results for %s\n", schedule.Name)
	case ActionWebhook:
		// Send to webhook
		fmt.Printf("Action: Send webhook for %s\n", schedule.Name)
	case ActionSetBaseline:
		// Set as new baseline
		fmt.Printf("Action: Set baseline for %s\n", schedule.Name)
	}
}

// RunScheduleNow manually triggers a schedule to run immediately.
func (m *Manager) RunScheduleNow(scheduleID string) error {
	schedule, err := m.storage.LoadSchedule(scheduleID)
	if err != nil {
		return err
	}

	m.runSchedule(schedule)
	return nil
}

// GetScheduleStatus returns the current status of a schedule.
func (m *Manager) GetScheduleStatus(scheduleID string) (*ScheduleStatus, error) {
	schedule, err := m.storage.LoadSchedule(scheduleID)
	if err != nil {
		return nil, err
	}

	m.mu.RLock()
	_, isRunning := m.activeJobs[scheduleID]
	m.mu.RUnlock()

	status := &ScheduleStatus{
		Schedule:  *schedule,
		IsRunning: isRunning,
	}

	return status, nil
}

// ListActiveJobs returns all currently running jobs.
func (m *Manager) ListActiveJobs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var jobIDs []string
	for id := range m.activeJobs {
		jobIDs = append(jobIDs, id)
	}

	return jobIDs
}
