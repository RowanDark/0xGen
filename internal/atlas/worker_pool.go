package atlas

import (
	"context"
	"sync"
)

// WorkerPool manages parallel job execution with configurable workers.
type WorkerPool struct {
	workers   int
	jobs      chan Job
	results   chan JobResult
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
	requester *Requester
}

// Job represents a scan job for a module.
type Job struct {
	ID     string
	Target *ScanTarget
	Module Module
}

// JobResult contains the result of a scan job.
type JobResult struct {
	JobID    string
	Findings []*Finding
	Error    error
}

// NewWorkerPool creates a new worker pool.
func NewWorkerPool(workers int, requester *Requester) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	return &WorkerPool{
		workers:   workers,
		jobs:      make(chan Job, workers*2), // Buffer for efficiency
		results:   make(chan JobResult, workers*2),
		ctx:       ctx,
		cancel:    cancel,
		requester: requester,
	}
}

// Start initializes worker goroutines.
func (p *WorkerPool) Start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}
}

func (p *WorkerPool) worker(id int) {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return

		case job, ok := <-p.jobs:
			if !ok {
				return // Channel closed
			}

			// Execute job
			findings, err := job.Module.Scan(p.ctx, job.Target)

			// Send result
			select {
			case p.results <- JobResult{
				JobID:    job.ID,
				Findings: findings,
				Error:    err,
			}:
			case <-p.ctx.Done():
				return
			}
		}
	}
}

// Submit adds a job to the pool.
func (p *WorkerPool) Submit(job Job) error {
	select {
	case p.jobs <- job:
		return nil
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

// Results returns the results channel.
func (p *WorkerPool) Results() <-chan JobResult {
	return p.results
}

// Stop gracefully shuts down the pool.
func (p *WorkerPool) Stop() {
	close(p.jobs)
	p.wg.Wait()
	close(p.results)
}

// Cancel immediately cancels all workers.
func (p *WorkerPool) Cancel() {
	p.cancel()
	p.wg.Wait()
}
