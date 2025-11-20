package atlas

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// BenchmarkOrchestrator_StartScan benchmarks scan startup overhead.
func BenchmarkOrchestrator_StartScan(b *testing.B) {
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	module := &mockDetectionModule{
		name:     "bench-module",
		findings: []*Finding{},
	}

	orchestrator := NewOrchestrator([]Module{module}, storage, nil, eventBus, logger)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		scan := &Scan{
			ID:   fmt.Sprintf("bench-scan-%d", i),
			Name: "Benchmark Scan",
			Target: Target{
				Type: TargetTypeSingleURL,
				URLs: []string{"http://test.com"},
			},
			Config: ScanConfig{
				MaxConcurrency: 5,
				Timeout:        1 * time.Second,
			},
		}

		orchestrator.StartScan(context.Background(), scan)

		// Let scan start
		time.Sleep(10 * time.Millisecond)

		// Stop it
		orchestrator.StopScan(scan.ID)
	}
}

// BenchmarkDeduplication benchmarks finding deduplication performance.
func BenchmarkDeduplication(b *testing.B) {
	dedup := NewDeduplicator()

	// Create 1000 findings with some duplicates
	findings := make([]*Finding, 1000)
	for i := range findings {
		findings[i] = &Finding{
			Type:       "SQL Injection",
			URL:        fmt.Sprintf("http://test.com/page%d", i%100), // 10 duplicates per URL
			Parameter:  "id",
			Location:   ParamLocationQuery,
			Method:     "GET",
			Severity:   SeverityHigh,
			Confidence: ConfidenceConfirmed,
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, f := range findings {
			dedup.Deduplicate(f)
		}
	}
}

// BenchmarkCVSSCalculation benchmarks CVSS score calculation.
func BenchmarkCVSSCalculation(b *testing.B) {
	calc := NewCVSSCalculator()

	finding := &Finding{
		Type:       "SQL Injection",
		Severity:   SeverityHigh,
		Confidence: ConfidenceConfirmed,
		URL:        "http://test.com",
		Parameter:  "id",
		Location:   ParamLocationQuery,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		calc.EnrichFinding(finding)
	}
}

// BenchmarkFalsePositiveDetection benchmarks false positive detection.
func BenchmarkFalsePositiveDetection(b *testing.B) {
	detector := NewFalsePositiveDetector()

	// Add some default rules
	detector.AddRule(FPRule{
		FindingType: "SQL Injection",
		Pattern:     "error",
		Reason:      "Generic error message may be false positive",
		Action:      FPActionFlag,
	})

	finding := &Finding{
		Type:       "SQL Injection",
		URL:        "http://test.com/page",
		Response:   "Database error: syntax error",
		Payload:    "' OR '1'='1",
		Confidence: ConfidenceTentative,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		detector.Analyze(context.Background(), finding)
	}
}

// BenchmarkMemoryStorage_Operations benchmarks storage operations.
func BenchmarkMemoryStorage_Operations(b *testing.B) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Pre-populate with scans
	for i := 0; i < 100; i++ {
		scan := &Scan{
			ID:     fmt.Sprintf("scan-%d", i),
			Name:   fmt.Sprintf("Scan %d", i),
			State:  ScanStateCompleted,
			Target: Target{Type: TargetTypeSingleURL},
			Config: ScanConfig{},
		}
		storage.StoreScan(ctx, scan)
	}

	b.Run("StoreScan", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			scan := &Scan{
				ID:     fmt.Sprintf("bench-scan-%d", i),
				Name:   "Benchmark Scan",
				State:  ScanStatePending,
				Target: Target{Type: TargetTypeSingleURL},
				Config: ScanConfig{},
			}
			storage.StoreScan(ctx, scan)
		}
	})

	b.Run("GetScan", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			storage.GetScan(ctx, "scan-50")
		}
	})

	b.Run("ListScans", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			storage.ListScans(ctx, ScanFilter{Limit: 10})
		}
	})

	b.Run("StoreFinding", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			finding := &Finding{
				ID:         fmt.Sprintf("finding-%d", i),
				ScanID:     "scan-1",
				Type:       "XSS",
				Severity:   SeverityMedium,
				Confidence: ConfidenceConfirmed,
				Title:      "Test Finding",
				URL:        "http://test.com",
				DetectedAt: time.Now(),
			}
			storage.StoreFinding(ctx, finding)
		}
	})
}

// BenchmarkModuleExecution benchmarks module execution performance.
func BenchmarkModuleExecution(b *testing.B) {
	module := &mockDetectionModule{
		name: "bench-module",
		findings: []*Finding{
			{Type: "Test", Severity: SeverityLow},
		},
	}

	target := &ScanTarget{
		URL:    "http://test.com?id=1",
		Method: "GET",
	}

	ctx := context.Background()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		module.Scan(ctx, target)
	}
}

// BenchmarkParallelModuleExecution benchmarks parallel module execution.
func BenchmarkParallelModuleExecution(b *testing.B) {
	modules := make([]Module, 10)
	for i := range modules {
		modules[i] = &mockDetectionModule{
			name:  fmt.Sprintf("module-%d", i),
			delay: 1 * time.Millisecond,
		}
	}

	target := &ScanTarget{
		URL:    "http://test.com",
		Method: "GET",
	}

	ctx := context.Background()

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			module := modules[i%len(modules)]
			module.Scan(ctx, target)
			i++
		}
	})
}

// BenchmarkEventBus benchmarks event bus performance.
func BenchmarkEventBus(b *testing.B) {
	bus := NewBus()
	ctx := context.Background()

	// Add subscribers with background consumers
	for i := 0; i < 10; i++ {
		ch := bus.Subscribe(ctx, "test.event")
		go func() {
			for range ch {
				// No-op consumer
			}
		}()
	}

	eventData := map[string]interface{}{
		"type": "test",
		"data": "benchmark",
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		bus.Publish("test.event", eventData)
	}
}

// BenchmarkFindingAggregation benchmarks finding collection and aggregation.
func BenchmarkFindingAggregation(b *testing.B) {
	findings := make([]*Finding, 1000)
	for i := range findings {
		findings[i] = &Finding{
			Type:       fmt.Sprintf("Type-%d", i%10),
			Severity:   SeverityHigh,
			Confidence: ConfidenceConfirmed,
			URL:        fmt.Sprintf("http://test.com/page%d", i),
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Aggregate by type
		byType := make(map[string][]*Finding)
		for _, f := range findings {
			byType[f.Type] = append(byType[f.Type], f)
		}

		// Count by severity
		bySeverity := make(map[Severity]int)
		for _, f := range findings {
			bySeverity[f.Severity]++
		}
	}
}

// BenchmarkScanProgress benchmarks progress tracking and updates.
func BenchmarkScanProgress(b *testing.B) {
	progress := &Progress{
		Phase:           "scanning",
		CurrentModule:   "sqli",
		URLsDiscovered:  1000,
		URLsTested:      0,
		URLsRemaining:   1000,
		RequestsSent:    0,
		FindingsFound:   0,
		PercentComplete: 0.0,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		progress.URLsTested++
		progress.URLsRemaining--
		progress.RequestsSent++
		progress.PercentComplete = float64(progress.URLsTested) / float64(progress.URLsDiscovered)

		if i%10 == 0 {
			progress.FindingsFound++
		}
	}
}

// BenchmarkConcurrentScanOperations benchmarks concurrent scan operations.
func BenchmarkConcurrentScanOperations(b *testing.B) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Pre-populate
	for i := 0; i < 100; i++ {
		scan := &Scan{
			ID:     fmt.Sprintf("scan-%d", i),
			Name:   fmt.Sprintf("Scan %d", i),
			State:  ScanStateRunning,
			Target: Target{Type: TargetTypeSingleURL},
			Config: ScanConfig{},
			Progress: Progress{
				URLsTested: i,
			},
		}
		storage.StoreScan(ctx, scan)
	}

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			scanID := fmt.Sprintf("scan-%d", i%100)

			// Mix of operations
			switch i % 4 {
			case 0:
				storage.GetScan(ctx, scanID)
			case 1:
				scan, _ := storage.GetScan(ctx, scanID)
				if scan != nil {
					scan.Progress.URLsTested++
					storage.UpdateScan(ctx, scan)
				}
			case 2:
				storage.ListScans(ctx, ScanFilter{Limit: 10})
			case 3:
				finding := &Finding{
					ID:         fmt.Sprintf("finding-%d", i),
					ScanID:     scanID,
					Type:       "Test",
					Severity:   SeverityLow,
					Confidence: ConfidenceConfirmed,
					Title:      "Test",
					URL:        "http://test.com",
					DetectedAt: time.Now(),
				}
				storage.StoreFinding(ctx, finding)
			}

			i++
		}
	})
}

// Expected benchmark results for new orchestrator benchmarks:
// BenchmarkOrchestrator_1000URLs          ~1-2 ops        ~5-10s/op      ~1-2GB/op
// BenchmarkOrchestrator_MultipleModules   ~10-50 ops      ~50-100ms/op   ~10-20MB/op
// BenchmarkOrchestrator_StartStop         ~100-500 ops    ~2-5ms/op      ~1-3MB/op

// BenchmarkOrchestrator_1000URLs benchmarks scanning 1000 URLs.
func BenchmarkOrchestrator_1000URLs(b *testing.B) {
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	module := &mockDetectionModule{
		name:     "bench-module",
		findings: []*Finding{},
		delay:    1 * time.Millisecond, // Minimal delay to simulate work
	}

	orchestrator := NewOrchestrator([]Module{module}, storage, nil, eventBus, logger)

	// Create 1000 target URLs
	urls := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		urls[i] = fmt.Sprintf("http://test.com/page%d", i)
	}

	scan := &Scan{
		ID:   "bench-1000urls",
		Name: "1000 URL Benchmark",
		Target: Target{
			Type: TargetTypeURLList,
			URLs: urls,
		},
		Config: ScanConfig{
			MaxConcurrency: 20,
			RateLimit:      100,
			Timeout:        5 * time.Second,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Update scan ID for each iteration
		scan.ID = fmt.Sprintf("bench-1000urls-%d", i)

		orchestrator.StartScan(context.Background(), scan)

		// Wait for completion or timeout
		waitForScanCompletion(orchestrator, scan.ID, 60*time.Second)

		orchestrator.StopScan(scan.ID)
	}
}

// BenchmarkOrchestrator_MultipleModules benchmarks orchestrator with multiple modules.
func BenchmarkOrchestrator_MultipleModules(b *testing.B) {
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	// Create 5 different modules
	modules := make([]Module, 5)
	for i := 0; i < 5; i++ {
		modules[i] = &mockDetectionModule{
			name:     fmt.Sprintf("module-%d", i),
			findings: []*Finding{},
			delay:    2 * time.Millisecond,
		}
	}

	orchestrator := NewOrchestrator(modules, storage, nil, eventBus, logger)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		scan := &Scan{
			ID:   fmt.Sprintf("bench-multi-%d", i),
			Name: "Multi-Module Benchmark",
			Target: Target{
				Type: TargetTypeSingleURL,
				URLs: []string{"http://test.com"},
			},
			Config: ScanConfig{
				MaxConcurrency: 5,
				Timeout:        5 * time.Second,
			},
		}

		orchestrator.StartScan(context.Background(), scan)

		// Wait for completion
		waitForScanCompletion(orchestrator, scan.ID, 10*time.Second)

		orchestrator.StopScan(scan.ID)
	}
}

// BenchmarkOrchestrator_StartStop benchmarks rapid scan start/stop cycles.
func BenchmarkOrchestrator_StartStop(b *testing.B) {
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	module := &mockDetectionModule{
		name:     "bench-module",
		findings: []*Finding{},
	}

	orchestrator := NewOrchestrator([]Module{module}, storage, nil, eventBus, logger)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		scan := &Scan{
			ID:   fmt.Sprintf("bench-startstop-%d", i),
			Name: "StartStop Benchmark",
			Target: Target{
				Type: TargetTypeSingleURL,
				URLs: []string{"http://test.com"},
			},
			Config: ScanConfig{
				MaxConcurrency: 5,
				Timeout:        1 * time.Second,
			},
		}

		orchestrator.StartScan(context.Background(), scan)

		// Immediately stop
		time.Sleep(1 * time.Millisecond)
		orchestrator.StopScan(scan.ID)
	}
}

// Expected benchmark results for new deduplication benchmarks:
// BenchmarkDeduplicator_GenerateFingerprint  ~500K-2M ops   ~500-1000ns/op  ~200-500B/op
// BenchmarkDeduplicator_10000Findings        ~5-20 ops      ~50-100ms/op    ~5-10MB/op
// BenchmarkDeduplicator_HighDuplication      ~10-50 ops     ~20-50ms/op     ~2-5MB/op

// BenchmarkDeduplicator_GenerateFingerprint benchmarks fingerprint generation specifically.
func BenchmarkDeduplicator_GenerateFingerprint(b *testing.B) {
	dedup := NewDeduplicator()
	finding := &Finding{
		Type:       "SQL Injection",
		URL:        "http://test.com/page?id=1",
		Parameter:  "id",
		Location:   ParamLocationQuery,
		Method:     "GET",
		Severity:   SeverityHigh,
		Confidence: ConfidenceConfirmed,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		dedup.generateFingerprint(finding)
	}
}

// BenchmarkDeduplicator_10000Findings benchmarks deduplication with 10,000 findings.
func BenchmarkDeduplicator_10000Findings(b *testing.B) {
	// Create 10,000 findings (20% duplicates)
	findings := make([]*Finding, 10000)
	for i := range findings {
		findings[i] = &Finding{
			Type:       fmt.Sprintf("Type-%d", i%5), // 5 different types
			URL:        fmt.Sprintf("http://test.com/page%d", i%2000),
			Parameter:  "id",
			Location:   ParamLocationQuery,
			Method:     "GET",
			Severity:   SeverityHigh,
			Confidence: ConfidenceConfirmed,
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		dedup := NewDeduplicator()
		for _, f := range findings {
			dedup.Deduplicate(f)
		}
	}
}

// BenchmarkDeduplicator_HighDuplication benchmarks deduplication with high duplicate rate.
func BenchmarkDeduplicator_HighDuplication(b *testing.B) {
	// Create 5000 findings (80% duplicates)
	findings := make([]*Finding, 5000)
	for i := range findings {
		findings[i] = &Finding{
			Type:       "SQL Injection",
			URL:        fmt.Sprintf("http://test.com/page%d", i%1000), // Only 1000 unique URLs
			Parameter:  "id",
			Location:   ParamLocationQuery,
			Method:     "GET",
			Severity:   SeverityHigh,
			Confidence: ConfidenceConfirmed,
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		dedup := NewDeduplicator()
		for _, f := range findings {
			dedup.Deduplicate(f)
		}
	}
}

// BenchmarkDeduplicator_ConfidenceUpgrade benchmarks confidence upgrade merging.
func BenchmarkDeduplicator_ConfidenceUpgrade(b *testing.B) {
	findings := make([]*Finding, 1000)
	for i := range findings {
		// Same finding with varying confidence levels
		confidence := ConfidenceTentative
		if i%3 == 0 {
			confidence = ConfidenceFirm
		} else if i%5 == 0 {
			confidence = ConfidenceConfirmed
		}

		findings[i] = &Finding{
			Type:       "XSS",
			URL:        "http://test.com/page",
			Parameter:  "q",
			Location:   ParamLocationQuery,
			Method:     "GET",
			Severity:   SeverityMedium,
			Confidence: confidence,
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		dedup := NewDeduplicator()
		for _, f := range findings {
			dedup.Deduplicate(f)
		}
	}
}

// BenchmarkDeduplicator_LargeDataset benchmarks deduplication with a large dataset.
func BenchmarkDeduplicator_LargeDataset(b *testing.B) {
	// Create 20,000 findings (30% duplicates)
	findings := make([]*Finding, 20000)
	for i := range findings {
		findings[i] = &Finding{
			Type:       fmt.Sprintf("Type-%d", i%10),
			URL:        fmt.Sprintf("http://test.com/page%d", i%6000),
			Parameter:  "id",
			Location:   ParamLocationQuery,
			Method:     "GET",
			Severity:   SeverityHigh,
			Confidence: ConfidenceConfirmed,
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		dedup := NewDeduplicator()
		for _, f := range findings {
			dedup.Deduplicate(f)
		}
	}
}
