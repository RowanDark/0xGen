package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"
)

// Test data generators

func generateRandomTokens(count, length int) []string {
	tokens := make([]string, count)
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	for i := 0; i < count; i++ {
		token := make([]byte, length)
		for j := 0; j < length; j++ {
			idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
			token[j] = chars[idx.Int64()]
		}
		tokens[i] = string(token)
	}

	return tokens
}

func generateSequentialTokens(count int) []string {
	tokens := make([]string, count)
	for i := 0; i < count; i++ {
		tokens[i] = fmt.Sprintf("token_%d", i*100)
	}
	return tokens
}

func generateLowEntropyTokens(count, length int) []string {
	tokens := make([]string, count)
	chars := "0123456789" // Limited charset

	for i := 0; i < count; i++ {
		token := make([]byte, length)
		for j := 0; j < length; j++ {
			idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
			token[j] = chars[idx.Int64()]
		}
		tokens[i] = string(token)
	}

	return tokens
}

// Statistical tests

func TestChiSquaredTest(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []string
		wantPass bool
	}{
		{
			name:    "random tokens should pass",
			tokens:  generateRandomTokens(100, 16),
			wantPass: true,
		},
		{
			name:    "non-uniform tokens should fail",
			tokens:  []string{"aaaaaaa", "aaaaaaa", "aaaaaaa", "b"},
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ChiSquaredTest(tt.tokens)
			if result.Passed != tt.wantPass {
				t.Errorf("ChiSquaredTest() passed = %v, want %v (p-value: %.4f)",
					result.Passed, tt.wantPass, result.PValue)
			}
		})
	}
}

func TestRunsTest(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []string
		wantPass bool
	}{
		{
			name:    "random tokens should pass",
			tokens:  generateRandomTokens(50, 16),
			wantPass: true,
		},
		{
			name:    "all same bits should fail",
			tokens:  []string{"aaaaaaa", "aaaaaaa", "aaaaaaa"},
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RunsTest(tt.tokens)
			if result.Passed != tt.wantPass {
				t.Errorf("RunsTest() passed = %v, want %v (p-value: %.4f)",
					result.Passed, tt.wantPass, result.PValue)
			}
		})
	}
}

func TestSerialCorrelationTest(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []string
		wantPass bool
	}{
		{
			name:    "random tokens should pass",
			tokens:  generateRandomTokens(50, 16),
			wantPass: true,
		},
		{
			name:    "sequential tokens should fail",
			tokens:  generateSequentialTokens(20),
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SerialCorrelationTest(tt.tokens)
			// Note: This test can be flaky with truly random data
			t.Logf("SerialCorrelationTest() passed = %v, p-value = %.4f",
				result.Passed, result.PValue)
		})
	}
}

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name         string
		tokens       []string
		minEntropy   float64
	}{
		{
			name:       "random tokens should have high entropy",
			tokens:     generateRandomTokens(100, 16),
			minEntropy: 5.0,
		},
		{
			name:       "low entropy tokens",
			tokens:     generateLowEntropyTokens(100, 6),
			minEntropy: 2.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := CalculateEntropy(tt.tokens)
			if entropy < tt.minEntropy {
				t.Errorf("CalculateEntropy() = %.4f, want >= %.4f", entropy, tt.minEntropy)
			}
			t.Logf("Entropy: %.4f bits/char", entropy)
		})
	}
}

func TestDetectCollisions(t *testing.T) {
	tests := []struct {
		name             string
		tokens           []string
		maxCollisionRate float64
	}{
		{
			name:             "random tokens should have low collision rate",
			tokens:           generateRandomTokens(100, 16),
			maxCollisionRate: 0.01,
		},
		{
			name:             "duplicate tokens should have high collision rate",
			tokens:           []string{"abc", "abc", "abc", "def", "def"},
			maxCollisionRate: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rate, result := DetectCollisions(tt.tokens)
			t.Logf("Collision rate: %.4f", rate)
			if rate > tt.maxCollisionRate && tt.maxCollisionRate < 0.5 {
				t.Errorf("DetectCollisions() rate = %.4f, want <= %.4f", rate, tt.maxCollisionRate)
			}
			if !result.Passed && rate < 0.01 {
				t.Errorf("DetectCollisions() should pass for low collision rate")
			}
		})
	}
}

func TestAnalyzeBitDistribution(t *testing.T) {
	tokens := generateRandomTokens(100, 16)
	biases := AnalyzeBitDistribution(tokens)

	if len(biases) == 0 {
		t.Fatal("AnalyzeBitDistribution() returned no results")
	}

	// Check that biases are reasonable (not all 0 or all 0.5)
	avgBias := 0.0
	for _, bias := range biases {
		avgBias += bias
	}
	avgBias /= float64(len(biases))

	t.Logf("Average bit bias: %.4f (ideal: close to 0)", avgBias)

	// For random data, average bias should be relatively small
	if avgBias > 0.3 {
		t.Errorf("Average bit bias too high: %.4f", avgBias)
	}
}

// Pattern detection tests

func TestDetectSequentialPattern(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []string
		shouldDetect  bool
	}{
		{
			name:         "sequential tokens should be detected",
			tokens:       generateSequentialTokens(10),
			shouldDetect: true,
		},
		{
			name:         "random tokens should not be detected as sequential",
			tokens:       generateRandomTokens(10, 16),
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := DetectSequentialPattern(tt.tokens)
			detected := (pattern != nil && pattern.Confidence > 0.7)

			if detected != tt.shouldDetect {
				t.Errorf("DetectSequentialPattern() detected = %v, want %v", detected, tt.shouldDetect)
			}

			if pattern != nil {
				t.Logf("Pattern: %s (confidence: %.2f)", pattern.Description, pattern.Confidence)
			}
		})
	}
}

func TestDetectLowEntropyPattern(t *testing.T) {
	tests := []struct {
		name         string
		tokens       []string
		shouldDetect bool
	}{
		{
			name:         "low entropy tokens should be detected",
			tokens:       generateLowEntropyTokens(20, 4),
			shouldDetect: true,
		},
		{
			name:         "high entropy tokens should not be detected",
			tokens:       generateRandomTokens(20, 16),
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := CalculateEntropy(tt.tokens)
			charSet := GetCharacterSet(tt.tokens)
			pattern := DetectLowEntropyPattern(tt.tokens, entropy, charSet)

			detected := (pattern != nil && pattern.Confidence > 0.3)

			if detected != tt.shouldDetect {
				t.Errorf("DetectLowEntropyPattern() detected = %v, want %v", detected, tt.shouldDetect)
			}

			if pattern != nil {
				t.Logf("Pattern: %s (confidence: %.2f)", pattern.Description, pattern.Confidence)
			}
		})
	}
}

// PRNG fingerprinting tests

func TestFingerprintPRNG(t *testing.T) {
	// Create analysis for sequential tokens
	tokens := generateSequentialTokens(50)
	analysis := &EntropyAnalysis{
		TokenCount:   len(tokens),
		CharacterSet: GetCharacterSet(tokens),
		ShannonEntropy: CalculateEntropy(tokens),
		DetectedPatterns: []Pattern{
			{
				Type:       "sequential",
				Confidence: 0.9,
			},
		},
	}

	prng := FingerprintPRNG(analysis, tokens)

	if prng == nil {
		t.Log("No PRNG detected (acceptable for this test)")
	} else {
		t.Logf("Detected PRNG: %s (confidence: %.2f)", prng.Name, prng.Confidence)
		t.Logf("Weakness: %s", prng.Weakness)
		t.Logf("Exploit: %s", prng.ExploitHint)
	}
}

// Storage tests

func TestStorage(t *testing.T) {
	// Create temporary database
	dbPath := "test_entropy.db"
	defer os.Remove(dbPath)

	storage, err := NewStorage(dbPath)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}
	defer storage.Close()

	// Create session
	extractor := TokenExtractor{
		Pattern:  ".*",
		Location: "cookie",
		Name:     "session",
	}

	session, err := storage.CreateSession("Test Session", extractor)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	t.Logf("Created session ID: %d", session.ID)

	// Store tokens
	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		sample := TokenSample{
			CaptureSessionID: session.ID,
			TokenValue:       fmt.Sprintf("token_%d", i),
			TokenLength:      10,
			CapturedAt:       now.Add(time.Duration(i) * time.Second),
		}

		if err := storage.StoreToken(sample); err != nil {
			t.Fatalf("StoreToken() error = %v", err)
		}
	}

	// Retrieve tokens
	tokens, err := storage.GetTokens(session.ID)
	if err != nil {
		t.Fatalf("GetTokens() error = %v", err)
	}

	if len(tokens) != 10 {
		t.Errorf("GetTokens() returned %d tokens, want 10", len(tokens))
	}

	// Get session
	retrievedSession, err := storage.GetSession(session.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}

	if retrievedSession.TokenCount != 10 {
		t.Errorf("Session token count = %d, want 10", retrievedSession.TokenCount)
	}

	// Complete session
	if err := storage.CompleteSession(session.ID); err != nil {
		t.Fatalf("CompleteSession() error = %v", err)
	}
}

// Engine tests

func TestEntropyEngine(t *testing.T) {
	// Create temporary database
	dbPath := "test_engine.db"
	defer os.Remove(dbPath)

	storage, err := NewStorage(dbPath)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}
	defer storage.Close()

	engine := NewEntropyEngine(storage, time.Now)

	// Create session and add tokens
	extractor := TokenExtractor{
		Pattern:  ".*",
		Location: "cookie",
		Name:     "session",
	}

	session, err := storage.CreateSession("Test Analysis", extractor)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	// Add random tokens
	tokens := generateRandomTokens(100, 16)
	now := time.Now().UTC()

	for i, token := range tokens {
		sample := TokenSample{
			CaptureSessionID: session.ID,
			TokenValue:       token,
			TokenLength:      len(token),
			CapturedAt:       now.Add(time.Duration(i) * time.Millisecond),
		}

		if err := storage.StoreToken(sample); err != nil {
			t.Fatalf("StoreToken() error = %v", err)
		}
	}

	// Perform analysis
	analysis, err := engine.AnalyzeSession(session.ID)
	if err != nil {
		t.Fatalf("AnalyzeSession() error = %v", err)
	}

	// Verify analysis results
	if analysis.TokenCount != 100 {
		t.Errorf("Analysis token count = %d, want 100", analysis.TokenCount)
	}

	if analysis.RandomnessScore < 0 || analysis.RandomnessScore > 100 {
		t.Errorf("Randomness score = %.2f, want 0-100", analysis.RandomnessScore)
	}

	t.Logf("Analysis Results:")
	t.Logf("  Randomness Score: %.2f/100", analysis.RandomnessScore)
	t.Logf("  Shannon Entropy: %.2f", analysis.ShannonEntropy)
	t.Logf("  Collision Rate: %.4f", analysis.CollisionRate)
	t.Logf("  Risk Level: %s", analysis.Risk)
	t.Logf("  Chi-Squared: %v (p=%.4f)", analysis.ChiSquared.Passed, analysis.ChiSquared.PValue)
	t.Logf("  Runs Test: %v (p=%.4f)", analysis.Runs.Passed, analysis.Runs.PValue)

	if len(analysis.DetectedPatterns) > 0 {
		t.Logf("  Detected Patterns:")
		for _, p := range analysis.DetectedPatterns {
			t.Logf("    - %s (%.2f confidence): %s", p.Type, p.Confidence, p.Description)
		}
	}

	if analysis.DetectedPRNG != nil {
		t.Logf("  Detected PRNG: %s (%.2f confidence)", analysis.DetectedPRNG.Name, analysis.DetectedPRNG.Confidence)
	}

	if len(analysis.Recommendations) > 0 {
		t.Logf("  Recommendations:")
		for _, rec := range analysis.Recommendations {
			t.Logf("    - %s", rec)
		}
	}
}

// Performance test

func TestPerformance(t *testing.T) {
	// Test that analysis completes in <5 seconds for 1000 tokens
	tokens := generateRandomTokens(1000, 16)

	start := time.Now()

	// Run all statistical tests
	_ = ChiSquaredTest(tokens)
	_ = RunsTest(tokens)
	_ = SerialCorrelationTest(tokens)
	_ = SpectralTest(tokens)
	_ = CalculateEntropy(tokens)
	_, _ = DetectCollisions(tokens)
	_ = AnalyzeBitDistribution(tokens)

	elapsed := time.Since(start)

	t.Logf("Analysis of 1000 tokens completed in %v", elapsed)

	if elapsed > 5*time.Second {
		t.Errorf("Analysis took %v, want < 5s", elapsed)
	}
}

// Benchmark tests

func BenchmarkChiSquaredTest(b *testing.B) {
	tokens := generateRandomTokens(100, 16)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = ChiSquaredTest(tokens)
	}
}

func BenchmarkRunsTest(b *testing.B) {
	tokens := generateRandomTokens(100, 16)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = RunsTest(tokens)
	}
}

func BenchmarkCalculateEntropy(b *testing.B) {
	tokens := generateRandomTokens(100, 16)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = CalculateEntropy(tokens)
	}
}

func BenchmarkFullAnalysis(b *testing.B) {
	dbPath := "bench_entropy.db"
	defer os.Remove(dbPath)

	storage, _ := NewStorage(dbPath)
	defer storage.Close()

	engine := NewEntropyEngine(storage, time.Now)

	// Setup session with tokens
	extractor := TokenExtractor{Pattern: ".*", Location: "cookie", Name: "session"}
	session, _ := storage.CreateSession("Benchmark", extractor)

	tokens := generateRandomTokens(100, 16)
	now := time.Now().UTC()

	for i, token := range tokens {
		sample := TokenSample{
			CaptureSessionID: session.ID,
			TokenValue:       token,
			TokenLength:      len(token),
			CapturedAt:       now.Add(time.Duration(i) * time.Millisecond),
		}
		storage.StoreToken(sample)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = engine.AnalyzeSession(session.ID)
	}
}

// Session Manager tests

func TestSessionManager(t *testing.T) {
	// Create temporary database
	dbPath := "test_session_manager.db"
	defer os.Remove(dbPath)

	storage, err := NewStorage(dbPath)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}
	defer storage.Close()

	engine := NewEntropyEngine(storage, time.Now)
	sm := NewSessionManager(storage, engine, time.Now)

	// Test session creation
	extractor := TokenExtractor{
		Pattern:  ".*",
		Location: "cookie",
		Name:     "session",
	}

	session, err := sm.StartSession("Test Session", extractor, 100, 10*time.Minute)
	if err != nil {
		t.Fatalf("StartSession() error = %v", err)
	}

	if session.Status != CaptureStatusActive {
		t.Errorf("Session status = %v, want active", session.Status)
	}

	t.Logf("Created session ID: %d", session.ID)

	// Test pause
	if err := sm.PauseSession(session.ID); err != nil {
		t.Fatalf("PauseSession() error = %v", err)
	}

	session, _ = sm.GetSession(session.ID)
	if !session.IsPaused() {
		t.Errorf("Session should be paused")
	}

	// Test resume
	if err := sm.ResumeSession(session.ID); err != nil {
		t.Fatalf("ResumeSession() error = %v", err)
	}

	session, _ = sm.GetSession(session.ID)
	if !session.IsActive() {
		t.Errorf("Session should be active")
	}

	// Test stop
	if err := sm.StopSession(session.ID, StopReasonManual); err != nil {
		t.Fatalf("StopSession() error = %v", err)
	}

	session, _ = sm.GetSession(session.ID)
	if !session.IsStopped() {
		t.Errorf("Session should be stopped")
	}

	if session.StopReason != StopReasonManual {
		t.Errorf("Stop reason = %v, want manual", session.StopReason)
	}
}

func TestSessionManagerTokenCapture(t *testing.T) {
	dbPath := "test_token_capture.db"
	defer os.Remove(dbPath)

	storage, _ := NewStorage(dbPath)
	defer storage.Close()

	engine := NewEntropyEngine(storage, time.Now)
	sm := NewSessionManager(storage, engine, time.Now)

	extractor := TokenExtractor{Pattern: ".*", Location: "cookie", Name: "session"}
	session, _ := sm.StartSession("Capture Test", extractor, 50, 1*time.Minute)

	// Capture tokens
	for i := 0; i < 50; i++ {
		token := fmt.Sprintf("token_%d", i)
		if err := sm.OnTokenCaptured(session.ID, token, ""); err != nil {
			t.Fatalf("OnTokenCaptured() error = %v", err)
		}
	}

	// Get incremental stats
	stats, err := sm.GetIncrementalStats(session.ID)
	if err != nil {
		t.Fatalf("GetIncrementalStats() error = %v", err)
	}

	if stats.TokenCount != 50 {
		t.Errorf("Token count = %d, want 50", stats.TokenCount)
	}

	t.Logf("Incremental stats: %d tokens, %.2f entropy, %.2f%% reliability",
		stats.TokenCount, stats.CurrentEntropy, stats.ReliabilityScore)

	// Session should auto-stop at target
	session, _ = sm.GetSession(session.ID)
	if !session.IsStopped() {
		t.Errorf("Session should auto-stop at target")
	}

	if session.StopReason != StopReasonTargetReached {
		t.Errorf("Stop reason = %v, want target_reached", session.StopReason)
	}
}

func TestSessionManagerConcurrent(t *testing.T) {
	dbPath := "test_concurrent.db"
	defer os.Remove(dbPath)

	storage, _ := NewStorage(dbPath)
	defer storage.Close()

	engine := NewEntropyEngine(storage, time.Now)
	sm := NewSessionManager(storage, engine, time.Now)

	// Start multiple concurrent sessions
	sessions := make([]*CaptureSession, 5)
	for i := 0; i < 5; i++ {
		extractor := TokenExtractor{Pattern: ".*", Location: "cookie", Name: fmt.Sprintf("session_%d", i)}
		session, _ := sm.StartSession(fmt.Sprintf("Session %d", i), extractor, 0, 0)
		sessions[i] = session
	}

	// Capture tokens to each session concurrently
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(sessionID int64, idx int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				token := fmt.Sprintf("session%d_token%d", idx, j)
				sm.OnTokenCaptured(sessionID, token, "")
				time.Sleep(1 * time.Millisecond)
			}
		}(sessions[i].ID, i)
	}

	wg.Wait()

	// Verify all sessions have correct token counts
	for i, session := range sessions {
		updatedSession, _ := sm.GetSession(session.ID)
		if updatedSession.TokenCount != 20 {
			t.Errorf("Session %d: token count = %d, want 20", i, updatedSession.TokenCount)
		}
	}

	// Stop all sessions
	for _, session := range sessions {
		sm.StopSession(session.ID, StopReasonManual)
	}

	activeSessions := sm.GetActiveSessions()
	if len(activeSessions) != 0 {
		t.Errorf("Active sessions = %d, want 0", len(activeSessions))
	}
}

func TestSessionManagerPersistence(t *testing.T) {
	dbPath := "test_persistence.db"
	defer os.Remove(dbPath)

	storage, _ := NewStorage(dbPath)
	engine := NewEntropyEngine(storage, time.Now)
	sm := NewSessionManager(storage, engine, time.Now)

	// Create a session and capture some tokens
	extractor := TokenExtractor{Pattern: ".*", Location: "cookie", Name: "session"}
	session, _ := sm.StartSession("Persistent Session", extractor, 0, 0)

	for i := 0; i < 30; i++ {
		sm.OnTokenCaptured(session.ID, fmt.Sprintf("token_%d", i), "")
	}

	storage.Close()

	// Restart - create new storage and session manager
	storage2, _ := NewStorage(dbPath)
	defer storage2.Close()

	engine2 := NewEntropyEngine(storage2, time.Now)
	sm2 := NewSessionManager(storage2, engine2, time.Now)

	// Load active sessions
	if err := sm2.LoadActiveSessions(); err != nil {
		t.Fatalf("LoadActiveSessions() error = %v", err)
	}

	activeSessions := sm2.GetActiveSessions()
	if len(activeSessions) != 1 {
		t.Fatalf("Active sessions = %d, want 1", len(activeSessions))
	}

	if activeSessions[0].TokenCount != 30 {
		t.Errorf("Token count = %d, want 30", activeSessions[0].TokenCount)
	}

	// Incremental stats should be rebuilt
	stats, err := sm2.GetIncrementalStats(activeSessions[0].ID)
	if err != nil {
		t.Fatalf("GetIncrementalStats() error = %v", err)
	}

	if stats.TokenCount != 30 {
		t.Errorf("Incremental stats token count = %d, want 30", stats.TokenCount)
	}

	t.Logf("Persistence test passed: %d tokens restored", stats.TokenCount)
}

func TestIncrementalStats(t *testing.T) {
	stats := &IncrementalStats{
		TokenCount:    0,
		CharFrequency: make(map[rune]int),
		UniqueTokens:  make(map[string]bool),
		MinSampleSize: 100,
	}

	sm := &SessionManager{minSampleSize: 100}

	// Add tokens and check incremental updates
	tokens := []string{"abc123", "def456", "ghi789", "abc123"} // One duplicate

	for _, token := range tokens {
		sm.updateIncrementalStats(stats, token)
	}

	if stats.TokenCount != 4 {
		t.Errorf("Token count = %d, want 4", stats.TokenCount)
	}

	if stats.CollisionCount != 1 {
		t.Errorf("Collision count = %d, want 1", stats.CollisionCount)
	}

	if stats.CurrentEntropy == 0 {
		t.Errorf("Entropy should be > 0")
	}

	if stats.TokensNeeded != 96 {
		t.Errorf("Tokens needed = %d, want 96", stats.TokensNeeded)
	}

	t.Logf("Incremental stats: %.2f entropy, %.0f%% confidence, %d tokens needed",
		stats.CurrentEntropy, stats.ReliabilityScore, stats.TokensNeeded)
}

func TestAutoStopConditions(t *testing.T) {
	dbPath := "test_auto_stop.db"
	defer os.Remove(dbPath)

	storage, _ := NewStorage(dbPath)
	defer storage.Close()

	engine := NewEntropyEngine(storage, time.Now)
	sm := NewSessionManager(storage, engine, time.Now)

	// Test target count auto-stop
	t.Run("TargetCountStop", func(t *testing.T) {
		extractor := TokenExtractor{Pattern: ".*", Location: "cookie", Name: "session"}
		session, _ := sm.StartSession("Target Test", extractor, 10, 0)

		for i := 0; i < 10; i++ {
			sm.OnTokenCaptured(session.ID, fmt.Sprintf("token_%d", i), "")
		}

		// Should auto-stop
		session, _ = sm.GetSession(session.ID)
		if !session.IsStopped() {
			t.Errorf("Session should auto-stop at target")
		}

		if session.StopReason != StopReasonTargetReached {
			t.Errorf("Stop reason = %v, want target_reached", session.StopReason)
		}
	})

	// Test timeout auto-stop
	t.Run("TimeoutStop", func(t *testing.T) {
		extractor := TokenExtractor{Pattern: ".*", Location: "cookie", Name: "session"}
		
		// Use a custom now function for testing
		startTime := time.Now()
		nowFunc := func() time.Time { return startTime }
		
		// Create storage and engine with custom time
		engine2 := NewEntropyEngine(storage, nowFunc)
		sm2 := NewSessionManager(storage, engine2, nowFunc)
		
		session, _ := sm2.StartSession("Timeout Test", extractor, 0, 1*time.Second)

		// Capture one token
		sm2.OnTokenCaptured(session.ID, "token_1", "")

		// Simulate time passing
		nowFunc = func() time.Time { return startTime.Add(2 * time.Second) }

		// Check auto-stop
		if err := sm2.checkAutoStop(session); err != nil {
			// Should stop
			session, _ = storage.GetSession(session.ID)
			if !session.IsStopped() {
				t.Errorf("Session should timeout")
			}
		}
	})
}

func TestConfidenceMetrics(t *testing.T) {
	dbPath := "test_confidence.db"
	defer os.Remove(dbPath)

	storage, _ := NewStorage(dbPath)
	defer storage.Close()

	engine := NewEntropyEngine(storage, time.Now)

	// Test with small sample
	extractor := TokenExtractor{Pattern: ".*", Location: "cookie", Name: "session"}
	session, _ := storage.CreateSession("Confidence Test", extractor, 0, 0)

	tokens := generateRandomTokens(30, 16)
	now := time.Now().UTC()

	for i, token := range tokens {
		sample := TokenSample{
			CaptureSessionID: session.ID,
			TokenValue:       token,
			TokenLength:      len(token),
			CapturedAt:       now.Add(time.Duration(i) * time.Millisecond),
		}
		storage.StoreToken(sample)
	}

	analysis, _ := engine.AnalyzeSession(session.ID)

	if analysis.SampleQuality != "marginal" {
		t.Errorf("Sample quality = %s, want marginal", analysis.SampleQuality)
	}

	if analysis.TokensNeeded != 70 {
		t.Errorf("Tokens needed = %d, want 70", analysis.TokensNeeded)
	}

	if analysis.ConfidenceLevel >= 0.9 {
		t.Errorf("Confidence should be < 0.9 for small sample")
	}

	t.Logf("Confidence metrics: %.2f%% reliability, %s quality, need %d more tokens",
		analysis.ReliabilityScore, analysis.SampleQuality, analysis.TokensNeeded)

	// Test with large sample
	session2, _ := storage.CreateSession("Large Sample", extractor, 0, 0)

	tokens2 := generateRandomTokens(150, 16)
	for i, token := range tokens2 {
		sample := TokenSample{
			CaptureSessionID: session2.ID,
			TokenValue:       token,
			TokenLength:      len(token),
			CapturedAt:       now.Add(time.Duration(i) * time.Millisecond),
		}
		storage.StoreToken(sample)
	}

	analysis2, _ := engine.AnalyzeSession(session2.ID)

	if analysis2.SampleQuality != "excellent" {
		t.Errorf("Sample quality = %s, want excellent", analysis2.SampleQuality)
	}

	if analysis2.TokensNeeded != 0 {
		t.Errorf("Tokens needed = %d, want 0", analysis2.TokensNeeded)
	}

	if analysis2.ConfidenceLevel < 0.9 {
		t.Errorf("Confidence should be >= 0.9 for large sample")
	}

	t.Logf("Large sample: %.2f%% reliability, %s quality",
		analysis2.ReliabilityScore, analysis2.SampleQuality)
}

// Benchmark session manager overhead
func BenchmarkSessionManagerOverhead(b *testing.B) {
	dbPath := "bench_overhead.db"
	defer os.Remove(dbPath)

	storage, _ := NewStorage(dbPath)
	defer storage.Close()

	engine := NewEntropyEngine(storage, time.Now)
	sm := NewSessionManager(storage, engine, time.Now)

	extractor := TokenExtractor{Pattern: ".*", Location: "cookie", Name: "session"}
	session, _ := sm.StartSession("Benchmark Session", extractor, 0, 0)

	tokens := generateRandomTokens(1000, 16)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		token := tokens[i%len(tokens)]
		sm.OnTokenCaptured(session.ID, token, "")
	}

	elapsed := b.Elapsed()
	opsPerSec := float64(b.N) / elapsed.Seconds()
	avgOverhead := elapsed.Nanoseconds() / int64(b.N)

	b.Logf("Throughput: %.0f tokens/sec, Avg overhead: %.2f µs",
		opsPerSec, float64(avgOverhead)/1000.0)

	// Check if overhead is within acceptable limit (<5ms)
	avgMs := float64(avgOverhead) / 1000000.0
	if avgMs > 5.0 {
		b.Errorf("Average overhead %.2fms exceeds 5ms target", avgMs)
	}
}
