package main

import (
	"fmt"
	"math"
	"sync"
	"time"

	pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"
)

// SessionManager manages multiple concurrent capture sessions
type SessionManager struct {
	storage *Storage
	engine  *EntropyEngine
	now     func() time.Time
	ctx     *pluginsdk.Context // Plugin context for emitting findings

	// Session management
	mu               sync.RWMutex
	sessions         map[int64]*CaptureSession
	incrementalStats map[int64]*IncrementalStats
	notifications    chan SessionNotification

	// Configuration
	minSampleSize int     // Minimum tokens for reliable analysis (default: 100)
	maxOverheadMs float64 // Maximum overhead per response in milliseconds (default: 5ms)
}

// NewSessionManager creates a new session manager
func NewSessionManager(storage *Storage, engine *EntropyEngine, now func() time.Time) *SessionManager {
	if now == nil {
		now = time.Now
	}

	return &SessionManager{
		storage:          storage,
		engine:           engine,
		now:              now,
		ctx:              nil, // Set later via SetContext
		sessions:         make(map[int64]*CaptureSession),
		incrementalStats: make(map[int64]*IncrementalStats),
		notifications:    make(chan SessionNotification, 100),
		minSampleSize:    100,
		maxOverheadMs:    5.0,
	}
}

// SetContext sets the plugin context for emitting findings
func (sm *SessionManager) SetContext(ctx *pluginsdk.Context) {
	sm.ctx = ctx
}

// StartSession creates and starts a new capture session
func (sm *SessionManager) StartSession(name string, extractor TokenExtractor, targetCount int, timeout time.Duration) (*CaptureSession, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Create session in database
	session, err := sm.storage.CreateSession(name, extractor, targetCount, timeout)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	// Add to active sessions
	sm.sessions[session.ID] = session

	// Initialize incremental stats
	sm.incrementalStats[session.ID] = &IncrementalStats{
		TokenCount:    0,
		CharFrequency: make(map[rune]int),
		UniqueTokens:  make(map[string]bool),
		MinSampleSize: sm.minSampleSize,
		LastUpdated:   sm.now(),
	}

	// Send notification
	sm.sendNotification(SessionNotification{
		SessionID:   session.ID,
		SessionName: session.Name,
		Event:       "started",
		Message:     fmt.Sprintf("Capture session '%s' started", session.Name),
		Timestamp:   sm.now(),
		Data: map[string]interface{}{
			"target_count": targetCount,
			"timeout":      timeout.String(),
		},
	})

	return session, nil
}

// PauseSession pauses a capture session
func (sm *SessionManager) PauseSession(sessionID int64) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %d not found", sessionID)
	}

	if !session.IsActive() {
		return fmt.Errorf("session %d is not active", sessionID)
	}

	if err := sm.storage.PauseSession(sessionID); err != nil {
		return err
	}

	session.Status = CaptureStatusPaused
	now := sm.now()
	session.PausedAt = &now

	sm.sendNotification(SessionNotification{
		SessionID:   sessionID,
		SessionName: session.Name,
		Event:       "paused",
		Message:     fmt.Sprintf("Capture session '%s' paused", session.Name),
		Timestamp:   now,
	})

	return nil
}

// ResumeSession resumes a paused session
func (sm *SessionManager) ResumeSession(sessionID int64) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %d not found", sessionID)
	}

	if !session.IsPaused() {
		return fmt.Errorf("session %d is not paused", sessionID)
	}

	if err := sm.storage.ResumeSession(sessionID); err != nil {
		return err
	}

	session.Status = CaptureStatusActive
	session.PausedAt = nil

	sm.sendNotification(SessionNotification{
		SessionID:   sessionID,
		SessionName: session.Name,
		Event:       "resumed",
		Message:     fmt.Sprintf("Capture session '%s' resumed", session.Name),
		Timestamp:   sm.now(),
	})

	return nil
}

// StopSession stops a capture session
func (sm *SessionManager) StopSession(sessionID int64, reason StopReason) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %d not found", sessionID)
	}

	if session.IsStopped() {
		return nil // Already stopped
	}

	if err := sm.storage.StopSession(sessionID, reason); err != nil {
		return err
	}

	session.Status = CaptureStatusStopped
	session.StopReason = reason
	now := sm.now()
	session.CompletedAt = &now

	sm.sendNotification(SessionNotification{
		SessionID:   sessionID,
		SessionName: session.Name,
		Event:       "stopped",
		Message:     fmt.Sprintf("Capture session '%s' stopped: %s", session.Name, reason),
		Timestamp:   now,
		Data: map[string]interface{}{
			"reason":      string(reason),
			"token_count": session.TokenCount,
		},
	})

	// Remove from active sessions
	delete(sm.sessions, sessionID)
	delete(sm.incrementalStats, sessionID)

	return nil
}

// OnTokenCaptured is called when a token is captured (optimized for low overhead)
func (sm *SessionManager) OnTokenCaptured(sessionID int64, token string, requestID string) error {
	startTime := time.Now()

	sm.mu.Lock()
	session, exists := sm.sessions[sessionID]
	if !exists || !session.IsActive() {
		sm.mu.Unlock()
		return nil // Session not active, skip
	}

	stats := sm.incrementalStats[sessionID]
	sm.mu.Unlock()

	// Store token in database
	sample := TokenSample{
		CaptureSessionID: sessionID,
		TokenValue:       token,
		TokenLength:      len(token),
		CapturedAt:       sm.now(),
		SourceRequestID:  requestID,
	}

	if err := sm.storage.StoreToken(sample); err != nil {
		return fmt.Errorf("store token: %w", err)
	}

	// Update incremental statistics (in-memory, fast)
	sm.updateIncrementalStats(stats, token)

	// Update session
	sm.mu.Lock()
	session.TokenCount++
	tokenCount := session.TokenCount
	sm.mu.Unlock()

	// Check auto-stop conditions
	if err := sm.checkAutoStop(session); err != nil {
		return err
	}

	// Check if we should run analysis
	if session.ShouldAnalyze() {
		sm.triggerAnalysis(session, stats)
	}

	// Check overhead
	elapsed := time.Since(startTime)
	if elapsed.Milliseconds() > int64(sm.maxOverheadMs) {
		// Log warning if overhead too high
		fmt.Printf("WARNING: Token capture overhead %.2fms (target: %.2fms)\n",
			float64(elapsed.Microseconds())/1000.0, sm.maxOverheadMs)
	}

	return nil
}

// updateIncrementalStats updates streaming statistics
func (sm *SessionManager) updateIncrementalStats(stats *IncrementalStats, token string) {
	stats.TokenCount++

	// Check for collisions
	if stats.UniqueTokens[token] {
		stats.CollisionCount++
	} else {
		stats.UniqueTokens[token] = true
	}

	// Update character frequency
	for _, ch := range token {
		stats.CharFrequency[ch]++
		stats.TotalChars++
	}

	// Update incremental entropy
	stats.CurrentEntropy = sm.calculateIncrementalEntropy(stats)

	// Update confidence metrics
	sm.updateConfidenceMetrics(stats)

	stats.LastUpdated = sm.now()
}

// calculateIncrementalEntropy calculates Shannon entropy from character frequencies
func (sm *SessionManager) calculateIncrementalEntropy(stats *IncrementalStats) float64 {
	if stats.TotalChars == 0 {
		return 0
	}

	entropy := 0.0
	for _, count := range stats.CharFrequency {
		probability := float64(count) / float64(stats.TotalChars)
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

// updateConfidenceMetrics calculates confidence based on sample size
func (sm *SessionManager) updateConfidenceMetrics(stats *IncrementalStats) {
	// Confidence increases with sample size using sigmoid function
	// Reaches 90% at minSampleSize, approaches 100% asymptotically
	x := float64(stats.TokenCount) / float64(stats.MinSampleSize)
	stats.ConfidenceLevel = 1.0 / (1.0 + math.Exp(-5*(x-0.5)))

	// Calculate reliability score (0-100)
	stats.ReliabilityScore = stats.ConfidenceLevel * 100

	// Tokens needed for full confidence
	if stats.TokenCount < stats.MinSampleSize {
		stats.TokensNeeded = stats.MinSampleSize - stats.TokenCount
	} else {
		stats.TokensNeeded = 0
	}
}

// checkAutoStop checks if session should auto-stop
func (sm *SessionManager) checkAutoStop(session *CaptureSession) error {
	now := sm.now()

	// Check target count
	if session.HasReachedTarget() {
		return sm.StopSession(session.ID, StopReasonTargetReached)
	}

	// Check timeout
	if session.IsTimedOut(now) {
		return sm.StopSession(session.ID, StopReasonTimeout)
	}

	// Check for pattern detection (weak PRNG detected early)
	// This is checked during analysis, not here to avoid overhead

	return nil
}

// triggerAnalysis runs full analysis asynchronously
func (sm *SessionManager) triggerAnalysis(session *CaptureSession, stats *IncrementalStats) {
	// Run analysis in background to avoid blocking token capture
	go func() {
		analysis, err := sm.engine.AnalyzeSession(session.ID)
		if err != nil {
			// Log error but don't fail
			if sm.ctx != nil {
				sm.ctx.Logger().Error("failed to analyze session", "session_id", session.ID, "error", err)
			}
			return
		}

		// Update session's last analysis tracking
		sm.mu.Lock()
		now := sm.now()
		session.LastAnalyzedAt = &now
		session.LastAnalysisCount = session.TokenCount
		sm.storage.UpdateSession(session)
		sm.mu.Unlock()

		// Send notification
		sm.sendNotification(SessionNotification{
			SessionID:   session.ID,
			SessionName: session.Name,
			Event:       "analyzed",
			Message:     fmt.Sprintf("Analysis complete: Score %.1f/100, Risk: %s", analysis.RandomnessScore, analysis.Risk),
			Timestamp:   now,
			Data: map[string]interface{}{
				"randomness_score": analysis.RandomnessScore,
				"risk":             string(analysis.Risk),
				"token_count":      analysis.TokenCount,
				"entropy":          analysis.ShannonEntropy,
				"collision_rate":   analysis.CollisionRate,
			},
		})

		// Create and emit finding to Atlas
		if sm.ctx != nil {
			finding := sm.engine.CreateFinding(analysis, session)
			if err := sm.ctx.EmitFinding(finding); err != nil {
				sm.ctx.Logger().Error("failed to emit finding", "session_id", session.ID, "error", err)
			} else {
				sm.ctx.Logger().Info("emitted entropy finding",
					"session_id", session.ID,
					"risk", analysis.Risk,
					"randomness_score", analysis.RandomnessScore)
			}
		}

		// Auto-stop if critical pattern detected
		if analysis.Risk == RiskCritical && len(analysis.DetectedPatterns) > 0 {
			sm.StopSession(session.ID, StopReasonPatternDetected)
		}
	}()
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID int64) (*CaptureSession, error) {
	sm.mu.RLock()
	session, exists := sm.sessions[sessionID]
	sm.mu.RUnlock()

	if exists {
		return session, nil
	}

	// Not in memory, load from database
	return sm.storage.GetSession(sessionID)
}

// GetActiveSessions returns all active sessions
func (sm *SessionManager) GetActiveSessions() []*CaptureSession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*CaptureSession, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// GetIncrementalStats returns incremental stats for a session
func (sm *SessionManager) GetIncrementalStats(sessionID int64) (*IncrementalStats, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats, exists := sm.incrementalStats[sessionID]
	if !exists {
		return nil, fmt.Errorf("session %d not found or not active", sessionID)
	}

	return stats, nil
}

// LoadActiveSessions loads active sessions from database on startup
func (sm *SessionManager) LoadActiveSessions() error {
	sessions, err := sm.storage.GetActiveSessions()
	if err != nil {
		return fmt.Errorf("load active sessions: %w", err)
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, session := range sessions {
		sm.sessions[session.ID] = session

		// Rebuild incremental stats from stored tokens
		stats := &IncrementalStats{
			TokenCount:    0,
			CharFrequency: make(map[rune]int),
			UniqueTokens:  make(map[string]bool),
			MinSampleSize: sm.minSampleSize,
			LastUpdated:   sm.now(),
		}

		// Load tokens and rebuild stats
		tokens, err := sm.storage.GetTokens(session.ID)
		if err == nil {
			for _, token := range tokens {
				sm.updateIncrementalStats(stats, token.TokenValue)
			}
		}

		sm.incrementalStats[session.ID] = stats
	}

	return nil
}

// sendNotification sends a notification (non-blocking)
func (sm *SessionManager) sendNotification(notification SessionNotification) {
	select {
	case sm.notifications <- notification:
	default:
		// Channel full, drop notification
	}
}

// GetNotifications returns the notification channel
func (sm *SessionManager) GetNotifications() <-chan SessionNotification {
	return sm.notifications
}

// CleanupSessions stops timed-out sessions
func (sm *SessionManager) CleanupSessions() {
	// Collect timed-out session IDs while holding the lock
	sm.mu.RLock()
	now := sm.now()
	var timedOutIDs []int64
	for id, session := range sm.sessions {
		if session.IsTimedOut(now) {
			timedOutIDs = append(timedOutIDs, id)
		}
	}
	sm.mu.RUnlock()

	// Stop sessions outside the lock to avoid deadlock
	// (StopSession acquires the mutex itself)
	for _, id := range timedOutIDs {
		sm.StopSession(id, StopReasonTimeout)
	}
}
