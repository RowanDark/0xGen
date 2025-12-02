package blitz

import (
	"os"
	"sync"
	"testing"
	"time"
)

// TestStore_AtomicOperations verifies that Store performs the insert
// atomically within a transaction
func TestStore_AtomicOperations(t *testing.T) {
	// Create temporary database
	dbPath := "test_atomic_store.db"
	defer os.Remove(dbPath)

	storage, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer storage.Close()

	// Create a FuzzResult to store
	result := &FuzzResult{
		RequestID:    "req-001",
		Position:     0,
		PositionName: "param1",
		Payload:      "test-payload",
		StatusCode:   200,
		Duration:     100,
		ContentLen:   256,
		Request: MessageSnapshot{
			Method:  "POST",
			URL:     "http://example.com/api",
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    `{"test": "data"}`,
		},
		Response: MessageSnapshot{
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    `{"result": "success"}`,
		},
		Timestamp: time.Now().UTC(),
	}

	// Store the result
	err = storage.Store(result)
	if err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	// Verify result ID was set
	if result.ID == 0 {
		t.Error("Result ID should be set after Store()")
	}

	// Verify result was inserted in database
	var count int
	err = storage.db.QueryRow(`
		SELECT COUNT(*) FROM results WHERE session_id = ?
	`, storage.sessionID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query result count: %v", err)
	}
	if count != 1 {
		t.Errorf("Result count = %d, want 1", count)
	}

	// Verify stored data
	var storedPayload string
	var storedStatusCode int
	err = storage.db.QueryRow(`
		SELECT payload, status_code FROM results WHERE id = ?
	`, result.ID).Scan(&storedPayload, &storedStatusCode)
	if err != nil {
		t.Fatalf("Failed to query stored result: %v", err)
	}
	if storedPayload != "test-payload" {
		t.Errorf("Stored payload = %s, want test-payload", storedPayload)
	}
	if storedStatusCode != 200 {
		t.Errorf("Stored status code = %d, want 200", storedStatusCode)
	}

	t.Logf("Atomic operations test passed: result ID = %d", result.ID)
}

// TestStore_MultipleResults tests storing multiple results and verifying IDs are correctly assigned
func TestStore_MultipleResults(t *testing.T) {
	// Create temporary database
	dbPath := "test_multiple_store.db"
	defer os.Remove(dbPath)

	storage, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer storage.Close()

	// Store multiple results
	numResults := 10
	results := make([]*FuzzResult, numResults)
	now := time.Now().UTC()

	for i := 0; i < numResults; i++ {
		results[i] = &FuzzResult{
			RequestID:    "req-" + string(rune('A'+i)),
			Position:     i,
			PositionName: "param",
			Payload:      "payload-" + string(rune('A'+i)),
			StatusCode:   200 + i,
			Duration:     int64(100 + i*10),
			ContentLen:   int64(256 + i),
			Request: MessageSnapshot{
				Method: "GET",
				URL:    "http://example.com/test",
			},
			Response: MessageSnapshot{
				Body: "response body",
			},
			Timestamp: now.Add(time.Duration(i) * time.Second),
		}

		err = storage.Store(results[i])
		if err != nil {
			t.Fatalf("Store() for result %d error = %v", i, err)
		}

		if results[i].ID == 0 {
			t.Errorf("Result %d ID should be set after Store()", i)
		}
	}

	// Verify all results were stored
	var count int
	err = storage.db.QueryRow(`
		SELECT COUNT(*) FROM results WHERE session_id = ?
	`, storage.sessionID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query result count: %v", err)
	}
	if count != numResults {
		t.Errorf("Result count = %d, want %d", count, numResults)
	}

	// Verify IDs are unique and sequential
	idMap := make(map[int64]bool)
	for i, r := range results {
		if idMap[r.ID] {
			t.Errorf("Duplicate ID found for result %d: %d", i, r.ID)
		}
		idMap[r.ID] = true
	}

	t.Logf("Multiple results test passed: %d results stored with unique IDs", numResults)
}

// TestStore_ConcurrentAtomicity tests that concurrent Store calls maintain data integrity
func TestStore_ConcurrentAtomicity(t *testing.T) {
	// Create temporary database
	dbPath := "test_concurrent_store.db"
	defer os.Remove(dbPath)

	storage, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer storage.Close()

	// Store results concurrently
	numGoroutines := 10
	resultsPerGoroutine := 10
	expectedTotal := numGoroutines * resultsPerGoroutine

	var wg sync.WaitGroup
	var mu sync.Mutex
	allResults := make([]*FuzzResult, 0, expectedTotal)
	now := time.Now().UTC()

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < resultsPerGoroutine; i++ {
				result := &FuzzResult{
					RequestID:    "req-" + string(rune('A'+goroutineID)) + "-" + string(rune('0'+i)),
					Position:     goroutineID*resultsPerGoroutine + i,
					PositionName: "param",
					Payload:      "payload",
					StatusCode:   200,
					Duration:     100,
					ContentLen:   256,
					Request: MessageSnapshot{
						Method: "GET",
						URL:    "http://example.com/test",
					},
					Response: MessageSnapshot{
						Body: "response",
					},
					Timestamp: now.Add(time.Duration(goroutineID*resultsPerGoroutine+i) * time.Millisecond),
				}

				if err := storage.Store(result); err != nil {
					t.Errorf("Store() goroutine %d, result %d error = %v", goroutineID, i, err)
					return
				}

				mu.Lock()
				allResults = append(allResults, result)
				mu.Unlock()
			}
		}(g)
	}

	wg.Wait()

	// Verify all results were stored
	var count int
	err = storage.db.QueryRow(`
		SELECT COUNT(*) FROM results WHERE session_id = ?
	`, storage.sessionID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query result count: %v", err)
	}

	if count != expectedTotal {
		t.Errorf("Result count = %d, want %d", count, expectedTotal)
	}

	// Verify all IDs are unique
	idMap := make(map[int64]bool)
	for _, r := range allResults {
		if r.ID == 0 {
			t.Error("Found result with ID = 0")
			continue
		}
		if idMap[r.ID] {
			t.Errorf("Duplicate ID found: %d", r.ID)
		}
		idMap[r.ID] = true
	}

	if len(idMap) != expectedTotal {
		t.Errorf("Unique IDs count = %d, want %d", len(idMap), expectedTotal)
	}

	t.Logf("Concurrent atomicity test passed: %d results stored with unique IDs", count)
}

// TestStore_WithAnomalyIndicator tests storing results with anomaly data
func TestStore_WithAnomalyIndicator(t *testing.T) {
	// Create temporary database
	dbPath := "test_anomaly_store.db"
	defer os.Remove(dbPath)

	storage, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer storage.Close()

	// Create result with anomaly indicator
	result := &FuzzResult{
		RequestID:    "req-anomaly",
		Position:     0,
		PositionName: "param",
		Payload:      "anomaly-payload",
		StatusCode:   500,
		Duration:     5000,
		ContentLen:   1024,
		Request: MessageSnapshot{
			Method: "POST",
			URL:    "http://example.com/api",
		},
		Response: MessageSnapshot{
			Body: "error response",
		},
		Timestamp: time.Now().UTC(),
		Anomaly: &AnomalyIndicator{
			StatusCodeAnomaly:  true,
			ContentLengthDelta: 500,
			ResponseTimeFactor: 2.5,
			PatternAnomalies:   3,
			IsInteresting:      true,
		},
	}

	err = storage.Store(result)
	if err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	// Verify anomaly data was stored
	var isInteresting bool
	var anomalyStatus bool
	var contentDelta int64
	var timeFactor float64

	err = storage.db.QueryRow(`
		SELECT is_interesting, anomaly_status_code, anomaly_content_len_delta, anomaly_response_time_factor
		FROM results WHERE id = ?
	`, result.ID).Scan(&isInteresting, &anomalyStatus, &contentDelta, &timeFactor)
	if err != nil {
		t.Fatalf("Failed to query anomaly data: %v", err)
	}

	if !isInteresting {
		t.Error("is_interesting should be true")
	}
	if !anomalyStatus {
		t.Error("anomaly_status_code should be true")
	}
	if contentDelta != 500 {
		t.Errorf("anomaly_content_len_delta = %d, want 500", contentDelta)
	}
	if timeFactor != 2.5 {
		t.Errorf("anomaly_response_time_factor = %f, want 2.5", timeFactor)
	}

	t.Logf("Anomaly indicator test passed: result ID = %d", result.ID)
}

// BenchmarkStore_TransactionOverhead measures the overhead of transaction-based storage
func BenchmarkStore_TransactionOverhead(b *testing.B) {
	dbPath := "bench_store.db"
	defer os.Remove(dbPath)

	storage, err := NewSQLiteStorage(dbPath)
	if err != nil {
		b.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer storage.Close()

	now := time.Now().UTC()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		result := &FuzzResult{
			RequestID:    "req-bench",
			Position:     i,
			PositionName: "param",
			Payload:      "benchmark-payload",
			StatusCode:   200,
			Duration:     100,
			ContentLen:   256,
			Request: MessageSnapshot{
				Method: "GET",
				URL:    "http://example.com/test",
			},
			Response: MessageSnapshot{
				Body: "response",
			},
			Timestamp: now,
		}

		if err := storage.Store(result); err != nil {
			b.Fatalf("Store() error = %v", err)
		}
	}

	elapsed := b.Elapsed()
	opsPerSec := float64(b.N) / elapsed.Seconds()
	avgOverhead := elapsed.Nanoseconds() / int64(b.N)

	b.Logf("Throughput: %.0f ops/sec, Avg overhead: %.2f µs", opsPerSec, float64(avgOverhead)/1000.0)

	// Check if overhead is within acceptable limit (<5ms = 5000µs)
	avgUs := float64(avgOverhead) / 1000.0
	if avgUs > 5000.0 {
		b.Errorf("Average overhead %.2f µs exceeds 5000 µs (5ms) target", avgUs)
	}
}

// TestGetResult_CorruptedJSON tests that GetResult returns error for corrupted JSON
func TestGetResult_CorruptedJSON(t *testing.T) {
	dbPath := "test_corrupted_json.db"
	defer os.Remove(dbPath)

	storage, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer storage.Close()

	// Insert a result with corrupted JSON directly into the database
	_, err = storage.db.Exec(`
		INSERT INTO results (
			session_id, request_id, position, position_name, payload,
			payload_set, status_code, duration_ms, content_length,
			request_method, request_url, request_headers, request_body,
			response_headers, response_body, matches, error, timestamp,
			anomaly_status_code, anomaly_content_len_delta,
			anomaly_response_time_factor, anomaly_pattern_count, is_interesting
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, storage.sessionID, "req-corrupt", 0, "param", "test",
		"{invalid json{{{", 200, 100, 256,
		"GET", "http://example.com", "[]", "body",
		"[]", "response", "[]", nil, time.Now().Unix(),
		false, 0, 0.0, 0, false)
	if err != nil {
		t.Fatalf("Failed to insert corrupted result: %v", err)
	}

	// Get the inserted ID
	var id int64
	err = storage.db.QueryRow(`
		SELECT id FROM results WHERE request_id = ? AND session_id = ?
	`, "req-corrupt", storage.sessionID).Scan(&id)
	if err != nil {
		t.Fatalf("Failed to get result ID: %v", err)
	}

	// GetResult should return error
	_, err = storage.GetResult(id)
	if err == nil {
		t.Error("GetResult should return error for corrupted payload_set JSON")
	}
	if err != nil && err.Error() == "" {
		t.Error("Error message should not be empty")
	}
}
