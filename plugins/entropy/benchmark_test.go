package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// Benchmark statistical functions

func BenchmarkChiSquaredTest(b *testing.B) {
	sizes := []int{100, 1000, 10000}

	for _, size := range sizes {
		tokens := generateBenchTokens(size, 16)
		b.Run(fmt.Sprintf("tokens=%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ChiSquaredTest(tokens)
			}
		})
	}
}

func BenchmarkRunsTest(b *testing.B) {
	sizes := []int{100, 1000, 10000}

	for _, size := range sizes {
		tokens := generateBenchTokens(size, 16)
		b.Run(fmt.Sprintf("tokens=%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				RunsTest(tokens)
			}
		})
	}
}

func BenchmarkSerialCorrelationTest(b *testing.B) {
	sizes := []int{100, 1000, 10000}

	for _, size := range sizes {
		tokens := generateBenchTokens(size, 16)
		b.Run(fmt.Sprintf("tokens=%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				SerialCorrelationTest(tokens)
			}
		})
	}
}

func BenchmarkSpectralTest(b *testing.B) {
	sizes := []int{100, 1000, 10000}

	for _, size := range sizes {
		tokens := generateBenchTokens(size, 16)
		b.Run(fmt.Sprintf("tokens=%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				SpectralTest(tokens)
			}
		})
	}
}

func BenchmarkCalculateEntropy(b *testing.B) {
	sizes := []int{100, 1000, 10000}

	for _, size := range sizes {
		tokens := generateBenchTokens(size, 16)
		b.Run(fmt.Sprintf("tokens=%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				CalculateEntropy(tokens)
			}
		})
	}
}

func BenchmarkDetectCollisions(b *testing.B) {
	sizes := []int{100, 1000, 10000}

	for _, size := range sizes {
		tokens := generateBenchTokens(size, 16)
		b.Run(fmt.Sprintf("tokens=%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				DetectCollisions(tokens)
			}
		})
	}
}

func BenchmarkAnalyzeBitDistribution(b *testing.B) {
	sizes := []int{100, 1000, 10000}

	for _, size := range sizes {
		tokens := generateBenchTokens(size, 16)
		b.Run(fmt.Sprintf("tokens=%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				AnalyzeBitDistribution(tokens)
			}
		})
	}
}

// Benchmark full analysis workflow

func BenchmarkFullAnalysisWorkflow(b *testing.B) {
	sizes := []int{100, 1000, 10000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("tokens=%d", size), func(b *testing.B) {
			// Create temporary storage
			storage, err := NewStorage(":memory:")
			if err != nil {
				b.Fatalf("Failed to create storage: %v", err)
			}
			defer storage.Close()

			engine := NewEntropyEngine(storage, time.Now)

			// Create session
			session, err := storage.CreateSession("bench", TokenExtractor{}, 0, 0)
			if err != nil {
				b.Fatalf("Failed to create session: %v", err)
			}

			// Add tokens
			tokens := generateBenchTokens(size, 16)
			for _, token := range tokens {
				storage.AddTokenSample(session.ID, token, len(token), "")
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := engine.AnalyzeSession(session.ID)
				if err != nil {
					b.Fatalf("Analysis failed: %v", err)
				}
			}
		})
	}
}

// Benchmark session manager overhead

func BenchmarkSessionManagerTokenCapture(b *testing.B) {
	storage, err := NewStorage(":memory:")
	if err != nil {
		b.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	engine := NewEntropyEngine(storage, time.Now)
	manager := NewSessionManager(storage, engine, time.Now)

	session, err := manager.StartSession("bench", TokenExtractor{}, 10000, 3600)
	if err != nil {
		b.Fatalf("Failed to start session: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := manager.OnTokenCaptured(session.ID, fmt.Sprintf("token_%d", i), fmt.Sprintf("req_%d", i))
		if err != nil {
			b.Fatalf("Token capture failed: %v", err)
		}
	}
	b.StopTimer()

	// Report overhead per token
	nsPerOp := b.Elapsed().Nanoseconds() / int64(b.N)
	msPerOp := float64(nsPerOp) / 1000000.0
	b.ReportMetric(msPerOp, "ms/token")
}

// Benchmark concurrent session handling

func BenchmarkConcurrentSessions(b *testing.B) {
	sessions := []int{1, 5, 10, 20}

	for _, numSessions := range sessions {
		b.Run(fmt.Sprintf("sessions=%d", numSessions), func(b *testing.B) {
			storage, err := NewStorage(":memory:")
			if err != nil {
				b.Fatalf("Failed to create storage: %v", err)
			}
			defer storage.Close()

			engine := NewEntropyEngine(storage, time.Now)
			manager := NewSessionManager(storage, engine, time.Now)

			// Start multiple sessions
			sessionIDs := make([]int64, numSessions)
			for i := 0; i < numSessions; i++ {
				session, err := manager.StartSession(
					fmt.Sprintf("session_%d", i),
					TokenExtractor{},
					1000,
					3600,
				)
				if err != nil {
					b.Fatalf("Failed to start session: %v", err)
				}
				sessionIDs[i] = session.ID
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sessionID := sessionIDs[i%numSessions]
				err := manager.OnTokenCaptured(
					sessionID,
					fmt.Sprintf("token_%d", i),
					fmt.Sprintf("req_%d", i),
				)
				if err != nil {
					b.Fatalf("Token capture failed: %v", err)
				}
			}
		})
	}
}

// Benchmark PRNG fingerprinting

func BenchmarkFingerprintPRNG(b *testing.B) {
	tokens := generateBenchTokens(200, 16)
	analysis := &EntropyAnalysis{
		TokenCount: len(tokens),
	}
	analysis.ChiSquared = ChiSquaredTest(tokens)
	analysis.Runs = RunsTest(tokens)
	analysis.SerialCorrelation = SerialCorrelationTest(tokens)
	analysis.Spectral = SpectralTest(tokens)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FingerprintPRNG(analysis, tokens)
	}
}

// Benchmark pattern detection

func BenchmarkPatternDetection(b *testing.B) {
	tokens := generateBenchTokens(200, 16)
	entropy := CalculateEntropy(tokens)
	charSet := GetCharacterSet(tokens)

	b.Run("Sequential", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			DetectSequentialPattern(tokens)
		}
	})

	b.Run("LowEntropy", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			DetectLowEntropyPattern(tokens, entropy, charSet)
		}
	})

	b.Run("RepeatedSubstrings", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			DetectRepeatedSubstrings(tokens)
		}
	})
}

// Benchmark incremental statistics

func BenchmarkIncrementalStatsUpdate(b *testing.B) {
	storage, err := NewStorage(":memory:")
	if err != nil {
		b.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	engine := NewEntropyEngine(storage, time.Now)
	manager := NewSessionManager(storage, engine, time.Now)

	session, err := manager.StartSession("bench", TokenExtractor{}, 100000, 0)
	if err != nil {
		b.Fatalf("Failed to start session: %v", err)
	}

	stats := &IncrementalStats{
		CharFrequency: make(map[rune]int),
		MinSampleSize: 30,
		LastUpdated:   time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token := fmt.Sprintf("token_%d", i)
		manager.updateIncrementalStats(stats, token)
	}

	// Verify incremental calculation is fast
	nsPerOp := b.Elapsed().Nanoseconds() / int64(b.N)
	usPerOp := float64(nsPerOp) / 1000.0
	b.ReportMetric(usPerOp, "μs/token")

	if usPerOp > 100 {
		b.Errorf("Incremental stats update too slow: %.2f μs/token (should be < 100 μs)", usPerOp)
	}
}

// Benchmark memory usage

func BenchmarkMemoryUsage(b *testing.B) {
	sizes := []int{1000, 10000, 100000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("tokens=%d", size), func(b *testing.B) {
			storage, err := NewStorage(":memory:")
			if err != nil {
				b.Fatalf("Failed to create storage: %v", err)
			}
			defer storage.Close()

			session, err := storage.CreateSession("bench", TokenExtractor{}, 0, 0)
			if err != nil {
				b.Fatalf("Failed to create session: %v", err)
			}

			tokens := generateBenchTokens(size, 16)

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, token := range tokens {
					storage.AddTokenSample(session.ID, token, len(token), "")
				}
			}
		})
	}
}

// Benchmark token extraction

func BenchmarkTokenExtraction(b *testing.B) {
	// Create mock HTTP response
	response := &HTTPResponse{
		StatusCode: 200,
		Headers: map[string][]string{
			"Set-Cookie": {"session=abc123; Path=/"},
			"X-CSRF-Token": {"token_xyz"},
		},
		Body: []byte(`{"token": "jwt_token_here", "user_id": 12345}`),
	}

	extractors := []struct {
		name      string
		extractor TokenExtractor
	}{
		{
			name: "Cookie",
			extractor: TokenExtractor{
				Location: "cookie",
				Name:     "session",
			},
		},
		{
			name: "Header",
			extractor: TokenExtractor{
				Location: "header",
				Name:     "X-CSRF-Token",
			},
		},
		{
			name: "JSON",
			extractor: TokenExtractor{
				Location: "body",
				Name:     "token",
			},
		},
	}

	for _, ext := range extractors {
		b.Run(ext.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := ExtractTokens(response, ext.extractor, "req_id")
				if err != nil {
					b.Fatalf("Extraction failed: %v", err)
				}
			}
		})
	}
}

// Benchmark database operations

func BenchmarkDatabaseOperations(b *testing.B) {
	storage, err := NewStorage(":memory:")
	if err != nil {
		b.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	b.Run("CreateSession", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := storage.CreateSession(fmt.Sprintf("session_%d", i), TokenExtractor{}, 0, 0)
			if err != nil {
				b.Fatalf("CreateSession failed: %v", err)
			}
		}
	})

	session, _ := storage.CreateSession("bench", TokenExtractor{}, 0, 0)

	b.Run("AddTokenSample", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := storage.AddTokenSample(session.ID, fmt.Sprintf("token_%d", i), 10, "req")
			if err != nil {
				b.Fatalf("AddTokenSample failed: %v", err)
			}
		}
	})

	// Add some tokens for retrieval benchmarks
	for i := 0; i < 1000; i++ {
		storage.AddTokenSample(session.ID, fmt.Sprintf("token_%d", i), 10, "req")
	}

	b.Run("GetTokenSamples", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := storage.GetTokenSamples(session.ID, 100)
			if err != nil {
				b.Fatalf("GetTokenSamples failed: %v", err)
			}
		}
	})

	b.Run("GetActiveSessions", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := storage.GetActiveSessions()
			if err != nil {
				b.Fatalf("GetActiveSessions failed: %v", err)
			}
		}
	})
}

// Helper function to generate benchmark tokens
func generateBenchTokens(count, length int) []string {
	tokens := make([]string, count)
	for i := 0; i < count; i++ {
		bytes := make([]byte, length)
		rand.Read(bytes)
		tokens[i] = hex.EncodeToString(bytes)
	}
	return tokens
}

// Performance requirement validation tests

func TestPerformanceRequirements(t *testing.T) {
	t.Run("Capture overhead < 5ms", func(t *testing.T) {
		storage, err := NewStorage(":memory:")
		if err != nil {
			t.Fatalf("Failed to create storage: %v", err)
		}
		defer storage.Close()

		engine := NewEntropyEngine(storage, time.Now)
		manager := NewSessionManager(storage, engine, time.Now)

		session, err := manager.StartSession("test", TokenExtractor{}, 1000, 3600)
		if err != nil {
			t.Fatalf("Failed to start session: %v", err)
		}

		// Measure 100 token captures
		iterations := 100
		start := time.Now()
		for i := 0; i < iterations; i++ {
			err := manager.OnTokenCaptured(session.ID, fmt.Sprintf("token_%d", i), fmt.Sprintf("req_%d", i))
			if err != nil {
				t.Fatalf("Token capture failed: %v", err)
			}
		}
		elapsed := time.Since(start)

		avgMs := float64(elapsed.Milliseconds()) / float64(iterations)
		t.Logf("Average capture overhead: %.3f ms/token", avgMs)

		if avgMs > 5.0 {
			t.Errorf("Capture overhead %.3f ms exceeds 5ms requirement", avgMs)
		}
	})

	t.Run("Analysis < 5s for 1000 tokens", func(t *testing.T) {
		storage, err := NewStorage(":memory:")
		if err != nil {
			t.Fatalf("Failed to create storage: %v", err)
		}
		defer storage.Close()

		engine := NewEntropyEngine(storage, time.Now)

		session, err := storage.CreateSession("test", TokenExtractor{}, 0, 0)
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}

		// Add 1000 tokens
		tokens := generateBenchTokens(1000, 16)
		for _, token := range tokens {
			storage.AddTokenSample(session.ID, token, len(token), "")
		}

		start := time.Now()
		_, err = engine.AnalyzeSession(session.ID)
		if err != nil {
			t.Fatalf("Analysis failed: %v", err)
		}
		elapsed := time.Since(start)

		t.Logf("Analysis time for 1000 tokens: %v", elapsed)

		if elapsed > 5*time.Second {
			t.Errorf("Analysis time %v exceeds 5s requirement", elapsed)
		}
	})
}
