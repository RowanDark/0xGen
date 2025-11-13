package blitz

import (
	"testing"
)

func TestSniperStrategy(t *testing.T) {
	positions := []Position{
		{Index: 0, Name: "param1"},
		{Index: 1, Name: "param2"},
	}
	payloads := [][]string{{"a", "b", "c"}}

	strategy := &SniperStrategy{}
	jobs, err := strategy.GenerateJobs(positions, payloads)

	if err != nil {
		t.Fatalf("GenerateJobs() error = %v", err)
	}

	// Sniper: 2 positions × 3 payloads = 6 jobs
	expected := 2 * 3
	if len(jobs) != expected {
		t.Errorf("Expected %d jobs, got %d", expected, len(jobs))
	}
}

func TestBatteringRamStrategy(t *testing.T) {
	positions := []Position{
		{Index: 0, Name: "param1"},
		{Index: 1, Name: "param2"},
	}
	payloads := [][]string{{"a", "b", "c"}}

	strategy := &BatteringRamStrategy{}
	jobs, err := strategy.GenerateJobs(positions, payloads)

	if err != nil {
		t.Fatalf("GenerateJobs() error = %v", err)
	}

	// Battering Ram: 3 payloads (applied to all positions simultaneously)
	expected := 3
	if len(jobs) != expected {
		t.Errorf("Expected %d jobs, got %d", expected, len(jobs))
	}

	// Check first job has payload in all positions
	if len(jobs[0].PayloadMap) != 2 {
		t.Errorf("Expected job to have 2 positions filled, got %d", len(jobs[0].PayloadMap))
	}
}

func TestPitchforkStrategy(t *testing.T) {
	positions := []Position{
		{Index: 0, Name: "param1"},
		{Index: 1, Name: "param2"},
	}
	payloads := [][]string{
		{"a", "b", "c"},
		{"1", "2", "3"},
	}

	strategy := &PitchforkStrategy{}
	jobs, err := strategy.GenerateJobs(positions, payloads)

	if err != nil {
		t.Fatalf("GenerateJobs() error = %v", err)
	}

	// Pitchfork: min(3, 3) = 3 jobs
	expected := 3
	if len(jobs) != expected {
		t.Errorf("Expected %d jobs, got %d", expected, len(jobs))
	}

	// Check first job pairs correctly
	if jobs[0].PayloadMap[0] != "a" || jobs[0].PayloadMap[1] != "1" {
		t.Errorf("Job 0 payload map incorrect: %v", jobs[0].PayloadMap)
	}
}

func TestClusterBombStrategy(t *testing.T) {
	positions := []Position{
		{Index: 0, Name: "param1"},
		{Index: 1, Name: "param2"},
	}
	payloads := [][]string{
		{"a", "b"},
		{"1", "2"},
	}

	strategy := &ClusterBombStrategy{}
	jobs, err := strategy.GenerateJobs(positions, payloads)

	if err != nil {
		t.Fatalf("GenerateJobs() error = %v", err)
	}

	// Cluster Bomb: 2 × 2 = 4 jobs (cartesian product)
	expected := 4
	if len(jobs) != expected {
		t.Errorf("Expected %d jobs, got %d", expected, len(jobs))
	}
}

func TestGetStrategy(t *testing.T) {
	tests := []struct {
		attackType AttackType
		wantErr    bool
	}{
		{AttackTypeSniper, false},
		{AttackTypeBatteringRam, false},
		{AttackTypePitchfork, false},
		{AttackTypeClusterBomb, false},
		{AttackType("invalid"), true},
	}

	for _, tt := range tests {
		t.Run(string(tt.attackType), func(t *testing.T) {
			_, err := GetStrategy(tt.attackType)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetStrategy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
