package blitz

import (
	"fmt"
)

// AttackJob represents a single fuzzing task with position-payload mapping.
type AttackJob struct {
	PayloadMap   map[int]string // Maps position index to payload
	PrimaryPos   int            // Primary position being fuzzed (for Sniper)
	PrimaryValue string         // Primary payload value (for Sniper)
}

// AttackStrategy generates jobs based on the attack type.
type AttackStrategy interface {
	GenerateJobs(positions []Position, payloadSets [][]string) ([]AttackJob, error)
}

// SniperStrategy implements the Sniper attack type.
// Targets one position at a time with each payload.
type SniperStrategy struct{}

func (s *SniperStrategy) GenerateJobs(positions []Position, payloadSets [][]string) ([]AttackJob, error) {
	if len(payloadSets) == 0 {
		return nil, fmt.Errorf("sniper attack requires at least one payload set")
	}

	// Use the first payload set for all positions
	payloads := payloadSets[0]
	var jobs []AttackJob

	// For each position
	for _, pos := range positions {
		// For each payload
		for _, payload := range payloads {
			job := AttackJob{
				PayloadMap:   map[int]string{pos.Index: payload},
				PrimaryPos:   pos.Index,
				PrimaryValue: payload,
			}
			jobs = append(jobs, job)
		}
	}

	return jobs, nil
}

// BatteringRamStrategy implements the Battering Ram attack type.
// Uses the same payload across all positions simultaneously.
type BatteringRamStrategy struct{}

func (s *BatteringRamStrategy) GenerateJobs(positions []Position, payloadSets [][]string) ([]AttackJob, error) {
	if len(payloadSets) == 0 {
		return nil, fmt.Errorf("battering-ram attack requires at least one payload set")
	}

	// Use the first payload set
	payloads := payloadSets[0]
	var jobs []AttackJob

	// For each payload, apply it to all positions
	for _, payload := range payloads {
		payloadMap := make(map[int]string, len(positions))
		for _, pos := range positions {
			payloadMap[pos.Index] = payload
		}

		job := AttackJob{
			PayloadMap:   payloadMap,
			PrimaryPos:   0, // All positions are equal in battering ram
			PrimaryValue: payload,
		}
		jobs = append(jobs, job)
	}

	return jobs, nil
}

// PitchforkStrategy implements the Pitchfork attack type.
// Pairs payloads from multiple lists, advancing through them in parallel.
type PitchforkStrategy struct{}

func (s *PitchforkStrategy) GenerateJobs(positions []Position, payloadSets [][]string) ([]AttackJob, error) {
	if len(positions) == 0 {
		return nil, fmt.Errorf("pitchfork attack requires at least one position")
	}

	// If only one payload set provided, use it for all positions
	if len(payloadSets) == 1 {
		payloadSets = make([][]string, len(positions))
		for i := range positions {
			payloadSets[i] = payloadSets[0]
		}
	}

	// Ensure we have a payload set for each position
	if len(payloadSets) != len(positions) {
		return nil, fmt.Errorf("pitchfork attack requires one payload set per position (got %d sets for %d positions)", len(payloadSets), len(positions))
	}

	// Find the minimum payload set size (determines number of iterations)
	minSize := len(payloadSets[0])
	for _, set := range payloadSets[1:] {
		if len(set) < minSize {
			minSize = len(set)
		}
	}

	if minSize == 0 {
		return nil, fmt.Errorf("pitchfork attack requires non-empty payload sets")
	}

	var jobs []AttackJob

	// Generate jobs by iterating through payloads in parallel
	for i := 0; i < minSize; i++ {
		payloadMap := make(map[int]string, len(positions))
		for posIdx, pos := range positions {
			payloadMap[pos.Index] = payloadSets[posIdx][i]
		}

		job := AttackJob{
			PayloadMap:   payloadMap,
			PrimaryPos:   0,
			PrimaryValue: payloadSets[0][i], // Use first set as primary reference
		}
		jobs = append(jobs, job)
	}

	return jobs, nil
}

// ClusterBombStrategy implements the Cluster Bomb attack type.
// Generates all possible combinations of payloads across positions.
type ClusterBombStrategy struct{}

func (s *ClusterBombStrategy) GenerateJobs(positions []Position, payloadSets [][]string) ([]AttackJob, error) {
	if len(positions) == 0 {
		return nil, fmt.Errorf("cluster-bomb attack requires at least one position")
	}

	// If only one payload set provided, use it for all positions
	if len(payloadSets) == 1 {
		originalSet := payloadSets[0]
		payloadSets = make([][]string, len(positions))
		for i := range positions {
			payloadSets[i] = originalSet
		}
	}

	// Ensure we have a payload set for each position
	if len(payloadSets) != len(positions) {
		return nil, fmt.Errorf("cluster-bomb attack requires one payload set per position (got %d sets for %d positions)", len(payloadSets), len(positions))
	}

	// Check for empty sets
	for i, set := range payloadSets {
		if len(set) == 0 {
			return nil, fmt.Errorf("payload set %d is empty", i)
		}
	}

	var jobs []AttackJob

	// Generate cartesian product of all payload sets
	generateCombinations(positions, payloadSets, 0, make(map[int]string), &jobs)

	return jobs, nil
}

// generateCombinations recursively generates all payload combinations.
func generateCombinations(positions []Position, payloadSets [][]string, posIdx int, current map[int]string, jobs *[]AttackJob) {
	if posIdx >= len(positions) {
		// Copy the current mapping
		payloadMap := make(map[int]string, len(current))
		for k, v := range current {
			payloadMap[k] = v
		}

		job := AttackJob{
			PayloadMap:   payloadMap,
			PrimaryPos:   0,
			PrimaryValue: payloadMap[0],
		}
		*jobs = append(*jobs, job)
		return
	}

	pos := positions[posIdx]
	for _, payload := range payloadSets[posIdx] {
		current[pos.Index] = payload
		generateCombinations(positions, payloadSets, posIdx+1, current, jobs)
	}
}

// GetStrategy returns the appropriate attack strategy for the given type.
func GetStrategy(attackType AttackType) (AttackStrategy, error) {
	switch attackType {
	case AttackTypeSniper:
		return &SniperStrategy{}, nil
	case AttackTypeBatteringRam:
		return &BatteringRamStrategy{}, nil
	case AttackTypePitchfork:
		return &PitchforkStrategy{}, nil
	case AttackTypeClusterBomb:
		return &ClusterBombStrategy{}, nil
	default:
		return nil, fmt.Errorf("unknown attack type: %s", attackType)
	}
}
