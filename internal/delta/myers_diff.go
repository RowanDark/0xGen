package delta

// myersDiff implements the Myers diff algorithm for computing differences
// between two sequences. This is a simplified implementation optimized for
// readability and correctness.
//
// Reference: "An O(ND) Difference Algorithm and Its Variations" by Eugene W. Myers
func myersDiff(left, right []string) []Change {
	n := len(left)
	m := len(right)

	// Handle edge cases
	if n == 0 && m == 0 {
		return []Change{}
	}
	if n == 0 {
		changes := make([]Change, m)
		for i, line := range right {
			changes[i] = Change{
				Type:       ChangeTypeAdded,
				NewValue:   line,
				LineNumber: i + 1, // +1 for 1-based line numbers
			}
		}
		return changes
	}
	if m == 0 {
		changes := make([]Change, n)
		for i, line := range left {
			changes[i] = Change{
				Type:       ChangeTypeRemoved,
				OldValue:   line,
				LineNumber: i + 1, // +1 for 1-based line numbers
			}
		}
		return changes
	}

	// Use dynamic programming to find the shortest edit script
	max := n + m
	v := make(map[int]int)
	trace := []map[int]int{}

	// Find the shortest path
	for d := 0; d <= max; d++ {
		// Save current state
		vCopy := make(map[int]int)
		for k, val := range v {
			vCopy[k] = val
		}
		trace = append(trace, vCopy)

		for k := -d; k <= d; k += 2 {
			var x int

			// Determine whether to move down or right
			if k == -d || (k != d && v[k-1] < v[k+1]) {
				x = v[k+1]
			} else {
				x = v[k-1] + 1
			}

			y := x - k

			// Follow diagonal matches
			for x < n && y < m && left[x] == right[y] {
				x++
				y++
			}

			v[k] = x

			// Check if we've reached the end
			if x >= n && y >= m {
				// Backtrack to construct the diff
				return backtrack(left, right, trace, n, m)
			}
		}
	}

	// Shouldn't reach here, but return all as changed if we do
	changes := make([]Change, 0, n+m)
	for i, line := range left {
		changes = append(changes, Change{
			Type:       ChangeTypeRemoved,
			OldValue:   line,
			LineNumber: i + 1, // +1 for 1-based line numbers
		})
	}
	for i, line := range right {
		changes = append(changes, Change{
			Type:       ChangeTypeAdded,
			NewValue:   line,
			LineNumber: i + 1, // +1 for 1-based line numbers
		})
	}
	return changes
}

// backtrack reconstructs the diff from the Myers algorithm trace
func backtrack(left, right []string, trace []map[int]int, n, m int) []Change {
	var changes []Change
	x, y := n, m

	for d := len(trace) - 1; d >= 0; d-- {
		v := trace[d]
		k := x - y

		var prevK int
		if k == -d || (k != d && v[k-1] < v[k+1]) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}

		prevX := v[prevK]
		prevY := prevX - prevK

		// Follow diagonals (matches)
		for x > prevX && y > prevY {
			x--
			y--
			// This is a match, no change needed
		}

		if d > 0 {
			// Record the change
			if x == prevX {
				// Insertion
				y--
				changes = append([]Change{{
					Type:       ChangeTypeAdded,
					NewValue:   right[y],
					LineNumber: y + 1, // +1 for 1-based line numbers
				}}, changes...)
			} else {
				// Deletion
				x--
				changes = append([]Change{{
					Type:       ChangeTypeRemoved,
					OldValue:   left[x],
					LineNumber: x + 1, // +1 for 1-based line numbers
				}}, changes...)
			}
		}
	}

	return changes
}

// longestCommonSubsequence computes the LCS for similarity calculation
func longestCommonSubsequence(left, right []string) int {
	n := len(left)
	m := len(right)

	if n == 0 || m == 0 {
		return 0
	}

	// Create DP table
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}

	// Fill DP table
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if left[i-1] == right[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				dp[i][j] = max(dp[i-1][j], dp[i][j-1])
			}
		}
	}

	return dp[n][m]
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
