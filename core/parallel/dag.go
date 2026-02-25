package parallel

// BuildLevels assigns each transaction to an execution level such that
// all transactions within a level are guaranteed non-conflicting.
// The returned slice is ordered by level; each element is a slice of
// tx indices (into the original transaction slice).
//
// Algorithm is O(N²) which is fine for typical block sizes.
func BuildLevels(accessSets []AccessSet) [][]int {
	n := len(accessSets)
	if n == 0 {
		return nil
	}
	levels := make([]int, n)
	for i := 1; i < n; i++ {
		for j := 0; j < i; j++ {
			if accessSets[i].Conflicts(&accessSets[j]) {
				if levels[j]+1 > levels[i] {
					levels[i] = levels[j] + 1
				}
			}
		}
		// Preserve tx-index execution order across levels:
		// level indices must be non-decreasing so flatten(levels) follows tx order.
		if levels[i] < levels[i-1] {
			levels[i] = levels[i-1]
		}
	}

	// Find max level.
	maxLevel := 0
	for _, l := range levels {
		if l > maxLevel {
			maxLevel = l
		}
	}

	// Group tx indices by level.
	result := make([][]int, maxLevel+1)
	for i, l := range levels {
		result[l] = append(result[l], i)
	}
	return result
}
