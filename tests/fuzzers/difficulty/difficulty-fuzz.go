// Package difficulty contained a fuzzer for the PoW difficulty adjustment
// algorithm. It is a no-op stub since DPoS does not use PoW difficulty.
package difficulty

// Fuzz is a no-op stub (DPoS has no difficulty adjustment).
func Fuzz(data []byte) int {
	return 0
}
