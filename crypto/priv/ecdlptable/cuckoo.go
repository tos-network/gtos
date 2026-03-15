package ecdlptable

import "encoding/binary"

// hashTable is an open-addressing hash table with linear probing,
// mapping truncated point fingerprints (uint32 from point bytes [4:8])
// to uint32 baby-step indices.
//
// Sentinel: key=0 marks empty slots.  Baby-step index 0 (identity
// point) is handled outside the table, so value=0 with key!=0 is valid.
//
// Multiple entries may share the same key (fingerprint collision).
// The caller must verify each candidate with a full point multiplication.
type hashTable struct {
	keys   []uint32
	values []uint32
	len    uint32
}

const (
	// ~1.3× overhead (same as plan spec).
	loadNum   = 10
	loadDenom = 13
)

// tableLen returns the slot count for n entries with ~1.3× overhead,
// rounded up to the next power of two for fast masking.
func tableLen(n uint32) uint32 {
	v := uint32(uint64(n) * loadDenom / loadNum)
	if v < 16 {
		v = 16
	}
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v++
	return v
}

// newHashTable allocates an empty table sized for n entries.
func newHashTable(n uint32) *hashTable {
	tl := tableLen(n)
	return &hashTable{
		keys:   make([]uint32, tl),
		values: make([]uint32, tl),
		len:    tl,
	}
}

// hashTableFromSlices wraps pre-existing key/value slices.
func hashTableFromSlices(keys, values []uint32) *hashTable {
	return &hashTable{
		keys:   keys,
		values: values,
		len:    uint32(len(keys)),
	}
}

// extractKey returns the fingerprint from point bytes [4:8].
func extractKey(pointBytes []byte) uint32 {
	return binary.LittleEndian.Uint32(pointBytes[4:8])
}

// mask for fast modulo (len is power of two).
func (ht *hashTable) mask() uint32 { return ht.len - 1 }

// hash computes the starting slot using a multiplicative hash.
func (ht *hashTable) hash(key uint32) uint32 {
	return (key * 2654435761) & ht.mask()
}

// insert adds key→value using linear probing. key must not be 0.
func (ht *hashTable) insert(key, value uint32) bool {
	pos := ht.hash(key)
	m := ht.mask()
	for i := uint32(0); i < ht.len; i++ {
		idx := (pos + i) & m
		if ht.keys[idx] == 0 {
			ht.keys[idx] = key
			ht.values[idx] = value
			return true
		}
	}
	return false
}

// lookupAll returns all values matching key.  Because fingerprints
// are truncated, multiple baby-step indices may share the same key.
func (ht *hashTable) lookupAll(key uint32) []uint32 {
	var results []uint32
	pos := ht.hash(key)
	m := ht.mask()
	for i := uint32(0); i < ht.len; i++ {
		idx := (pos + i) & m
		if ht.keys[idx] == 0 {
			break
		}
		if ht.keys[idx] == key {
			results = append(results, ht.values[idx])
		}
	}
	return results
}

// lookup returns the first value matching key.
func (ht *hashTable) lookup(key uint32) (uint32, bool) {
	pos := ht.hash(key)
	m := ht.mask()
	for i := uint32(0); i < ht.len; i++ {
		idx := (pos + i) & m
		if ht.keys[idx] == 0 {
			return 0, false
		}
		if ht.keys[idx] == key {
			return ht.values[idx], true
		}
	}
	return 0, false
}
