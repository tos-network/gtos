// Package ecdlptable provides precomputed Baby-Step Giant-Step (BSGS) lookup
// tables for solving the Elliptic Curve Discrete Logarithm Problem on
// Ristretto255.  Tables are generated once, persisted to disk, and loaded at
// runtime to decrypt Twisted ElGamal balances without rebuilding the baby-step
// map on every query.
//
// The table stores { i*G → i } for i ∈ [1, 2^(L1-1)] in a hash table with
// a negation trick so the effective search range per giant step is [0, 2^L1].
package ecdlptable

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/tos-network/gtos/crypto/ristretto255"
)

const (
	// L1Medium gives ~2 M baby entries (~21 MB table).
	L1Medium uint = 22
	// L1High gives ~33 M baby entries (~350 MB table).
	L1High uint = 26

	fileMagic   = "BSGS"
	fileVersion = uint32(1)
	headerSize  = 32
)

// Table is a precomputed BSGS baby-step lookup table.
type Table struct {
	l1        uint
	babyCount uint32 // 2^(l1-1)
	ht        *hashTable
	stepPoint *ristretto255.Element // 2^l1 * G, cached for giant steps
}

// L1 returns the table's L1 parameter.
func (t *Table) L1() uint { return t.l1 }

// Generate builds a new table with 2^(l1-1) baby-step entries.
// progress is called with a value in [0,1] periodically.
// l1 must be in [1, 32].
func Generate(l1 uint, progress func(pct float64)) (*Table, error) {
	if l1 == 0 || l1 > 32 {
		return nil, errors.New("ecdlptable: l1 must be in [1, 32]")
	}
	babyCount := uint32(1) << (l1 - 1)

	ht := newHashTable(babyCount)

	G := ristretto255.NewGeneratorElement()
	current := ristretto255.NewIdentityElement()

	pctStep := uint32(1)
	if babyCount > 100 {
		pctStep = babyCount / 100
	}
	for i := uint32(1); i <= babyCount; i++ {
		current = ristretto255.NewIdentityElement().Add(current, G)
		encoded := current.Bytes()
		key := extractKey(encoded)
		if key == 0 {
			// Remap zero-key to avoid sentinel collision.
			// This is extremely rare; store with key=1 and let
			// verification reject false positives.
			key = 1
		}
		if !ht.insert(key, i) {
			return nil, fmt.Errorf("ecdlptable: hash insert failed at i=%d", i)
		}
		if progress != nil && i%pctStep == 0 {
			progress(float64(i) / float64(babyCount))
		}
	}

	stepPoint := computeStepPoint(l1)

	if progress != nil {
		progress(1.0)
	}

	return &Table{
		l1:        l1,
		babyCount: babyCount,
		ht:        ht,
		stepPoint: stepPoint,
	}, nil
}

// computeStepPoint returns 2^l1 * G using repeated doubling.
func computeStepPoint(l1 uint) *ristretto255.Element {
	p := ristretto255.NewGeneratorElement()
	for i := uint(0); i < l1; i++ {
		p = ristretto255.NewIdentityElement().Add(p, p)
	}
	return p
}

// Save writes the table to a binary file.
//
// Format:
//
//	[0:4]   magic "BSGS"
//	[4:8]   version (1)
//	[8:12]  L1 (uint32)
//	[12:16] table_len (uint32)
//	[16:32] reserved
//	[32 .. 32 + 4*table_len]                   keys   ([]uint32 LE)
//	[32 + 4*table_len .. 32 + 8*table_len]     values ([]uint32 LE)
func (t *Table) Save(path string) error {
	tl := t.ht.len

	hdr := make([]byte, headerSize)
	copy(hdr[0:4], fileMagic)
	binary.LittleEndian.PutUint32(hdr[4:8], fileVersion)
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(t.l1))
	binary.LittleEndian.PutUint32(hdr[12:16], tl)

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("ecdlptable: create %s: %w", path, err)
	}
	defer f.Close()

	if _, err := f.Write(hdr); err != nil {
		return fmt.Errorf("ecdlptable: write header: %w", err)
	}

	buf := make([]byte, 4)
	for _, v := range t.ht.keys {
		binary.LittleEndian.PutUint32(buf, v)
		if _, err := f.Write(buf); err != nil {
			return fmt.Errorf("ecdlptable: write keys: %w", err)
		}
	}
	for _, v := range t.ht.values {
		binary.LittleEndian.PutUint32(buf, v)
		if _, err := f.Write(buf); err != nil {
			return fmt.Errorf("ecdlptable: write values: %w", err)
		}
	}

	return f.Sync()
}

// Load reads a precomputed table from a binary file.
func Load(path string) (*Table, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ecdlptable: read %s: %w", path, err)
	}

	if len(data) < headerSize {
		return nil, errors.New("ecdlptable: file too short for header")
	}
	if string(data[0:4]) != fileMagic {
		return nil, errors.New("ecdlptable: bad magic")
	}
	ver := binary.LittleEndian.Uint32(data[4:8])
	if ver != fileVersion {
		return nil, fmt.Errorf("ecdlptable: unsupported version %d", ver)
	}
	l1 := binary.LittleEndian.Uint32(data[8:12])
	tl := binary.LittleEndian.Uint32(data[12:16])

	if l1 == 0 || l1 > 32 {
		return nil, fmt.Errorf("ecdlptable: invalid L1=%d", l1)
	}
	expectedSize := int64(headerSize) + int64(tl)*8
	if int64(len(data)) < expectedSize {
		return nil, fmt.Errorf("ecdlptable: file truncated: have %d, want %d", len(data), expectedSize)
	}

	keys := make([]uint32, tl)
	values := make([]uint32, tl)
	off := headerSize
	for i := uint32(0); i < tl; i++ {
		keys[i] = binary.LittleEndian.Uint32(data[off : off+4])
		off += 4
	}
	for i := uint32(0); i < tl; i++ {
		values[i] = binary.LittleEndian.Uint32(data[off : off+4])
		off += 4
	}

	return &Table{
		l1:        uint(l1),
		babyCount: 1 << (l1 - 1),
		ht:        hashTableFromSlices(keys, values),
		stepPoint: computeStepPoint(uint(l1)),
	}, nil
}
