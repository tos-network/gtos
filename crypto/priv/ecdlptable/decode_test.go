package ecdlptable

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tos-network/gtos/crypto/ristretto255"
)

// amountToPoint computes amount*G as a 32-byte compressed Ristretto255 point.
func amountToPoint(amount uint64) []byte {
	s := u64ToScalar(amount)
	P := ristretto255.NewIdentityElement().ScalarMult(s, ristretto255.NewGeneratorElement())
	return P.Bytes()
}

func TestGenerateAndDecode(t *testing.T) {
	const l1 = 13 // small table for fast tests
	tbl, err := Generate(l1, nil)
	if err != nil {
		t.Fatalf("Generate(l1=%d): %v", l1, err)
	}
	if tbl.L1() != l1 {
		t.Fatalf("L1() = %d, want %d", tbl.L1(), l1)
	}

	amounts := []uint64{0, 1, 2, 100, 1000, 4095, 4096, 4097, 8191, 8192, 8193}
	const maxAmount = uint64(100_000)

	for _, amount := range amounts {
		msgPoint := amountToPoint(amount)
		got, found, err := tbl.Decode(msgPoint, maxAmount)
		if err != nil {
			t.Errorf("Decode(%d): %v", amount, err)
			continue
		}
		if !found {
			t.Errorf("Decode(%d): not found within maxAmount=%d", amount, maxAmount)
			continue
		}
		if got != amount {
			t.Errorf("Decode(%d): got %d", amount, got)
		}
	}
}

func TestDecodeBoundaryValues(t *testing.T) {
	const l1 = 13
	tbl, err := Generate(l1, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Boundary values around 2^l1 and 2^(l1-1).
	step := uint64(1) << l1
	halfStep := uint64(1) << (l1 - 1)

	amounts := []uint64{
		halfStep - 1, halfStep, halfStep + 1,
		step - 1, step, step + 1,
		2*step - 1, 2 * step, 2*step + 1,
	}
	const maxAmount = uint64(200_000)

	for _, amount := range amounts {
		msgPoint := amountToPoint(amount)
		got, found, err := tbl.Decode(msgPoint, maxAmount)
		if err != nil {
			t.Errorf("Decode(%d): %v", amount, err)
			continue
		}
		if !found {
			t.Errorf("Decode(%d): not found", amount)
			continue
		}
		if got != amount {
			t.Errorf("Decode(%d): got %d", amount, got)
		}
	}
}

func TestDecodeExceedsMax(t *testing.T) {
	const l1 = 13
	tbl, err := Generate(l1, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	msgPoint := amountToPoint(50_000)
	_, found, err := tbl.Decode(msgPoint, 49_999)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if found {
		t.Fatal("expected found=false for amount > maxAmount")
	}
}

func TestDecodeBadInput(t *testing.T) {
	const l1 = 13
	tbl, err := Generate(l1, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	_, _, err = tbl.Decode(make([]byte, 31), 100)
	if err == nil {
		t.Fatal("expected error for 31-byte input")
	}
	_, _, err = tbl.Decode(make([]byte, 33), 100)
	if err == nil {
		t.Fatal("expected error for 33-byte input")
	}
}

func TestSaveAndLoad(t *testing.T) {
	const l1 = 13
	tbl, err := Generate(l1, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "test_table.bin")

	if err := tbl.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.L1() != l1 {
		t.Fatalf("loaded L1 = %d, want %d", loaded.L1(), l1)
	}

	// Verify loaded table decodes correctly.
	amounts := []uint64{0, 1, 42, 4096, 10_000, 50_000}
	const maxAmount = uint64(100_000)
	for _, amount := range amounts {
		msgPoint := amountToPoint(amount)
		got, found, err := loaded.Decode(msgPoint, maxAmount)
		if err != nil {
			t.Errorf("loaded.Decode(%d): %v", amount, err)
			continue
		}
		if !found {
			t.Errorf("loaded.Decode(%d): not found", amount)
			continue
		}
		if got != amount {
			t.Errorf("loaded.Decode(%d): got %d", amount, got)
		}
	}
}

func TestLoadBadFile(t *testing.T) {
	dir := t.TempDir()

	// Non-existent file.
	_, err := Load(filepath.Join(dir, "nonexistent"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}

	// Too short.
	short := filepath.Join(dir, "short.bin")
	os.WriteFile(short, []byte("BSGS"), 0600)
	_, err = Load(short)
	if err == nil {
		t.Fatal("expected error for truncated file")
	}

	// Bad magic.
	bad := filepath.Join(dir, "bad.bin")
	os.WriteFile(bad, make([]byte, 32), 0600)
	_, err = Load(bad)
	if err == nil {
		t.Fatal("expected error for bad magic")
	}
}

func TestGenerateProgress(t *testing.T) {
	var calls int
	_, err := Generate(10, func(pct float64) {
		calls++
		if pct < 0 || pct > 1 {
			t.Errorf("progress pct out of range: %f", pct)
		}
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if calls == 0 {
		t.Fatal("progress callback never called")
	}
}

func TestHashTableInsertLookup(t *testing.T) {
	ht := newHashTable(1000)

	// Insert known entries.
	for i := uint32(1); i <= 1000; i++ {
		if !ht.insert(i*7+13, i) {
			t.Fatalf("insert failed at i=%d", i)
		}
	}

	// Lookup should find them.
	for i := uint32(1); i <= 1000; i++ {
		v, ok := ht.lookup(i*7 + 13)
		if !ok {
			t.Fatalf("lookup failed for key=%d", i*7+13)
		}
		if v != i {
			t.Fatalf("lookup key=%d: got %d, want %d", i*7+13, v, i)
		}
	}

	// Lookup for absent keys.
	_, ok := ht.lookup(999999)
	if ok {
		t.Fatal("expected miss for absent key")
	}
}

func TestHashTableDuplicateKeys(t *testing.T) {
	ht := newHashTable(100)

	// Insert multiple entries with the same key.
	ht.insert(42, 10)
	ht.insert(42, 20)
	ht.insert(42, 30)

	results := ht.lookupAll(42)
	if len(results) != 3 {
		t.Fatalf("lookupAll returned %d results, want 3", len(results))
	}
	// Check all values present (order may vary).
	seen := map[uint32]bool{}
	for _, v := range results {
		seen[v] = true
	}
	for _, want := range []uint32{10, 20, 30} {
		if !seen[want] {
			t.Errorf("missing value %d in lookupAll results", want)
		}
	}
}

func TestGenerateBadL1(t *testing.T) {
	_, err := Generate(0, nil)
	if err == nil {
		t.Fatal("expected error for l1=0")
	}
	_, err = Generate(33, nil)
	if err == nil {
		t.Fatal("expected error for l1=33")
	}
}
