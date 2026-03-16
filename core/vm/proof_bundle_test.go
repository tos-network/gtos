package vm

import (
	"bytes"
	"testing"

	"github.com/tos-network/gtos/crypto"
)

func makeInputHash(op string, inputs ...[]byte) [32]byte {
	tag, ok := opTagByName[op]
	if !ok {
		return [32]byte{}
	}
	var buf []byte
	buf = append(buf, tag)
	for _, inp := range inputs {
		buf = append(buf, inp...)
	}
	return crypto.Keccak256Hash(buf)
}

func TestProofBundleRoundTrip(t *testing.T) {
	a := make([]byte, 64)
	a[0] = 0x01
	b := make([]byte, 64)
	b[0] = 0x02
	result := make([]byte, 64)
	result[0] = 0x03
	proof := []byte("fake-proof")

	entries := []ProofEntry{
		{
			Op:         "mul",
			InputHash:  makeInputHash("mul", a, b),
			ResultData: result,
			Proof:      proof,
		},
		{
			Op:         "lt",
			InputHash:  makeInputHash("lt", a, b),
			ResultData: []byte{1},
			Proof:      []byte("lt-proof"),
		},
	}

	encoded := EncodeProofBundle(entries)
	data := append([]byte("calldata-prefix"), encoded...)

	pb, prefix := ExtractProofBundle(data)
	if pb == nil {
		t.Fatal("expected non-nil bundle")
	}
	if !bytes.Equal(prefix, []byte("calldata-prefix")) {
		t.Fatalf("prefix mismatch: %x", prefix)
	}

	// Consume first entry.
	e1, err := pb.Next("mul", a, b)
	if err != nil {
		t.Fatalf("Next(mul): %v", err)
	}
	if !bytes.Equal(e1.ResultData, result) {
		t.Errorf("result mismatch")
	}
	if !bytes.Equal(e1.Proof, proof) {
		t.Errorf("proof mismatch")
	}

	// Consume second entry.
	e2, err := pb.Next("lt", a, b)
	if err != nil {
		t.Fatalf("Next(lt): %v", err)
	}
	if !bytes.Equal(e2.ResultData, []byte{1}) {
		t.Errorf("lt result mismatch")
	}
}

func TestProofBundleEmpty(t *testing.T) {
	encoded := EncodeProofBundle(nil)
	data := append([]byte("prefix"), encoded...)
	pb, prefix := ExtractProofBundle(data)
	if pb == nil {
		t.Fatal("expected non-nil bundle for empty entries")
	}
	if !bytes.Equal(prefix, []byte("prefix")) {
		t.Errorf("prefix mismatch")
	}
	// Next should fail on empty bundle.
	_, err := pb.Next("mul")
	if err == nil {
		t.Error("expected error on empty bundle Next()")
	}
}

func TestProofBundleMalformed(t *testing.T) {
	// Just the magic + truncated count.
	data := append([]byte("prefix"), proofBundleMagic...)
	data = append(data, 0x00) // only 1 byte of count (need 2)
	pb, returned := ExtractProofBundle(data)
	if pb != nil {
		t.Error("expected nil bundle for malformed data")
	}
	if !bytes.Equal(returned, data) {
		t.Error("expected original data returned for malformed")
	}
}

func TestProofBundleNoMagic(t *testing.T) {
	data := []byte("no-magic-here")
	pb, returned := ExtractProofBundle(data)
	if pb != nil {
		t.Error("expected nil bundle when no magic present")
	}
	if !bytes.Equal(returned, data) {
		t.Error("expected original data returned")
	}
}

func TestProofBundleNextOpMismatch(t *testing.T) {
	a := make([]byte, 64)
	entries := []ProofEntry{
		{
			Op:         "mul",
			InputHash:  makeInputHash("mul", a),
			ResultData: make([]byte, 64),
			Proof:      []byte("p"),
		},
	}
	encoded := EncodeProofBundle(entries)
	pb, _ := ExtractProofBundle(encoded)
	if pb == nil {
		t.Fatal("expected non-nil bundle")
	}
	_, err := pb.Next("div", a) // wrong op
	if err == nil {
		t.Error("expected op mismatch error")
	}
}

func TestProofBundleNextInputHashMismatch(t *testing.T) {
	a := make([]byte, 64)
	b := make([]byte, 64)
	b[0] = 0xFF
	entries := []ProofEntry{
		{
			Op:         "mul",
			InputHash:  makeInputHash("mul", a), // hash for input a
			ResultData: make([]byte, 64),
			Proof:      []byte("p"),
		},
	}
	encoded := EncodeProofBundle(entries)
	pb, _ := ExtractProofBundle(encoded)
	if pb == nil {
		t.Fatal("expected non-nil bundle")
	}
	_, err := pb.Next("mul", b) // wrong input
	if err == nil {
		t.Error("expected input hash mismatch error")
	}
}

func TestProofBundleNextExhaustion(t *testing.T) {
	a := make([]byte, 64)
	entries := []ProofEntry{
		{
			Op:         "eq",
			InputHash:  makeInputHash("eq", a),
			ResultData: []byte{0},
			Proof:      []byte("p"),
		},
	}
	encoded := EncodeProofBundle(entries)
	pb, _ := ExtractProofBundle(encoded)
	if pb == nil {
		t.Fatal("expected non-nil bundle")
	}
	_, err := pb.Next("eq", a)
	if err != nil {
		t.Fatalf("first Next: %v", err)
	}
	_, err = pb.Next("eq", a)
	if err == nil {
		t.Error("expected exhaustion error on second Next()")
	}
}
