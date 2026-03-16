package vm

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/tos-network/gtos/crypto"
)

// Op tag constants for binary encoding.
const (
	opTagMul            uint8 = 1
	opTagDiv            uint8 = 2
	opTagRem            uint8 = 3
	opTagLt             uint8 = 4
	opTagGt             uint8 = 5
	opTagEq             uint8 = 6
	opTagMin            uint8 = 7
	opTagMax            uint8 = 8
	opTagSelect         uint8 = 9
	opTagVerifyTransfer uint8 = 10
	opTagVerifyEq       uint8 = 11
)

var opTagByName = map[string]uint8{
	"mul":             opTagMul,
	"div":             opTagDiv,
	"rem":             opTagRem,
	"lt":              opTagLt,
	"gt":              opTagGt,
	"eq":              opTagEq,
	"min":             opTagMin,
	"max":             opTagMax,
	"select":          opTagSelect,
	"verify_transfer": opTagVerifyTransfer,
	"verify_eq":       opTagVerifyEq,
}

var opNameByTag = map[uint8]string{
	opTagMul:            "mul",
	opTagDiv:            "div",
	opTagRem:            "rem",
	opTagLt:             "lt",
	opTagGt:             "gt",
	opTagEq:             "eq",
	opTagMin:            "min",
	opTagMax:            "max",
	opTagSelect:         "select",
	opTagVerifyTransfer: "verify_transfer",
	opTagVerifyEq:       "verify_eq",
}

// proofBundleMagic is the 4-byte marker "PBND" separating ABI calldata from
// the appended proof bundle.
var proofBundleMagic = []byte{0x50, 0x42, 0x4E, 0x44}

// ProofEntry holds one pre-computed ZK proof for a ciphertext operation.
type ProofEntry struct {
	Op         string // "mul","div","rem","lt","gt","eq","min","max","select","verify_transfer","verify_eq"
	InputHash  [32]byte
	ResultData []byte // 64B ciphertext or 1B bool
	Proof      []byte // ZK proof bytes
}

// ProofBundle is an ordered sequence of ProofEntry values consumed one at a
// time by Tier-2 ciphertext operations.
type ProofBundle struct {
	entries []ProofEntry
	cursor  int
}

// Next returns the next proof entry, verifying that the operation tag and
// input hash match the expected values.
func (pb *ProofBundle) Next(op string, inputs ...[]byte) (*ProofEntry, error) {
	if pb.cursor >= len(pb.entries) {
		return nil, errors.New("proof bundle exhausted")
	}
	entry := &pb.entries[pb.cursor]
	if entry.Op != op {
		return nil, fmt.Errorf("proof bundle op mismatch: want %q, got %q", op, entry.Op)
	}

	// Compute expected InputHash = keccak256(op_bytes || inputs...).
	tag, ok := opTagByName[op]
	if !ok {
		return nil, fmt.Errorf("unknown proof bundle op %q", op)
	}
	var hashInput []byte
	hashInput = append(hashInput, tag)
	for _, inp := range inputs {
		hashInput = append(hashInput, inp...)
	}
	expected := crypto.Keccak256Hash(hashInput)
	if entry.InputHash != expected {
		return nil, fmt.Errorf("proof bundle input hash mismatch for op %q", op)
	}

	pb.cursor++
	return entry, nil
}

// EncodeProofBundle serialises a slice of ProofEntry values into the binary
// wire format: [magic 4B] [count u16 BE] [entries...].
func EncodeProofBundle(entries []ProofEntry) []byte {
	var buf []byte
	buf = append(buf, proofBundleMagic...)
	var countBuf [2]byte
	binary.BigEndian.PutUint16(countBuf[:], uint16(len(entries)))
	buf = append(buf, countBuf[:]...)

	for _, e := range entries {
		tag, ok := opTagByName[e.Op]
		if !ok {
			tag = 0
		}
		buf = append(buf, tag)
		buf = append(buf, e.InputHash[:]...)

		var rlenBuf [2]byte
		binary.BigEndian.PutUint16(rlenBuf[:], uint16(len(e.ResultData)))
		buf = append(buf, rlenBuf[:]...)
		buf = append(buf, e.ResultData...)

		var plenBuf [2]byte
		binary.BigEndian.PutUint16(plenBuf[:], uint16(len(e.Proof)))
		buf = append(buf, plenBuf[:]...)
		buf = append(buf, e.Proof...)
	}
	return buf
}

// ExtractProofBundle scans data for the "PBND" magic marker. If found, it
// decodes the trailing proof bundle and returns (bundle, data_before_magic).
// If not found, it returns (nil, original_data).
func ExtractProofBundle(data []byte) (*ProofBundle, []byte) {
	// Scan backwards for the magic bytes.
	idx := -1
	for i := len(data) - 4; i >= 0; i-- {
		if data[i] == proofBundleMagic[0] &&
			data[i+1] == proofBundleMagic[1] &&
			data[i+2] == proofBundleMagic[2] &&
			data[i+3] == proofBundleMagic[3] {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, data
	}

	bundleData := data[idx+4:] // after magic
	prefix := data[:idx]

	if len(bundleData) < 2 {
		return nil, data
	}
	count := int(binary.BigEndian.Uint16(bundleData[:2]))
	pos := 2
	entries := make([]ProofEntry, 0, count)

	for i := 0; i < count; i++ {
		if pos >= len(bundleData) {
			return nil, data // malformed
		}
		tag := bundleData[pos]
		pos++

		if pos+32 > len(bundleData) {
			return nil, data
		}
		var inputHash [32]byte
		copy(inputHash[:], bundleData[pos:pos+32])
		pos += 32

		if pos+2 > len(bundleData) {
			return nil, data
		}
		rlen := int(binary.BigEndian.Uint16(bundleData[pos : pos+2]))
		pos += 2
		if pos+rlen > len(bundleData) {
			return nil, data
		}
		resultData := make([]byte, rlen)
		copy(resultData, bundleData[pos:pos+rlen])
		pos += rlen

		if pos+2 > len(bundleData) {
			return nil, data
		}
		plen := int(binary.BigEndian.Uint16(bundleData[pos : pos+2]))
		pos += 2
		if pos+plen > len(bundleData) {
			return nil, data
		}
		proof := make([]byte, plen)
		copy(proof, bundleData[pos:pos+plen])
		pos += plen

		opName, ok := opNameByTag[tag]
		if !ok {
			opName = fmt.Sprintf("unknown_%d", tag)
		}

		entries = append(entries, ProofEntry{
			Op:         opName,
			InputHash:  inputHash,
			ResultData: resultData,
			Proof:      proof,
		})
	}

	return &ProofBundle{entries: entries}, prefix
}
