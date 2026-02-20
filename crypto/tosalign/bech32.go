package tosalign

import (
	"fmt"
	"strings"
)

const (
	bech32Charset   = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	bech32Separator = '1'
)

var bech32Generator = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i, g := range bech32Generator {
			if ((top >> uint(i)) & 1) == 1 {
				chk ^= g
			}
		}
	}
	return chk
}

func bech32HrpExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func verifyBech32Checksum(hrp string, data []byte) bool {
	vals := bech32HrpExpand(hrp)
	vals = append(vals, data...)
	return bech32Polymod(vals) == 1
}

func createBech32Checksum(hrp string, data []byte) [6]byte {
	vals := bech32HrpExpand(hrp)
	vals = append(vals, data...)
	vals = append(vals, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(vals) ^ 1

	var out [6]byte
	for i := 0; i < 6; i++ {
		out[i] = byte((polymod >> uint(5*(5-i))) & 31)
	}
	return out
}

// ConvertBits mirrors tos/common/src/crypto/bech32.rs convert_bits behavior.
func ConvertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	var acc uint
	var bits uint
	maxValue := (uint(1) << to) - 1
	out := make([]byte, 0, len(data))

	for _, v := range data {
		value := uint(v)
		if value>>from != 0 {
			return nil, fmt.Errorf("invalid data range: %d (max bits %d)", value, from)
		}
		acc = (acc << from) | value
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte((acc>>bits)&maxValue))
		}
	}

	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(to-bits))&maxValue))
		}
	} else if bits >= from {
		return nil, fmt.Errorf("illegal zero padding")
	} else if ((acc << (to - bits)) & maxValue) != 0 {
		return nil, fmt.Errorf("non-zero padding")
	}

	return out, nil
}

func Bech32Encode(hrp string, data []byte) (string, error) {
	if len(hrp) == 0 {
		return "", fmt.Errorf("human readable part is empty")
	}
	for i := 0; i < len(hrp); i++ {
		c := hrp[i]
		if c < 33 || c > 126 {
			return "", fmt.Errorf("invalid HRP character: %d", c)
		}
	}
	if strings.ToUpper(hrp) != hrp && strings.ToLower(hrp) != hrp {
		return "", fmt.Errorf("mix case is not allowed in HRP")
	}

	hrp = strings.ToLower(hrp)
	combined := make([]byte, 0, len(data)+6)
	combined = append(combined, data...)
	checksum := createBech32Checksum(hrp, data)
	combined = append(combined, checksum[:]...)

	var b strings.Builder
	b.Grow(len(hrp) + 1 + len(combined))
	b.WriteString(hrp)
	b.WriteByte(bech32Separator)
	for _, v := range combined {
		if int(v) >= len(bech32Charset) {
			return "", fmt.Errorf("invalid value: %d", v)
		}
		b.WriteByte(bech32Charset[v])
	}
	return b.String(), nil
}

func Bech32Decode(bech string) (string, []byte, error) {
	if strings.ToUpper(bech) != bech && strings.ToLower(bech) != bech {
		return "", nil, fmt.Errorf("mix case is not allowed")
	}

	pos := strings.LastIndexByte(bech, bech32Separator)
	if pos < 0 {
		return "", nil, fmt.Errorf("separator not found")
	}
	if pos < 1 || pos+7 > len(bech) {
		return "", nil, fmt.Errorf("invalid separator position: %d", pos)
	}

	hrp := bech[:pos]
	for i := 0; i < len(hrp); i++ {
		c := hrp[i]
		if c < 33 || c > 126 {
			return "", nil, fmt.Errorf("invalid HRP character: %d", c)
		}
	}

	data := make([]byte, 0, len(bech)-pos-1)
	for i := pos + 1; i < len(bech); i++ {
		idx := strings.IndexByte(bech32Charset, bech[i])
		if idx < 0 {
			return "", nil, fmt.Errorf("invalid bech32 character: %q", bech[i])
		}
		data = append(data, byte(idx))
	}

	if !verifyBech32Checksum(hrp, data) {
		return "", nil, fmt.Errorf("invalid checksum")
	}

	return hrp, data[:len(data)-6], nil
}
