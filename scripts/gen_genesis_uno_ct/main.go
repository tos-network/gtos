//go:build cgo && ed25519c

// gen_genesis_uno_ct generates the uno_ct_commitment and uno_ct_handle values
// needed to pre-seed a UNO ciphertext in the genesis alloc.
//
// Usage:
//
//	go run -tags cgo,ed25519c ./scripts/gen_genesis_uno_ct/main.go <pubkey-hex> <amount>
//
// Arguments:
//
//	pubkey-hex   32-byte ElGamal public key as hex (with or without 0x prefix)
//	amount       initial UNO balance in TOS units (e.g. 100 means 100 TOS)
//
// Output:
//
//	JSON fragment ready to merge into the genesis alloc entry for the account.
//
// Example:
//
//	go run -tags cgo,ed25519c ./scripts/gen_genesis_uno_ct/main.go \
//	  8cf9d0e10b0ec9a16b87b2d6c284c637fb6f8fceb93bcf112d4fcd4a055b4705 100
//
//	{
//	  "uno_ct_commitment": "0x...",
//	  "uno_ct_handle":     "0x...",
//	  "uno_version":       0
//	}
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	cryptouno "github.com/tos-network/gtos/crypto/uno"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <pubkey-hex> <amount>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  pubkey-hex  32-byte ElGamal public key (hex, with or without 0x)\n")
		fmt.Fprintf(os.Stderr, "  amount      UNO balance in TOS units (integer)\n")
		os.Exit(1)
	}

	pubHex := strings.TrimPrefix(os.Args[1], "0x")
	pub32, err := hex.DecodeString(pubHex)
	if err != nil || len(pub32) != 32 {
		fmt.Fprintf(os.Stderr, "error: pubkey must be exactly 32 bytes hex (got %d bytes)\n", len(pub32))
		os.Exit(1)
	}

	amount, err := strconv.ParseUint(os.Args[2], 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: amount must be a non-negative integer: %v\n", err)
		os.Exit(1)
	}

	ct64, err := cryptouno.Encrypt(pub32, amount)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: Encrypt failed: %v\n", err)
		os.Exit(1)
	}
	if len(ct64) != 64 {
		fmt.Fprintf(os.Stderr, "error: unexpected ciphertext length %d (want 64)\n", len(ct64))
		os.Exit(1)
	}

	out := map[string]interface{}{
		"uno_ct_commitment": "0x" + hex.EncodeToString(ct64[:32]),
		"uno_ct_handle":     "0x" + hex.EncodeToString(ct64[32:]),
		"uno_version":       0,
	}
	enc, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(enc))
}
