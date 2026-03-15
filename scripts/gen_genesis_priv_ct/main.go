//go:build cgo && ed25519c

// gen_genesis_priv_ct generates the priv_commitment, priv_handle, priv_version,
// and priv_nonce values needed to pre-seed a PrivAccount ciphertext in the
// genesis alloc.
//
// Usage:
//
//	go run -tags cgo,ed25519c ./scripts/gen_genesis_priv_ct/main.go <pubkey-hex> <amount>
//
// Arguments:
//
//	pubkey-hex   32-byte ElGamal public key as hex (with or without 0x prefix)
//	amount       initial Priv balance in TOS units (e.g. 100 means 100 TOS)
//
// Output:
//
//	JSON fragment ready to merge into the genesis alloc entry for the account,
//	plus the ElGamal public key and derived address.
//
// Example:
//
//	go run -tags cgo,ed25519c ./scripts/gen_genesis_priv_ct/main.go \
//	  8cf9d0e10b0ec9a16b87b2d6c284c637fb6f8fceb93bcf112d4fcd4a055b4705 100
//
//	{
//	  "address": "0x...",
//	  "elgamal_pubkey": "0x...",
//	  "priv_commitment": "0x...",
//	  "priv_handle": "0x...",
//	  "priv_nonce": 0,
//	  "priv_version": 0
//	}
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	cryptouno "github.com/tos-network/gtos/crypto/uno"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <pubkey-hex> <amount>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  pubkey-hex  32-byte ElGamal public key (hex, with or without 0x)\n")
		fmt.Fprintf(os.Stderr, "  amount      Priv balance in TOS units (integer)\n")
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

	// Derive Ethereum-style address from ElGamal pubkey: Keccak256(pubkey)[:20]
	addr := common.BytesToAddress(crypto.Keccak256(pub32))

	out := map[string]interface{}{
		"address":         addr.Hex(),
		"elgamal_pubkey":  "0x" + hex.EncodeToString(pub32),
		"priv_commitment": "0x" + hex.EncodeToString(ct64[:32]),
		"priv_handle":     "0x" + hex.EncodeToString(ct64[32:]),
		"priv_version":    0,
		"priv_nonce":      0,
	}
	enc, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(enc))
}
