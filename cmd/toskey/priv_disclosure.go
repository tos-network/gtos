package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	corepriv "github.com/tos-network/gtos/core/priv"
	"github.com/urfave/cli/v2"
)

type outputPrivDisclosure struct {
	Pubkey      string `json:"pubkey"`
	Commitment  string `json:"commitment"`
	Handle      string `json:"handle"`
	Amount      uint64 `json:"amount"`
	Proof       string `json:"proof"`
	ChainID     uint64 `json:"chainId"`
	BlockNumber uint64 `json:"blockNumber"`
}

var commandPrivDisclose = &cli.Command{
	Name:  "priv-disclose",
	Usage: "Generate a selective disclosure proof for an encrypted balance",
	Description: `
Generates a DLEQ disclosure proof that proves the encrypted balance of the
given account is exactly the specified amount, without revealing the private key.

The proof can be verified by any third party who knows the public key and
on-chain ciphertext.`,
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "privkey", Usage: "hex-encoded 32-byte ElGamal private key", Required: true},
		&cli.StringFlag{Name: "pubkey", Usage: "hex-encoded 32-byte ElGamal public key", Required: true},
		&cli.StringFlag{Name: "ct", Usage: "hex-encoded 64-byte ciphertext (commitment||handle)", Required: true},
		&cli.Uint64Flag{Name: "amount", Usage: "plaintext balance amount in UNO base units", Required: true},
		&cli.Uint64Flag{Name: "chain-id", Usage: "chain ID for replay protection", Value: 1},
		&cli.Uint64Flag{Name: "block", Usage: "block number for freshness binding", Value: 0},
	},
	Action: actionPrivDisclose,
}

func actionPrivDisclose(ctx *cli.Context) error {
	privkey, err := decodeHexFixed(ctx.String("privkey"), 32, "privkey")
	if err != nil {
		return err
	}
	pubkey, err := decodeHexFixed(ctx.String("pubkey"), 32, "pubkey")
	if err != nil {
		return err
	}
	ctBytes, err := decodeHexFixed(ctx.String("ct"), 64, "ciphertext")
	if err != nil {
		return err
	}

	amount := ctx.Uint64("amount")
	chainID := new(big.Int).SetUint64(ctx.Uint64("chain-id"))
	blockNum := ctx.Uint64("block")

	var privkey32, pubkey32 [32]byte
	copy(privkey32[:], privkey)
	copy(pubkey32[:], pubkey)

	var ct corepriv.Ciphertext
	copy(ct.Commitment[:], ctBytes[:32])
	copy(ct.Handle[:], ctBytes[32:])

	proof, err := corepriv.ProveDisclosure(privkey32, pubkey32, ct, amount, chainID, blockNum)
	if err != nil {
		return fmt.Errorf("disclosure proof generation failed: %w", err)
	}

	out := outputPrivDisclosure{
		Pubkey:      hex.EncodeToString(pubkey),
		Commitment:  hex.EncodeToString(ct.Commitment[:]),
		Handle:      hex.EncodeToString(ct.Handle[:]),
		Amount:      amount,
		Proof:       hex.EncodeToString(proof),
		ChainID:     chainID.Uint64(),
		BlockNumber: blockNum,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// decodeHexFixed decodes a hex string (with optional 0x prefix) and checks
// that the result is exactly n bytes.
func decodeHexFixed(s string, n int, name string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid %s hex: %w", name, err)
	}
	if len(b) != n {
		return nil, fmt.Errorf("%s must be %d bytes, got %d", name, n, len(b))
	}
	return b, nil
}
