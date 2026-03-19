package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	corepriv "github.com/tos-network/gtos/core/priv"
	"github.com/urfave/cli/v2"
)

type outputPrivDecryptionToken struct {
	Pubkey      string `json:"pubkey"`
	Commitment  string `json:"commitment"`
	Handle      string `json:"handle"`
	Token       string `json:"token"`
	DLEQProof   string `json:"dleqProof"`
	ChainID     uint64 `json:"chainId"`
	BlockNumber uint64 `json:"blockNumber"`
}

type outputPrivTokenDecrypt struct {
	Amount uint64 `json:"amount"`
}

var commandPrivGenerateToken = &cli.Command{
	Name:  "priv-generate-token",
	Usage: "Generate a decryption token for an encrypted balance",
	Description: `
Generates a decryption token that allows a third party to decrypt a specific
encrypted balance. Includes a DLEQ proof of honest generation.`,
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "privkey", Usage: "hex-encoded 32-byte ElGamal private key", Required: true},
		&cli.StringFlag{Name: "pubkey", Usage: "hex-encoded 32-byte ElGamal public key", Required: true},
		&cli.StringFlag{Name: "ct", Usage: "hex-encoded 64-byte ciphertext (commitment||handle)", Required: true},
		&cli.Uint64Flag{Name: "chain-id", Usage: "chain ID for replay protection", Value: 1},
		&cli.Uint64Flag{Name: "block", Usage: "block number for freshness binding", Value: 0},
	},
	Action: actionPrivGenerateToken,
}

var commandPrivDecryptToken = &cli.Command{
	Name:  "priv-decrypt-token",
	Usage: "Decrypt an encrypted balance using a decryption token",
	Description: `
Decrypts an encrypted balance given a decryption token and commitment.
Uses baby-step giant-step to recover the plaintext amount from the
decrypted point.`,
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "token", Usage: "hex-encoded 32-byte decryption token", Required: true},
		&cli.StringFlag{Name: "commitment", Usage: "hex-encoded 32-byte commitment", Required: true},
	},
	Action: actionPrivDecryptToken,
}

func actionPrivGenerateToken(ctx *cli.Context) error {
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

	chainID := new(big.Int).SetUint64(ctx.Uint64("chain-id"))
	blockNum := ctx.Uint64("block")

	var privkey32, pubkey32 [32]byte
	copy(privkey32[:], privkey)
	copy(pubkey32[:], pubkey)

	var ct corepriv.Ciphertext
	copy(ct.Commitment[:], ctBytes[:32])
	copy(ct.Handle[:], ctBytes[32:])

	dt, err := corepriv.BuildDecryptionToken(privkey32, pubkey32, ct, chainID, blockNum)
	if err != nil {
		return fmt.Errorf("decryption token generation failed: %w", err)
	}

	out := outputPrivDecryptionToken{
		Pubkey:      hex.EncodeToString(dt.Pubkey[:]),
		Commitment:  hex.EncodeToString(dt.Ciphertext.Commitment[:]),
		Handle:      hex.EncodeToString(dt.Ciphertext.Handle[:]),
		Token:       hex.EncodeToString(dt.Token[:]),
		DLEQProof:   hex.EncodeToString(dt.DLEQProof[:]),
		ChainID:     chainID.Uint64(),
		BlockNumber: blockNum,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func actionPrivDecryptToken(ctx *cli.Context) error {
	tokenBytes, err := decodeHexFixed(ctx.String("token"), 32, "token")
	if err != nil {
		return err
	}
	commitmentBytes, err := decodeHexFixed(ctx.String("commitment"), 32, "commitment")
	if err != nil {
		return err
	}

	dt := &corepriv.DecryptionToken{}
	copy(dt.Token[:], tokenBytes)
	copy(dt.Ciphertext.Commitment[:], commitmentBytes)

	amount, err := corepriv.DecryptTokenAmount(dt)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	out := outputPrivTokenDecrypt{Amount: amount}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
