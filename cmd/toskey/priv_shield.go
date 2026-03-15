package main

import (
	"encoding/hex"
	"fmt"

	"github.com/tos-network/gtos/core/priv"
	"github.com/urfave/cli/v2"
)

// commandPrivShield generates proofs for a ShieldTx (public→private deposit).
var commandPrivShield = &cli.Command{
	Name:      "priv-shield",
	Usage:     "Generate proofs for a shield (public-to-private deposit) transaction",
	ArgsUsage: "",
	Description: `
Generates a ShieldProof and RangeProof for depositing a plaintext amount into
the recipient's encrypted (private) balance. The recipient defaults to the
sender if --receiver-pub is not specified.

Requires --sender-pub (or --receiver-pub), --amount flags at minimum.
`,
	Flags: []cli.Flag{
		jsonFlag,
		privSenderPubFlag,
		privReceiverPubFlag,
		privAmountFlag,
		privContextFlag,
	},
	Action: func(ctx *cli.Context) error {
		amount := ctx.Uint64(privAmountFlag.Name)
		if amount == 0 {
			return fmt.Errorf("--amount must be greater than zero")
		}

		senderPubHex := ctx.String(privSenderPubFlag.Name)
		if senderPubHex == "" {
			return fmt.Errorf("--sender-pub is required")
		}
		senderPubBytes, err := hex.DecodeString(senderPubHex)
		if err != nil || len(senderPubBytes) != 32 {
			return fmt.Errorf("--sender-pub must be 32 bytes hex")
		}

		// Recipient defaults to sender for self-directed shield.
		recipientPubHex := ctx.String(privReceiverPubFlag.Name)
		if recipientPubHex == "" {
			recipientPubHex = senderPubHex
		}
		recipientPubBytes, err := hex.DecodeString(recipientPubHex)
		if err != nil || len(recipientPubBytes) != 32 {
			return fmt.Errorf("--receiver-pub must be 32 bytes hex")
		}

		var recipientPub [32]byte
		copy(recipientPub[:], recipientPubBytes)

		var context []byte
		if ctxHex := ctx.String(privContextFlag.Name); ctxHex != "" {
			context, err = hex.DecodeString(ctxHex)
			if err != nil {
				return fmt.Errorf("--context must be valid hex: %w", err)
			}
		}

		commitment, handle, shieldProof, rangeProof, err := priv.BuildShieldProofs(
			recipientPub, amount, context,
		)
		if err != nil {
			return fmt.Errorf("proof generation failed: %w", err)
		}

		result := map[string]interface{}{
			"commitment":  hex.EncodeToString(commitment[:]),
			"handle":      hex.EncodeToString(handle[:]),
			"shieldProof": hex.EncodeToString(shieldProof),
			"rangeProof":  hex.EncodeToString(rangeProof),
		}
		mustPrintJSON(result)
		return nil
	},
}

// commandPrivUnshield generates proofs for an UnshieldTx (private→public withdrawal).
var commandPrivUnshield = &cli.Command{
	Name:      "priv-unshield",
	Usage:     "Generate proofs for an unshield (private-to-public withdrawal) transaction",
	ArgsUsage: "",
	Description: `
Generates a CommitmentEqProof and RangeProof for withdrawing a plaintext amount
from the sender's encrypted balance. The withdrawn TOS is credited to the
recipient's public balance (defaults to sender's own address).

Requires --sender-priv, --sender-pub, --amount, --balance, --sender-ct flags.
`,
	Flags: []cli.Flag{
		jsonFlag,
		privSenderPrivFlag,
		privSenderPubFlag,
		privAmountFlag,
		privBalanceFlag,
		privSenderCtFlag,
		privContextFlag,
	},
	Action: func(ctx *cli.Context) error {
		amount := ctx.Uint64(privAmountFlag.Name)
		if amount == 0 {
			return fmt.Errorf("--amount must be greater than zero")
		}

		senderPrivHex := ctx.String(privSenderPrivFlag.Name)
		senderPubHex := ctx.String(privSenderPubFlag.Name)
		senderCtHex := ctx.String(privSenderCtFlag.Name)

		if senderPrivHex == "" || senderPubHex == "" || senderCtHex == "" {
			return fmt.Errorf("--sender-priv, --sender-pub, and --sender-ct are required")
		}

		senderPrivBytes, err := hex.DecodeString(senderPrivHex)
		if err != nil || len(senderPrivBytes) != 32 {
			return fmt.Errorf("--sender-priv must be 32 bytes hex")
		}
		senderPubBytes, err := hex.DecodeString(senderPubHex)
		if err != nil || len(senderPubBytes) != 32 {
			return fmt.Errorf("--sender-pub must be 32 bytes hex")
		}
		senderCtBytes, err := hex.DecodeString(senderCtHex)
		if err != nil || len(senderCtBytes) != 64 {
			return fmt.Errorf("--sender-ct must be 64 bytes hex (commitment||handle)")
		}

		balance := ctx.Uint64(privBalanceFlag.Name)

		var senderPriv, senderPub [32]byte
		copy(senderPriv[:], senderPrivBytes)
		copy(senderPub[:], senderPubBytes)

		var senderCiphertext priv.Ciphertext
		copy(senderCiphertext.Commitment[:], senderCtBytes[:32])
		copy(senderCiphertext.Handle[:], senderCtBytes[32:])

		var context []byte
		if ctxHex := ctx.String(privContextFlag.Name); ctxHex != "" {
			context, err = hex.DecodeString(ctxHex)
			if err != nil {
				return fmt.Errorf("--context must be valid hex: %w", err)
			}
		}

		sourceCommitment, commitmentEqProof, rangeProof, err := priv.BuildUnshieldProofs(
			senderPriv, senderPub,
			amount, balance,
			senderCiphertext, context,
		)
		if err != nil {
			return fmt.Errorf("proof generation failed: %w", err)
		}

		result := map[string]interface{}{
			"sourceCommitment":  hex.EncodeToString(sourceCommitment[:]),
			"commitmentEqProof": hex.EncodeToString(commitmentEqProof),
			"rangeProof":        hex.EncodeToString(rangeProof),
		}
		mustPrintJSON(result)
		return nil
	},
}
