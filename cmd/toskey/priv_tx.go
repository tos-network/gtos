package main

import (
	"encoding/hex"
	"fmt"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/priv"
	"github.com/urfave/cli/v2"
)

var (
	rpcURLFlag = &cli.StringFlag{
		Name:  "rpc",
		Usage: "RPC endpoint URL",
		Value: "http://127.0.0.1:8545",
	}
	privToFlag = &cli.StringFlag{
		Name:  "to",
		Usage: "recipient address (hex)",
	}
	privAmountFlag = &cli.Uint64Flag{
		Name:  "amount",
		Usage: "amount in UNO base units (1 = 0.01 UNO = 0.01 TOS)",
	}
	privMemoHexFlag = &cli.StringFlag{
		Name:  "memo",
		Usage: "optional encrypted memo (hex)",
	}
	privGasFlag = &cli.Uint64Flag{
		Name:  "gas",
		Usage: "gas limit override",
	}
	privNonceFlag = &cli.Int64Flag{
		Name:  "nonce",
		Usage: "nonce override (-1 = auto)",
		Value: -1,
	}
	privAllowPendingFlag = &cli.BoolFlag{
		Name:  "allow-pending",
		Usage: "allow pending nonce",
	}
	privSenderPrivFlag = &cli.StringFlag{
		Name:  "sender-priv",
		Usage: "sender ElGamal private key (hex, 32 bytes)",
	}
	privSenderPubFlag = &cli.StringFlag{
		Name:  "sender-pub",
		Usage: "sender ElGamal public key (hex, 32 bytes)",
	}
	privReceiverPubFlag = &cli.StringFlag{
		Name:  "receiver-pub",
		Usage: "receiver ElGamal public key (hex, 32 bytes)",
	}
	privBalanceFlag = &cli.Uint64Flag{
		Name:  "balance",
		Usage: "sender current plaintext balance (decrypted client-side)",
	}
	privFeeLimitFlag = &cli.Uint64Flag{
		Name:  "fee-limit",
		Usage: "fee limit for the transfer",
		Value: 0,
	}
	privSenderCtFlag = &cli.StringFlag{
		Name:  "sender-ct",
		Usage: "sender current encrypted balance ciphertext (hex, 64 bytes: commitment||handle)",
	}
	privContextFlag = &cli.StringFlag{
		Name:  "context",
		Usage: "Merlin transcript context bytes (hex)",
	}
)

func parseToAddress(ctx *cli.Context) common.Address {
	return common.HexToAddress(ctx.String(privToFlag.Name))
}

// commandPrivTransfer is a CLI command for private transfers.
// It generates the three ZK proofs required for a PrivTransferTx using
// BuildTransferProofs.
var commandPrivTransfer = &cli.Command{
	Name:      "priv-transfer",
	Usage:     "Create and sign a private transfer transaction",
	ArgsUsage: "<keyfile>",
	Description: `
Creates a PrivTransferTx: a confidential transfer between two ElGamal accounts.
The sender's private key is used to generate proofs and sign the transaction.
The receiver is identified by their ElGamal compressed public key (32 bytes).

This command requires the CGO crypto backend (ed25519c build tag) for proof generation.

In proof-of-concept mode (with --sender-priv, --sender-pub, --receiver-pub,
--balance, --sender-ct flags), it generates proofs locally without RPC.
`,
	Flags: []cli.Flag{
		passphraseFlag,
		jsonFlag,
		rpcURLFlag,
		privToFlag,
		privAmountFlag,
		privMemoHexFlag,
		privGasFlag,
		privNonceFlag,
		privAllowPendingFlag,
		privSenderPrivFlag,
		privSenderPubFlag,
		privReceiverPubFlag,
		privBalanceFlag,
		privFeeLimitFlag,
		privSenderCtFlag,
		privContextFlag,
	},
	Action: func(ctx *cli.Context) error {
		amount := ctx.Uint64(privAmountFlag.Name)
		if amount == 0 {
			return fmt.Errorf("--amount must be greater than zero")
		}

		// Proof-of-concept mode: generate proofs from explicit flags.
		senderPrivHex := ctx.String(privSenderPrivFlag.Name)
		senderPubHex := ctx.String(privSenderPubFlag.Name)
		receiverPubHex := ctx.String(privReceiverPubFlag.Name)
		senderCtHex := ctx.String(privSenderCtFlag.Name)

		if senderPrivHex == "" || senderPubHex == "" || receiverPubHex == "" || senderCtHex == "" {
			return fmt.Errorf("proof-of-concept mode requires --sender-priv, --sender-pub, --receiver-pub, and --sender-ct flags")
		}

		senderPrivBytes, err := hex.DecodeString(senderPrivHex)
		if err != nil || len(senderPrivBytes) != 32 {
			return fmt.Errorf("--sender-priv must be 32 bytes hex")
		}
		senderPubBytes, err := hex.DecodeString(senderPubHex)
		if err != nil || len(senderPubBytes) != 32 {
			return fmt.Errorf("--sender-pub must be 32 bytes hex")
		}
		receiverPubBytes, err := hex.DecodeString(receiverPubHex)
		if err != nil || len(receiverPubBytes) != 32 {
			return fmt.Errorf("--receiver-pub must be 32 bytes hex")
		}
		senderCtBytes, err := hex.DecodeString(senderCtHex)
		if err != nil || len(senderCtBytes) != 64 {
			return fmt.Errorf("--sender-ct must be 64 bytes hex (commitment||handle)")
		}

		balance := ctx.Uint64(privBalanceFlag.Name)
		feeLimit := ctx.Uint64(privFeeLimitFlag.Name)

		var senderPriv, senderPub, receiverPub [32]byte
		copy(senderPriv[:], senderPrivBytes)
		copy(senderPub[:], senderPubBytes)
		copy(receiverPub[:], receiverPubBytes)

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

		commitment, senderHandle, receiverHandle, sourceCommitment,
			ctValidityProof, commitmentEqProof, rangeProof, err := priv.BuildTransferProofs(
			senderPriv, senderPub, receiverPub,
			amount, balance, feeLimit,
			senderCiphertext, context,
		)
		if err != nil {
			return fmt.Errorf("proof generation failed: %w", err)
		}

		result := map[string]interface{}{
			"commitment":        hex.EncodeToString(commitment[:]),
			"senderHandle":      hex.EncodeToString(senderHandle[:]),
			"receiverHandle":    hex.EncodeToString(receiverHandle[:]),
			"sourceCommitment":  hex.EncodeToString(sourceCommitment[:]),
			"ctValidityProof":   hex.EncodeToString(ctValidityProof),
			"commitmentEqProof": hex.EncodeToString(commitmentEqProof),
			"rangeProof":        hex.EncodeToString(rangeProof),
		}
		mustPrintJSON(result)
		return nil
	},
}
