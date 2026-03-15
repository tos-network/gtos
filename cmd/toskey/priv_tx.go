package main

import (
	"fmt"

	"github.com/tos-network/gtos/common"
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
		Usage: "amount to transfer (in TOS units)",
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
)

func parseToAddress(ctx *cli.Context) common.Address {
	return common.HexToAddress(ctx.String(privToFlag.Name))
}

// commandPrivTransfer is a CLI command for private transfers.
// This is a minimal placeholder that demonstrates the command structure.
// Full proof generation requires the crypto backend.
var commandPrivTransfer = &cli.Command{
	Name:      "priv-transfer",
	Usage:     "Create and sign a private transfer transaction",
	ArgsUsage: "<keyfile>",
	Description: `
Creates a PrivTransferTx: a confidential transfer between two ElGamal accounts.
The sender's private key is used to generate proofs and sign the transaction.
The receiver is identified by their ElGamal compressed public key (32 bytes).

This command requires the CGO crypto backend (ed25519c build tag) for proof generation.
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
	},
	Action: func(ctx *cli.Context) error {
		keyfilepath := ctx.Args().First()
		if keyfilepath == "" {
			return fmt.Errorf("Usage: toskey priv-transfer --to <addr> --amount <n> <keyfile>")
		}
		amount := ctx.Uint64(privAmountFlag.Name)
		if amount == 0 {
			return fmt.Errorf("--amount must be greater than zero")
		}
		_ = parseToAddress(ctx) // validate --to flag

		// Placeholder: proof generation is not yet implemented.
		// A full implementation would:
		//   1. Load the ElGamal keyfile (loadElgamalKeyFromFile)
		//   2. Connect to the RPC endpoint
		//   3. Fetch sender/receiver ciphertexts and public keys
		//   4. Build PrivTransferTx with proofs (CtValidityProof, CommitmentEqProof, RangeProof)
		//   5. Sign with ElGamal Ristretto-Schnorr
		//   6. Submit via RPC
		return fmt.Errorf("priv-transfer: proof generation not yet implemented; use RPC priv_transfer with pre-generated proofs")
	},
}
