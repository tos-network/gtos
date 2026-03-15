package main

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

// Add a CLI command for private transfers.
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
		unoToFlag,
		unoAmountFlag,
		unoMemoHexFlag,
		unoGasFlag,
		unoNonceFlag,
		unoAllowPendingFlag,
	},
	Action: func(ctx *cli.Context) error {
		keyfilepath := ctx.Args().First()
		if keyfilepath == "" {
			return fmt.Errorf("Usage: toskey priv-transfer --to <addr> --amount <n> <keyfile>")
		}
		amount := ctx.Uint64(unoAmountFlag.Name)
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
