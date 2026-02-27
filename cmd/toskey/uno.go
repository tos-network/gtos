package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/tos-network/gtos/accounts/keystore"
	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/cmd/utils"
	"github.com/tos-network/gtos/common/hexutil"
	cryptouno "github.com/tos-network/gtos/crypto/uno"
	"github.com/tos-network/gtos/rpc"
	"github.com/urfave/cli/v2"
)

var (
	rpcURLFlag = &cli.StringFlag{
		Name:  "rpc",
		Usage: "RPC endpoint URL",
		Value: "http://127.0.0.1:8545",
	}
	maxAmountFlag = &cli.Uint64Flag{
		Name:  "max-amount",
		Usage: "maximum balance to search (TOS units)",
		Value: 1_000_000_000,
	}
	blockFlag = &cli.StringFlag{
		Name:  "block",
		Usage: "block number or tag (latest, earliest, pending)",
		Value: "latest",
	}
)

type unoBalanceOutput struct {
	Address     string `json:"address"`
	Balance     uint64 `json:"balance"`
	Version     uint64 `json:"version"`
	BlockNumber uint64 `json:"blockNumber"`
}

var commandUnoBalance = &cli.Command{
	Name:      "uno-balance",
	Usage:     "decrypt UNO ElGamal balance from a local keyfile",
	ArgsUsage: "<keyfile>",
	Description: `
Decrypt the UNO (privacy) balance for an ElGamal account.

The keyfile is decrypted locally; the private key never leaves this machine.
The node is only queried for the public ciphertext state.

Example:
    toskey uno-balance --rpc http://localhost:8545 /path/to/keyfile.json
`,
	Flags: []cli.Flag{
		passphraseFlag,
		jsonFlag,
		rpcURLFlag,
		maxAmountFlag,
		blockFlag,
	},
	Action: func(ctx *cli.Context) error {
		// 1. Read keyfile.
		keyfilepath := ctx.Args().First()
		if keyfilepath == "" {
			utils.Fatalf("Usage: toskey uno-balance <keyfile>")
		}
		keyjson, err := os.ReadFile(keyfilepath)
		if err != nil {
			utils.Fatalf("Failed to read keyfile '%s': %v", keyfilepath, err)
		}

		// 2. Decrypt key with passphrase.
		passphrase := getPassphrase(ctx, false)
		key, err := keystore.DecryptKey(keyjson, passphrase)
		if err != nil {
			utils.Fatalf("Error decrypting key: %v", err)
		}

		// 3. Verify account is an ElGamal account.
		signerType, canonErr := accountsigner.CanonicalSignerType(key.SignerType)
		if canonErr != nil || signerType != accountsigner.SignerTypeElgamal {
			utils.Fatalf("uno-balance requires an ElGamal keyfile (got signer type: %q)", key.SignerType)
		}
		privKey := key.ElgamalPrivateKey
		address := key.Address

		// 4. Connect to RPC and fetch ciphertext.
		client, err := rpc.Dial(ctx.String(rpcURLFlag.Name))
		if err != nil {
			utils.Fatalf("Failed to connect to RPC endpoint: %v", err)
		}
		defer client.Close()

		blockArg := ctx.String(blockFlag.Name)
		var ct struct {
			Commitment  hexutil.Bytes  `json:"commitment"`
			Handle      hexutil.Bytes  `json:"handle"`
			Version     hexutil.Uint64 `json:"version"`
			BlockNumber hexutil.Uint64 `json:"blockNumber"`
		}
		if err := client.Call(&ct, "tos_getUNOCiphertext", address, blockArg); err != nil {
			utils.Fatalf("tos_getUNOCiphertext RPC call failed: %v", err)
		}
		if len(ct.Commitment) != 32 || len(ct.Handle) != 32 {
			utils.Fatalf("invalid ciphertext from node: commitment=%d bytes, handle=%d bytes",
				len(ct.Commitment), len(ct.Handle))
		}

		// 5. Decrypt ciphertext locally.
		var ct64 [64]byte
		copy(ct64[:32], ct.Commitment)
		copy(ct64[32:], ct.Handle)

		msgPoint, err := cryptouno.DecryptToPoint(privKey, ct64[:])
		if err != nil {
			if errors.Is(err, cryptouno.ErrBackendUnavailable) {
				utils.Fatalf("UNO crypto backend unavailable: build with CGO and ed25519c tags")
			}
			utils.Fatalf("Decryption failed: %v", err)
		}

		// 6. Solve ECDLP.
		maxAmount := ctx.Uint64(maxAmountFlag.Name)
		balance, found, err := cryptouno.SolveDiscreteLog(msgPoint, maxAmount)
		if err != nil {
			utils.Fatalf("ECDLP failed: %v", err)
		}
		if !found {
			utils.Fatalf("Balance exceeds --max-amount %d TOS; retry with a larger value", maxAmount)
		}

		// 7. Print result.
		out := unoBalanceOutput{
			Address:     address.Hex(),
			Balance:     balance,
			Version:     uint64(ct.Version),
			BlockNumber: uint64(ct.BlockNumber),
		}
		if ctx.Bool(jsonFlag.Name) {
			mustPrintJSON(out)
		} else {
			fmt.Printf("UNO balance: %d TOS (version %d, block %d)\n",
				out.Balance, out.Version, out.BlockNumber)
		}
		return nil
	},
}
