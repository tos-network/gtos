package main

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/tos-network/gtos/accounts/keystore"
	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/cmd/utils"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	coreuno "github.com/tos-network/gtos/core/uno"
	cryptouno "github.com/tos-network/gtos/crypto/uno"
	"github.com/tos-network/gtos/rpc"
	"github.com/urfave/cli/v2"
)

var (
	unoAmountFlag = &cli.Uint64Flag{
		Name:  "amount",
		Usage: "UNO amount in TOS units",
	}
	unoToFlag = &cli.StringFlag{
		Name:  "to",
		Usage: "destination address (0x + 64 hex chars)",
	}
	unoMemoHexFlag = &cli.StringFlag{
		Name:  "memo-hex",
		Usage: "optional encrypted memo bytes in hex (0x...)",
	}
	unoGasFlag = &cli.Uint64Flag{
		Name:  "gas",
		Usage: "optional gas limit override",
	}
	unoNonceFlag = &cli.Uint64Flag{
		Name:  "nonce",
		Usage: "optional explicit nonce override",
	}
	unoAllowPendingFlag = &cli.BoolFlag{
		Name:  "allow-pending",
		Usage: "allow building from latest state even when sender has pending tx (unsafe for proof context)",
		Value: false,
	}
)

type rpcUNOCiphertextResult struct {
	Commitment hexutil.Bytes  `json:"commitment"`
	Handle     hexutil.Bytes  `json:"handle"`
	Version    hexutil.Uint64 `json:"version"`
}

type rpcSignerDescriptor struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Defaulted bool   `json:"defaulted"`
}

type rpcSignerProfile struct {
	Signer rpcSignerDescriptor `json:"signer"`
}

type rpcUNOShieldArgs struct {
	From                common.Address `json:"from"`
	Nonce               *hexutil.Uint64
	Gas                 *hexutil.Uint64
	Amount              hexutil.Uint64 `json:"amount"`
	NewSenderCommitment hexutil.Bytes  `json:"newSenderCommitment"`
	NewSenderHandle     hexutil.Bytes  `json:"newSenderHandle"`
	ProofBundle         hexutil.Bytes  `json:"proofBundle"`
	EncryptedMemo       hexutil.Bytes  `json:"encryptedMemo,omitempty"`
}

type rpcUNOTransferArgs struct {
	From                    common.Address `json:"from"`
	Nonce                   *hexutil.Uint64
	Gas                     *hexutil.Uint64
	To                      common.Address `json:"to"`
	NewSenderCommitment     hexutil.Bytes  `json:"newSenderCommitment"`
	NewSenderHandle         hexutil.Bytes  `json:"newSenderHandle"`
	ReceiverDeltaCommitment hexutil.Bytes  `json:"receiverDeltaCommitment"`
	ReceiverDeltaHandle     hexutil.Bytes  `json:"receiverDeltaHandle"`
	ProofBundle             hexutil.Bytes  `json:"proofBundle"`
	EncryptedMemo           hexutil.Bytes  `json:"encryptedMemo,omitempty"`
}

type rpcUNOUnshieldArgs struct {
	From                common.Address `json:"from"`
	Nonce               *hexutil.Uint64
	Gas                 *hexutil.Uint64
	To                  common.Address `json:"to"`
	Amount              hexutil.Uint64 `json:"amount"`
	NewSenderCommitment hexutil.Bytes  `json:"newSenderCommitment"`
	NewSenderHandle     hexutil.Bytes  `json:"newSenderHandle"`
	ProofBundle         hexutil.Bytes  `json:"proofBundle"`
	EncryptedMemo       hexutil.Bytes  `json:"encryptedMemo,omitempty"`
}

type unoSubmitOutput struct {
	Action string `json:"action"`
	From   string `json:"from"`
	To     string `json:"to,omitempty"`
	Amount uint64 `json:"amount,omitempty"`
	Nonce  uint64 `json:"nonce"`
	TxHash string `json:"txHash"`
}

func loadElgamalKeyFromFile(ctx *cli.Context, keyfilepath string) (*keystore.Key, []byte) {
	keyjson, err := os.ReadFile(keyfilepath)
	if err != nil {
		utils.Fatalf("Failed to read keyfile '%s': %v", keyfilepath, err)
	}
	passphrase := getPassphrase(ctx, false)
	key, err := keystore.DecryptKey(keyjson, passphrase)
	if err != nil {
		utils.Fatalf("Error decrypting key: %v", err)
	}
	signerType, err := accountsigner.CanonicalSignerType(key.SignerType)
	if err != nil || signerType != accountsigner.SignerTypeElgamal || len(key.ElgamalPrivateKey) != 32 {
		utils.Fatalf("UNO tx commands require an ElGamal keyfile (got signer type: %q)", key.SignerType)
	}
	pub, err := cryptouno.PublicKeyFromPrivate(key.ElgamalPrivateKey)
	if err != nil {
		if errors.Is(err, cryptouno.ErrBackendUnavailable) {
			utils.Fatalf("UNO crypto backend unavailable: build toskey with CGO and ed25519c tags")
		}
		utils.Fatalf("Failed to derive elgamal public key: %v", err)
	}
	return key, pub
}

func requireRPCElgamalPubkey(client *rpc.Client, addr common.Address) []byte {
	var profile rpcSignerProfile
	if err := client.Call(&profile, "tos_getSigner", addr, "latest"); err != nil {
		utils.Fatalf("tos_getSigner(%s) failed: %v", addr.Hex(), err)
	}
	if profile.Signer.Type != accountsigner.SignerTypeElgamal {
		utils.Fatalf("account %s signer type must be elgamal, got %q", addr.Hex(), profile.Signer.Type)
	}
	pub, err := hexutil.Decode(strings.TrimSpace(profile.Signer.Value))
	if err != nil || len(pub) != 32 {
		utils.Fatalf("account %s signer value is not a valid 32-byte elgamal pubkey", addr.Hex())
	}
	return pub
}

func rpcUNOCiphertext(client *rpc.Client, addr common.Address) coreuno.Ciphertext {
	var got rpcUNOCiphertextResult
	if err := client.Call(&got, "tos_getUNOCiphertext", addr, "latest"); err != nil {
		utils.Fatalf("tos_getUNOCiphertext(%s) failed: %v", addr.Hex(), err)
	}
	if len(got.Commitment) != coreuno.CiphertextSize || len(got.Handle) != coreuno.CiphertextSize {
		utils.Fatalf("invalid uno ciphertext for %s: commitment=%d handle=%d", addr.Hex(), len(got.Commitment), len(got.Handle))
	}
	var out coreuno.Ciphertext
	copy(out.Commitment[:], got.Commitment)
	copy(out.Handle[:], got.Handle)
	return out
}

func rpcChainID(client *rpc.Client) *big.Int {
	var chainID hexutil.Big
	if err := client.Call(&chainID, "tos_chainId"); err != nil {
		utils.Fatalf("tos_chainId failed: %v", err)
	}
	return new(big.Int).Set((*big.Int)(&chainID))
}

func rpcAccountNonce(client *rpc.Client, addr common.Address, tag string) uint64 {
	var out hexutil.Uint64
	if err := client.Call(&out, "tos_getTransactionCount", addr, tag); err != nil {
		utils.Fatalf("tos_getTransactionCount(%s, %s) failed: %v", addr.Hex(), tag, err)
	}
	return uint64(out)
}

func pickNonce(ctx *cli.Context, client *rpc.Client, from common.Address) uint64 {
	if ctx.IsSet(unoNonceFlag.Name) {
		return ctx.Uint64(unoNonceFlag.Name)
	}
	latest := rpcAccountNonce(client, from, "latest")
	pending := rpcAccountNonce(client, from, "pending")
	if pending != latest && !ctx.Bool(unoAllowPendingFlag.Name) {
		utils.Fatalf("sender %s has pending tx (latest nonce=%d, pending nonce=%d); wait for confirmation or pass --allow-pending", from.Hex(), latest, pending)
	}
	return pending
}

func parseMemoHex(ctx *cli.Context) hexutil.Bytes {
	raw := strings.TrimSpace(ctx.String(unoMemoHexFlag.Name))
	if raw == "" {
		return nil
	}
	b, err := hexutil.Decode(raw)
	if err != nil {
		utils.Fatalf("invalid --memo-hex: %v", err)
	}
	return b
}

func parseToAddress(ctx *cli.Context) common.Address {
	raw := strings.TrimSpace(ctx.String(unoToFlag.Name))
	if !common.IsHexAddress(raw) {
		utils.Fatalf("invalid --to address: %q", raw)
	}
	return common.HexToAddress(raw)
}

func optionalNonce(ctx *cli.Context, nonce uint64) *hexutil.Uint64 {
	n := hexutil.Uint64(nonce)
	return &n
}

func optionalGas(ctx *cli.Context) *hexutil.Uint64 {
	if !ctx.IsSet(unoGasFlag.Name) {
		return nil
	}
	g := hexutil.Uint64(ctx.Uint64(unoGasFlag.Name))
	return &g
}

var commandUnoShield = &cli.Command{
	Name:      "uno-shield",
	Usage:     "build UNO shield proof locally and submit via tos_unoShield",
	ArgsUsage: "<keyfile>",
	Flags: []cli.Flag{
		passphraseFlag,
		jsonFlag,
		rpcURLFlag,
		unoAmountFlag,
		unoMemoHexFlag,
		unoGasFlag,
		unoNonceFlag,
		unoAllowPendingFlag,
	},
	Action: func(ctx *cli.Context) error {
		keyfilepath := ctx.Args().First()
		if keyfilepath == "" {
			utils.Fatalf("Usage: toskey uno-shield --amount <n> <keyfile>")
		}
		amount := ctx.Uint64(unoAmountFlag.Name)
		if amount == 0 {
			utils.Fatalf("--amount must be greater than zero")
		}
		key, localPub := loadElgamalKeyFromFile(ctx, keyfilepath)
		client, err := rpc.Dial(ctx.String(rpcURLFlag.Name))
		if err != nil {
			utils.Fatalf("Failed to connect to RPC endpoint: %v", err)
		}
		defer client.Close()

		statePub := requireRPCElgamalPubkey(client, key.Address)
		if !bytes.Equal(statePub, localPub) {
			utils.Fatalf("keyfile pubkey does not match on-chain signer for %s", key.Address.Hex())
		}
		senderOld := rpcUNOCiphertext(client, key.Address)
		nonce := pickNonce(ctx, client, key.Address)
		payload, _, err := coreuno.BuildShieldPayloadProof(coreuno.ShieldBuildArgs{
			ChainID:   rpcChainID(client),
			From:      key.Address,
			Nonce:     nonce,
			SenderOld: senderOld,
			SenderPub: localPub,
			Amount:    amount,
		})
		if err != nil {
			utils.Fatalf("BuildShieldPayloadProof failed: %v", err)
		}
		args := rpcUNOShieldArgs{
			From:                key.Address,
			Nonce:               optionalNonce(ctx, nonce),
			Gas:                 optionalGas(ctx),
			Amount:              hexutil.Uint64(amount),
			NewSenderCommitment: hexutil.Bytes(payload.NewSender.Commitment[:]),
			NewSenderHandle:     hexutil.Bytes(payload.NewSender.Handle[:]),
			ProofBundle:         hexutil.Bytes(payload.ProofBundle),
			EncryptedMemo:       parseMemoHex(ctx),
		}
		var txHash common.Hash
		if err := client.Call(&txHash, "tos_unoShield", args); err != nil {
			utils.Fatalf("tos_unoShield failed: %v", err)
		}
		out := unoSubmitOutput{
			Action: "shield",
			From:   key.Address.Hex(),
			Amount: amount,
			Nonce:  nonce,
			TxHash: txHash.Hex(),
		}
		if ctx.Bool(jsonFlag.Name) {
			mustPrintJSON(out)
		} else {
			fmt.Printf("UNO shield submitted: tx=%s nonce=%d amount=%d from=%s\n", out.TxHash, out.Nonce, out.Amount, out.From)
		}
		return nil
	},
}

var commandUnoTransfer = &cli.Command{
	Name:      "uno-transfer",
	Usage:     "build UNO transfer proof locally and submit via tos_unoTransfer",
	ArgsUsage: "<keyfile>",
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
			utils.Fatalf("Usage: toskey uno-transfer --to <addr> --amount <n> <keyfile>")
		}
		amount := ctx.Uint64(unoAmountFlag.Name)
		if amount == 0 {
			utils.Fatalf("--amount must be greater than zero")
		}
		to := parseToAddress(ctx)
		key, localPub := loadElgamalKeyFromFile(ctx, keyfilepath)
		client, err := rpc.Dial(ctx.String(rpcURLFlag.Name))
		if err != nil {
			utils.Fatalf("Failed to connect to RPC endpoint: %v", err)
		}
		defer client.Close()

		senderStatePub := requireRPCElgamalPubkey(client, key.Address)
		if !bytes.Equal(senderStatePub, localPub) {
			utils.Fatalf("keyfile pubkey does not match on-chain signer for %s", key.Address.Hex())
		}
		receiverPub := requireRPCElgamalPubkey(client, to)
		nonce := pickNonce(ctx, client, key.Address)
		payload, _, err := coreuno.BuildTransferPayloadProof(coreuno.TransferBuildArgs{
			ChainID:     rpcChainID(client),
			From:        key.Address,
			To:          to,
			Nonce:       nonce,
			SenderOld:   rpcUNOCiphertext(client, key.Address),
			ReceiverOld: rpcUNOCiphertext(client, to),
			SenderPriv:  key.ElgamalPrivateKey,
			ReceiverPub: receiverPub,
			Amount:      amount,
		})
		if err != nil {
			utils.Fatalf("BuildTransferPayloadProof failed: %v", err)
		}
		args := rpcUNOTransferArgs{
			From:                    key.Address,
			Nonce:                   optionalNonce(ctx, nonce),
			Gas:                     optionalGas(ctx),
			To:                      to,
			NewSenderCommitment:     hexutil.Bytes(payload.NewSender.Commitment[:]),
			NewSenderHandle:         hexutil.Bytes(payload.NewSender.Handle[:]),
			ReceiverDeltaCommitment: hexutil.Bytes(payload.ReceiverDelta.Commitment[:]),
			ReceiverDeltaHandle:     hexutil.Bytes(payload.ReceiverDelta.Handle[:]),
			ProofBundle:             hexutil.Bytes(payload.ProofBundle),
			EncryptedMemo:           parseMemoHex(ctx),
		}
		var txHash common.Hash
		if err := client.Call(&txHash, "tos_unoTransfer", args); err != nil {
			utils.Fatalf("tos_unoTransfer failed: %v", err)
		}
		out := unoSubmitOutput{
			Action: "transfer",
			From:   key.Address.Hex(),
			To:     to.Hex(),
			Amount: amount,
			Nonce:  nonce,
			TxHash: txHash.Hex(),
		}
		if ctx.Bool(jsonFlag.Name) {
			mustPrintJSON(out)
		} else {
			fmt.Printf("UNO transfer submitted: tx=%s nonce=%d amount=%d from=%s to=%s\n", out.TxHash, out.Nonce, out.Amount, out.From, out.To)
		}
		return nil
	},
}

var commandUnoUnshield = &cli.Command{
	Name:      "uno-unshield",
	Usage:     "build UNO unshield proof locally and submit via tos_unoUnshield",
	ArgsUsage: "<keyfile>",
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
			utils.Fatalf("Usage: toskey uno-unshield --to <addr> --amount <n> <keyfile>")
		}
		amount := ctx.Uint64(unoAmountFlag.Name)
		if amount == 0 {
			utils.Fatalf("--amount must be greater than zero")
		}
		to := parseToAddress(ctx)
		key, localPub := loadElgamalKeyFromFile(ctx, keyfilepath)
		client, err := rpc.Dial(ctx.String(rpcURLFlag.Name))
		if err != nil {
			utils.Fatalf("Failed to connect to RPC endpoint: %v", err)
		}
		defer client.Close()

		statePub := requireRPCElgamalPubkey(client, key.Address)
		if !bytes.Equal(statePub, localPub) {
			utils.Fatalf("keyfile pubkey does not match on-chain signer for %s", key.Address.Hex())
		}
		nonce := pickNonce(ctx, client, key.Address)
		payload, _, err := coreuno.BuildUnshieldPayloadProof(coreuno.UnshieldBuildArgs{
			ChainID:    rpcChainID(client),
			From:       key.Address,
			To:         to,
			Nonce:      nonce,
			SenderOld:  rpcUNOCiphertext(client, key.Address),
			SenderPriv: key.ElgamalPrivateKey,
			Amount:     amount,
		})
		if err != nil {
			utils.Fatalf("BuildUnshieldPayloadProof failed: %v", err)
		}
		args := rpcUNOUnshieldArgs{
			From:                key.Address,
			Nonce:               optionalNonce(ctx, nonce),
			Gas:                 optionalGas(ctx),
			To:                  to,
			Amount:              hexutil.Uint64(amount),
			NewSenderCommitment: hexutil.Bytes(payload.NewSender.Commitment[:]),
			NewSenderHandle:     hexutil.Bytes(payload.NewSender.Handle[:]),
			ProofBundle:         hexutil.Bytes(payload.ProofBundle),
			EncryptedMemo:       parseMemoHex(ctx),
		}
		var txHash common.Hash
		if err := client.Call(&txHash, "tos_unoUnshield", args); err != nil {
			utils.Fatalf("tos_unoUnshield failed: %v", err)
		}
		out := unoSubmitOutput{
			Action: "unshield",
			From:   key.Address.Hex(),
			To:     to.Hex(),
			Amount: amount,
			Nonce:  nonce,
			TxHash: txHash.Hex(),
		}
		if ctx.Bool(jsonFlag.Name) {
			mustPrintJSON(out)
		} else {
			fmt.Printf("UNO unshield submitted: tx=%s nonce=%d amount=%d from=%s to=%s\n", out.TxHash, out.Nonce, out.Amount, out.From, out.To)
		}
		return nil
	},
}
