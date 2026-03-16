package main

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/tos-network/gtos/accounts/keystore"
	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/cmd/utils"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	cryptopriv "github.com/tos-network/gtos/crypto/priv"
	"github.com/tos-network/gtos/crypto/priv/ecdlptable"
	"github.com/tos-network/gtos/rpc"
	"github.com/urfave/cli/v2"
)

var (
	privCiphertextFlag = &cli.StringFlag{
		Name:  "ct",
		Usage: "encrypted balance ciphertext as 64-byte hex (commitment||handle)",
	}
	privMaxBalanceFlag = &cli.Uint64Flag{
		Name:  "max-balance",
		Usage: "maximum plaintext balance to search when decrypting via baby-step giant-step",
		Value: 1_000_000,
	}
	privTableFlag = &cli.StringFlag{
		Name:  "table",
		Usage: "path to a precomputed BSGS table file (from priv-generate-table)",
	}
)

type rpcPrivBalanceResult struct {
	Pubkey      hexutil.Bytes  `json:"pubkey"`
	Commitment  hexutil.Bytes  `json:"commitment"`
	Handle      hexutil.Bytes  `json:"handle"`
	Version     hexutil.Uint64 `json:"version"`
	PrivNonce   hexutil.Uint64 `json:"privNonce"`
	BlockNumber hexutil.Uint64 `json:"blockNumber"`
}

type outputPrivKeygen struct {
	Address        string `json:"address"`
	SignerType     string `json:"signerType"`
	PublicKey      string `json:"publicKey"`
	PrivateKey     string `json:"privateKey"`
	Keyfile        string `json:"keyfile,omitempty"`
	DerivationPath string `json:"derivationPath,omitempty"`
	Mnemonic       string `json:"mnemonic,omitempty"`
}

type outputPrivBalance struct {
	Address          string `json:"address"`
	Pubkey           string `json:"pubkey"`
	Ciphertext       string `json:"ciphertext"`
	Commitment       string `json:"commitment"`
	Handle           string `json:"handle"`
	PlaintextBalance uint64 `json:"plaintextBalance"`
	MaxBalance       uint64 `json:"maxBalance"`
	Version          uint64 `json:"version"`
	PrivNonce        uint64 `json:"privNonce"`
	BlockNumber      uint64 `json:"blockNumber"`
	Source           string `json:"source"`
}

// commandPrivKeygen generates a raw ElGamal keypair and can optionally store it
// as an encrypted keyfile when a path argument is provided.
var commandPrivKeygen = &cli.Command{
	Name:      "priv-keygen",
	Usage:     "generate an ElGamal keypair for privacy transactions",
	ArgsUsage: "[<keyfile>]",
	Description: `
Generates an ElGamal keypair, prints the public/private key material, and
optionally writes an encrypted elgamal keyfile when a path argument is given.

Mnemonic derivation is supported via the same flags as toskey generate.
`,
	Flags: []cli.Flag{
		passphraseFlag,
		jsonFlag,
		lightKDFFlag,
		mnemonicGenerateFlag,
		mnemonicFlag,
		mnemonicPassphraseFlag,
		mnemonicBitsFlag,
		hdPathFlag,
	},
	Action: func(ctx *cli.Context) error {
		var (
			privkey         []byte
			derivationPath  string
			mnemonicOutput  string
			mnemonicInput   = strings.TrimSpace(ctx.String(mnemonicFlag.Name))
			mnemonicMode    = mnemonicInput != "" || ctx.Bool(mnemonicGenerateFlag.Name)
			mnemonicGenFlow = false
		)
		if mnemonicMode {
			if mnemonicInput == "" {
				var err error
				mnemonicInput, err = generateMnemonic(ctx.Int(mnemonicBitsFlag.Name))
				if err != nil {
					return fmt.Errorf("failed to generate mnemonic: %w", err)
				}
				mnemonicOutput = mnemonicInput
				mnemonicGenFlow = true
			}
			derivationPath = ctx.String(hdPathFlag.Name)
			var err error
			privkey, err = deriveElgamalPrivateFromMnemonic(mnemonicInput, ctx.String(mnemonicPassphraseFlag.Name), derivationPath)
			if err != nil {
				return fmt.Errorf("failed to derive elgamal private key from mnemonic: %w", err)
			}
		} else {
			var err error
			privkey, err = accountsigner.GenerateElgamalPrivateKey(crand.Reader)
			if err != nil {
				return fmt.Errorf("failed to generate elgamal private key: %w", err)
			}
		}

		pubkey, err := accountsigner.PublicKeyFromElgamalPrivate(privkey)
		if err != nil {
			return fmt.Errorf("failed to derive elgamal public key: %w", err)
		}
		address, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeElgamal, pubkey)
		if err != nil {
			return fmt.Errorf("failed to derive elgamal address: %w", err)
		}

		keyfilePath := ctx.Args().First()
		if keyfilePath != "" {
			if _, err := os.Stat(keyfilePath); err == nil {
				utils.Fatalf("Keyfile already exists at %s.", keyfilePath)
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("error checking keyfile path %q: %w", keyfilePath, err)
			}
			if err := writeElgamalKeyfile(ctx, keyfilePath, address, privkey); err != nil {
				return err
			}
		}

		out := outputPrivKeygen{
			Address:        address.Hex(),
			SignerType:     accountsigner.SignerTypeElgamal,
			PublicKey:      hex.EncodeToString(pubkey),
			PrivateKey:     hex.EncodeToString(privkey),
			Keyfile:        keyfilePath,
			DerivationPath: derivationPath,
		}
		if mnemonicGenFlow {
			out.Mnemonic = mnemonicOutput
		}
		if ctx.Bool(jsonFlag.Name) {
			mustPrintJSON(out)
		} else {
			fmt.Println("Address:", out.Address)
			fmt.Println("Signer type:", out.SignerType)
			fmt.Println("Public key:", out.PublicKey)
			fmt.Println("Private key:", out.PrivateKey)
			if out.Keyfile != "" {
				fmt.Println("Keyfile:", out.Keyfile)
			}
			if out.DerivationPath != "" {
				fmt.Println("Derivation path:", out.DerivationPath)
			}
			if out.Mnemonic != "" {
				fmt.Println("Mnemonic:", out.Mnemonic)
			}
		}
		return nil
	},
}

// commandPrivBalance decrypts a private balance either from RPC or from an
// explicit ciphertext blob provided on the command line.
var commandPrivBalance = &cli.Command{
	Name:      "priv-balance",
	Usage:     "decrypt a private balance from RPC or an explicit ciphertext",
	ArgsUsage: "<keyfile>",
	Description: `
Decrypts an ElGamal private balance client-side. By default it fetches the
current encrypted balance via tos_privGetBalance. You can also pass --ct with a
64-byte ciphertext blob (commitment||handle) to decrypt explicit balance data.

The discrete log search is bounded by --max-balance. Increase it if the command
reports that the balance exceeds the current search window.
`,
	Flags: []cli.Flag{
		passphraseFlag,
		jsonFlag,
		rpcURLFlag,
		privCiphertextFlag,
		privMaxBalanceFlag,
		privTableFlag,
	},
	Action: func(ctx *cli.Context) error {
		keyfilePath := ctx.Args().First()
		if keyfilePath == "" {
			return fmt.Errorf("missing keyfile argument")
		}
		address, pubkey, privkey, err := loadElgamalKeyfile(ctx, keyfilePath)
		if err != nil {
			return err
		}

		var (
			source      string
			blockNumber uint64
			version     uint64
			privNonce   uint64
			ct64        []byte
		)
		if ctHex := ctx.String(privCiphertextFlag.Name); ctHex != "" {
			ct64, err = decodeHexArg("ct", ctHex, 64)
			if err != nil {
				return err
			}
			source = "flag"
		} else {
			result, err := fetchPrivBalanceRPC(ctx.Context, ctx.String(rpcURLFlag.Name), pubkey)
			if err != nil {
				return fmt.Errorf("tos_privGetBalance failed: %w", err)
			}
			ct64 = make([]byte, 64)
			copy(ct64[:32], result.Commitment)
			copy(ct64[32:], result.Handle)
			source = "rpc"
			blockNumber = uint64(result.BlockNumber)
			version = uint64(result.Version)
			privNonce = uint64(result.PrivNonce)
		}

		msgPoint, err := cryptopriv.DecryptToPoint(privkey[:], ct64)
		if err != nil {
			return fmt.Errorf("failed to decrypt ciphertext: %w", err)
		}
		maxBalance := ctx.Uint64(privMaxBalanceFlag.Name)

		var table *ecdlptable.Table
		if tablePath := ctx.String(privTableFlag.Name); tablePath != "" {
			table, err = ecdlptable.Load(tablePath)
			if err != nil {
				return fmt.Errorf("failed to load BSGS table: %w", err)
			}
		}

		plaintextBalance, ok, err := cryptopriv.SolveDiscreteLogWithTable(table, msgPoint, maxBalance)
		if err != nil {
			return fmt.Errorf("failed to solve plaintext balance: %w", err)
		}
		if !ok {
			return fmt.Errorf("plaintext balance exceeds --max-balance=%d", maxBalance)
		}

		out := outputPrivBalance{
			Address:          address.Hex(),
			Pubkey:           hex.EncodeToString(pubkey[:]),
			Ciphertext:       hex.EncodeToString(ct64),
			Commitment:       hex.EncodeToString(ct64[:32]),
			Handle:           hex.EncodeToString(ct64[32:]),
			PlaintextBalance: plaintextBalance,
			MaxBalance:       maxBalance,
			Version:          version,
			PrivNonce:        privNonce,
			BlockNumber:      blockNumber,
			Source:           source,
		}
		if ctx.Bool(jsonFlag.Name) {
			mustPrintJSON(out)
		} else {
			fmt.Println("Address:", out.Address)
			fmt.Println("Pubkey:", out.Pubkey)
			fmt.Println("Ciphertext:", out.Ciphertext)
			fmt.Printf("Plaintext balance: %d.%02d UNO\n", out.PlaintextBalance/100, out.PlaintextBalance%100)
			fmt.Println("Plaintext balance (raw):", out.PlaintextBalance)
			fmt.Println("Search bound:", out.MaxBalance)
			fmt.Println("Source:", out.Source)
			if source == "rpc" {
				fmt.Println("Version:", out.Version)
				fmt.Println("Priv nonce:", out.PrivNonce)
				fmt.Println("Block number:", out.BlockNumber)
			}
		}
		return nil
	},
}

func loadElgamalKeyfile(ctx *cli.Context, keyfilePath string) (common.Address, [32]byte, [32]byte, error) {
	var pubkey, privkey [32]byte

	keyjson, err := os.ReadFile(keyfilePath)
	if err != nil {
		return common.Address{}, pubkey, privkey, fmt.Errorf("failed to read keyfile %q: %w", keyfilePath, err)
	}
	key, err := keystore.DecryptKey(keyjson, getPassphrase(ctx, false))
	if err != nil {
		return common.Address{}, pubkey, privkey, fmt.Errorf("error decrypting key: %w", err)
	}
	signerType, err := accountsigner.CanonicalSignerType(key.SignerType)
	if err != nil {
		return common.Address{}, pubkey, privkey, fmt.Errorf("unsupported signer type in keyfile: %w", err)
	}
	if signerType != accountsigner.SignerTypeElgamal {
		return common.Address{}, pubkey, privkey, fmt.Errorf("keyfile signer type must be elgamal, got %s", signerType)
	}
	if len(key.ElgamalPrivateKey) != 32 {
		return common.Address{}, pubkey, privkey, fmt.Errorf("invalid elgamal private key size: %d", len(key.ElgamalPrivateKey))
	}
	copy(privkey[:], key.ElgamalPrivateKey)
	pubkeyBytes, err := accountsigner.PublicKeyFromElgamalPrivate(key.ElgamalPrivateKey)
	if err != nil {
		return common.Address{}, pubkey, privkey, fmt.Errorf("failed to derive elgamal public key: %w", err)
	}
	copy(pubkey[:], pubkeyBytes)
	return key.Address, pubkey, privkey, nil
}

func writeElgamalKeyfile(ctx *cli.Context, keyfilePath string, address common.Address, privkey []byte) error {
	keyID, err := uuid.NewRandom()
	if err != nil {
		return fmt.Errorf("failed to generate key uuid: %w", err)
	}
	key := &keystore.Key{
		Id:                keyID,
		Address:           address,
		SignerType:        accountsigner.SignerTypeElgamal,
		ElgamalPrivateKey: append([]byte(nil), privkey...),
	}

	scryptN, scryptP := keystore.StandardScryptN, keystore.StandardScryptP
	if ctx.Bool(lightKDFFlag.Name) {
		scryptN, scryptP = keystore.LightScryptN, keystore.LightScryptP
	}
	keyjson, err := keystore.EncryptKey(key, getPassphrase(ctx, true), scryptN, scryptP)
	if err != nil {
		return fmt.Errorf("error encrypting key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyfilePath), 0700); err != nil {
		return fmt.Errorf("could not create directory %s: %w", filepath.Dir(keyfilePath), err)
	}
	if err := os.WriteFile(keyfilePath, keyjson, 0600); err != nil {
		return fmt.Errorf("failed to write keyfile to %s: %w", keyfilePath, err)
	}
	return nil
}

func fetchPrivBalanceRPC(ctx context.Context, endpoint string, pubkey [32]byte) (*rpcPrivBalanceResult, error) {
	client, err := rpc.DialContext(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var result rpcPrivBalanceResult
	if err := client.CallContext(ctx, &result, "tos_privGetBalance", hexutil.Bytes(pubkey[:])); err != nil {
		return nil, err
	}
	return &result, nil
}

func decodeHexArg(name, value string, wantLen int) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
		trimmed = trimmed[2:]
	}
	raw, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("--%s must be valid hex: %w", name, err)
	}
	if len(raw) != wantLen {
		return nil, fmt.Errorf("--%s must be %d bytes hex", name, wantLen)
	}
	return raw, nil
}
