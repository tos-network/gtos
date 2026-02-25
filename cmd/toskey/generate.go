package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	btcschnorr "github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/google/uuid"
	"github.com/tos-network/gtos/accounts/keystore"
	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/cmd/utils"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	ed25519 "github.com/tos-network/gtos/crypto/ed25519"
	"github.com/urfave/cli/v2"
)

type outputGenerate struct {
	Address        string `json:"address"`
	SignerType     string `json:"signerType"`
	DerivationPath string `json:"derivationPath,omitempty"`
	Mnemonic       string `json:"mnemonic,omitempty"`
}

var (
	privateKeyFlag = &cli.StringFlag{
		Name:  "privatekey",
		Usage: "file containing a raw private key to encrypt",
	}
	lightKDFFlag = &cli.BoolFlag{
		Name:  "lightkdf",
		Usage: "use less secure scrypt parameters",
	}
	signerTypeFlag = &cli.StringFlag{
		Name:  "signer",
		Usage: "Signer algorithm for generated key (`secp256k1` default, supports `schnorr`, `secp256r1`, `ed25519`, `bls12-381`, `elgamal`)",
	}
	mnemonicGenerateFlag = &cli.BoolFlag{
		Name:  "mnemonic-generate",
		Usage: "Generate a BIP39 mnemonic and derive key using --hd-path",
	}
	mnemonicFlag = &cli.StringFlag{
		Name:  "mnemonic",
		Usage: "Use existing BIP39 mnemonic to derive the key",
	}
	mnemonicPassphraseFlag = &cli.StringFlag{
		Name:  "mnemonic-passphrase",
		Usage: "Optional BIP39 passphrase for mnemonic-to-seed",
	}
	mnemonicBitsFlag = &cli.IntFlag{
		Name:  "mnemonic-bits",
		Usage: "Entropy bits for generated mnemonic (128,160,192,224,256)",
		Value: defaultMnemonicBits,
	}
	hdPathFlag = &cli.StringFlag{
		Name:  "hd-path",
		Usage: "Derivation path used with mnemonic flow",
		Value: defaultHDPath,
	}
)

var commandGenerate = &cli.Command{
	Name:      "generate",
	Usage:     "generate new keyfile",
	ArgsUsage: "[ <keyfile> ]",
	Description: `
Generate a new keyfile.

If you want to encrypt an existing private key, it can be specified by setting
--privatekey with the location of the file containing the private key.
`,
	Flags: []cli.Flag{
		passphraseFlag,
		jsonFlag,
		privateKeyFlag,
		lightKDFFlag,
		signerTypeFlag,
		mnemonicGenerateFlag,
		mnemonicFlag,
		mnemonicPassphraseFlag,
		mnemonicBitsFlag,
		hdPathFlag,
	},
	Action: func(ctx *cli.Context) error {
		// Check if keyfile path given and make sure it doesn't already exist.
		keyfilepath := ctx.Args().First()
		if keyfilepath == "" {
			keyfilepath = defaultKeyfileName
		}
		if _, err := os.Stat(keyfilepath); err == nil {
			utils.Fatalf("Keyfile already exists at %s.", keyfilepath)
		} else if !os.IsNotExist(err) {
			utils.Fatalf("Error checking if keyfile exists: %v", err)
		}

		requestedSignerType := ctx.String(signerTypeFlag.Name)
		if requestedSignerType == "" {
			requestedSignerType = accountsigner.SignerTypeSecp256k1
		}
		signerType, err := accountsigner.CanonicalSignerType(requestedSignerType)
		if err != nil {
			utils.Fatalf("Unsupported signer type %q", requestedSignerType)
		}
		switch signerType {
		case accountsigner.SignerTypeSecp256k1, accountsigner.SignerTypeSchnorr, accountsigner.SignerTypeSecp256r1, accountsigner.SignerTypeEd25519, accountsigner.SignerTypeBLS12381, accountsigner.SignerTypeElgamal:
		default:
			utils.Fatalf("Signer type %q is not supported by toskey generate", signerType)
		}

		var (
			privateKey      *ecdsa.PrivateKey
			ed25519Priv     ed25519.PrivateKey
			blsPriv         []byte
			elgamalPriv     []byte
			derivationPath  string
			mnemonicOutput  string
			mnemonicInput   = strings.TrimSpace(ctx.String(mnemonicFlag.Name))
			mnemonicMode    = mnemonicInput != "" || ctx.Bool(mnemonicGenerateFlag.Name)
			mnemonicGenFlow = false
		)
		if file := ctx.String(privateKeyFlag.Name); file != "" {
			if mnemonicMode {
				utils.Fatalf("Can't use --privatekey with mnemonic flags")
			}
			rawPriv, loadErr := loadRawPrivateKeyHex(file)
			if loadErr != nil {
				utils.Fatalf("Can't load private key: %v", loadErr)
			}
			switch signerType {
			case accountsigner.SignerTypeSecp256k1, accountsigner.SignerTypeSchnorr:
				privateKey, err = crypto.ToECDSA(rawPriv)
				if err != nil {
					utils.Fatalf("Invalid %s private key: %v", signerType, err)
				}
			case accountsigner.SignerTypeSecp256r1:
				privateKey, err = secp256r1PrivateFromBytes(rawPriv)
				if err != nil {
					utils.Fatalf("Invalid secp256r1 private key: %v", err)
				}
			case accountsigner.SignerTypeEd25519:
				ed25519Priv, err = ed25519PrivateFromBytes(rawPriv)
				if err != nil {
					utils.Fatalf("Invalid ed25519 private key: %v", err)
				}
			case accountsigner.SignerTypeBLS12381:
				if _, err := accountsigner.PublicKeyFromBLS12381Private(rawPriv); err != nil {
					utils.Fatalf("Invalid bls12-381 private key: %v", err)
				}
				blsPriv = append([]byte(nil), rawPriv...)
			case accountsigner.SignerTypeElgamal:
				if _, err := accountsigner.PublicKeyFromElgamalPrivate(rawPriv); err != nil {
					utils.Fatalf("Invalid elgamal private key: %v", err)
				}
				elgamalPriv = append([]byte(nil), rawPriv...)
			}
		} else if mnemonicMode {
			if mnemonicInput == "" {
				mnemonicInput, err = generateMnemonic(ctx.Int(mnemonicBitsFlag.Name))
				if err != nil {
					utils.Fatalf("Failed to generate mnemonic: %v", err)
				}
				mnemonicOutput = mnemonicInput
				mnemonicGenFlow = true
			}
			derivationPath = ctx.String(hdPathFlag.Name)
			switch signerType {
			case accountsigner.SignerTypeEd25519:
				ed25519Priv, err = deriveEd25519PrivateFromMnemonic(mnemonicInput, ctx.String(mnemonicPassphraseFlag.Name), derivationPath)
				if err != nil {
					utils.Fatalf("Failed to derive ed25519 private key from mnemonic: %v", err)
				}
			case accountsigner.SignerTypeBLS12381:
				blsPriv, err = deriveBLS12381PrivateFromMnemonic(mnemonicInput, ctx.String(mnemonicPassphraseFlag.Name), derivationPath)
				if err != nil {
					utils.Fatalf("Failed to derive bls12-381 private key from mnemonic: %v", err)
				}
			case accountsigner.SignerTypeElgamal:
				elgamalPriv, err = deriveElgamalPrivateFromMnemonic(mnemonicInput, ctx.String(mnemonicPassphraseFlag.Name), derivationPath)
				if err != nil {
					utils.Fatalf("Failed to derive elgamal private key from mnemonic: %v", err)
				}
			case accountsigner.SignerTypeSecp256r1:
				privateKey, err = deriveECDSAFromMnemonic(mnemonicInput, ctx.String(mnemonicPassphraseFlag.Name), derivationPath)
				if err != nil {
					utils.Fatalf("Failed to derive private key from mnemonic: %v", err)
				}
				privateKey, err = secp256r1PrivateFromECDSA(privateKey)
				if err != nil {
					utils.Fatalf("Failed to convert mnemonic key to secp256r1: %v", err)
				}
			default:
				privateKey, err = deriveECDSAFromMnemonic(mnemonicInput, ctx.String(mnemonicPassphraseFlag.Name), derivationPath)
				if err != nil {
					utils.Fatalf("Failed to derive private key from mnemonic: %v", err)
				}
			}
		} else {
			// If not loaded, generate random key material per signer type.
			switch signerType {
			case accountsigner.SignerTypeSecp256k1, accountsigner.SignerTypeSchnorr:
				privateKey, err = crypto.GenerateKey()
			case accountsigner.SignerTypeSecp256r1:
				privateKey, err = ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
			case accountsigner.SignerTypeEd25519:
				_, ed25519Priv, err = ed25519.GenerateKey(crand.Reader)
			case accountsigner.SignerTypeBLS12381:
				blsPriv, err = accountsigner.GenerateBLS12381PrivateKey(crand.Reader)
			case accountsigner.SignerTypeElgamal:
				elgamalPriv, err = accountsigner.GenerateElgamalPrivateKey(crand.Reader)
			}
			if err != nil {
				utils.Fatalf("Failed to generate random private key: %v", err)
			}
		}

		// Create the keyfile object with a random UUID.
		UUID, err := uuid.NewRandom()
		if err != nil {
			utils.Fatalf("Failed to generate random uuid: %v", err)
		}

		var (
			address common.Address
			key     *keystore.Key
		)
		switch signerType {
		case accountsigner.SignerTypeSecp256k1:
			address = crypto.PubkeyToAddress(privateKey.PublicKey)
			key = &keystore.Key{
				Id:         UUID,
				Address:    address,
				SignerType: signerType,
				PrivateKey: privateKey,
			}
		case accountsigner.SignerTypeSchnorr:
			schnorrPriv, _ := btcec.PrivKeyFromBytes(crypto.FromECDSA(privateKey))
			schnorrPub := btcschnorr.SerializePubKey(schnorrPriv.PubKey())
			addr, addrErr := accountsigner.AddressFromSigner(accountsigner.SignerTypeSchnorr, schnorrPub)
			if addrErr != nil {
				utils.Fatalf("Failed to derive schnorr address: %v", addrErr)
			}
			address = addr
			key = &keystore.Key{
				Id:         UUID,
				Address:    address,
				SignerType: signerType,
				PrivateKey: privateKey,
			}
		case accountsigner.SignerTypeSecp256r1:
			pub := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
			addr, addrErr := accountsigner.AddressFromSigner(accountsigner.SignerTypeSecp256r1, pub)
			if addrErr != nil {
				utils.Fatalf("Failed to derive secp256r1 address: %v", addrErr)
			}
			address = addr
			key = &keystore.Key{
				Id:         UUID,
				Address:    address,
				SignerType: signerType,
				PrivateKey: privateKey,
			}
		case accountsigner.SignerTypeEd25519:
			pub, ok := ed25519Priv.Public().(ed25519.PublicKey)
			if !ok {
				utils.Fatalf("Failed to derive ed25519 public key")
			}
			addr, addrErr := accountsigner.AddressFromSigner(accountsigner.SignerTypeEd25519, pub)
			if addrErr != nil {
				utils.Fatalf("Failed to derive ed25519 address: %v", addrErr)
			}
			address = addr
			key = &keystore.Key{
				Id:                UUID,
				Address:           address,
				SignerType:        signerType,
				Ed25519PrivateKey: append(ed25519.PrivateKey(nil), ed25519Priv...),
			}
		case accountsigner.SignerTypeBLS12381:
			pub, pubErr := accountsigner.PublicKeyFromBLS12381Private(blsPriv)
			if pubErr != nil {
				utils.Fatalf("Failed to derive bls12-381 public key: %v", pubErr)
			}
			addr, addrErr := accountsigner.AddressFromSigner(accountsigner.SignerTypeBLS12381, pub)
			if addrErr != nil {
				utils.Fatalf("Failed to derive bls12-381 address: %v", addrErr)
			}
			address = addr
			key = &keystore.Key{
				Id:                 UUID,
				Address:            address,
				SignerType:         signerType,
				BLS12381PrivateKey: append([]byte(nil), blsPriv...),
			}
		case accountsigner.SignerTypeElgamal:
			pub, pubErr := accountsigner.PublicKeyFromElgamalPrivate(elgamalPriv)
			if pubErr != nil {
				utils.Fatalf("Failed to derive elgamal public key: %v", pubErr)
			}
			addr, addrErr := accountsigner.AddressFromSigner(accountsigner.SignerTypeElgamal, pub)
			if addrErr != nil {
				utils.Fatalf("Failed to derive elgamal address: %v", addrErr)
			}
			address = addr
			key = &keystore.Key{
				Id:                UUID,
				Address:           address,
				SignerType:        signerType,
				ElgamalPrivateKey: append([]byte(nil), elgamalPriv...),
			}
		default:
			utils.Fatalf("Signer type %q is not supported by toskey generate", signerType)
		}

		// Encrypt key with passphrase.
		passphrase := getPassphrase(ctx, true)
		scryptN, scryptP := keystore.StandardScryptN, keystore.StandardScryptP
		if ctx.Bool(lightKDFFlag.Name) {
			scryptN, scryptP = keystore.LightScryptN, keystore.LightScryptP
		}
		keyjson, err := keystore.EncryptKey(key, passphrase, scryptN, scryptP)
		if err != nil {
			utils.Fatalf("Error encrypting key: %v", err)
		}

		// Store the file to disk.
		if err := os.MkdirAll(filepath.Dir(keyfilepath), 0700); err != nil {
			utils.Fatalf("Could not create directory %s", filepath.Dir(keyfilepath))
		}
		if err := os.WriteFile(keyfilepath, keyjson, 0600); err != nil {
			utils.Fatalf("Failed to write keyfile to %s: %v", keyfilepath, err)
		}

		// Output some information.
		out := outputGenerate{
			Address:        key.Address.Hex(),
			SignerType:     signerType,
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

func secp256r1PrivateFromECDSA(key *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	if key == nil || key.D == nil {
		return nil, fmt.Errorf("missing ecdsa private key")
	}
	return secp256r1PrivateFromBytes(key.D.Bytes())
}

func secp256r1PrivateFromBytes(raw []byte) (*ecdsa.PrivateKey, error) {
	if len(raw) == 0 || len(raw) > 32 {
		return nil, fmt.Errorf("invalid secp256r1 private key size: %d", len(raw))
	}
	curve := elliptic.P256()
	d := new(big.Int).SetBytes(raw)
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, fmt.Errorf("invalid secp256r1 private scalar")
	}
	out := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve},
		D:         d,
	}
	out.PublicKey.X, out.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
	if out.PublicKey.X == nil || out.PublicKey.Y == nil {
		return nil, fmt.Errorf("invalid secp256r1 public key")
	}
	return out, nil
}

func ed25519PrivateFromBytes(raw []byte) (ed25519.PrivateKey, error) {
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(append([]byte(nil), raw...)), nil
	default:
		return nil, fmt.Errorf("invalid ed25519 private key size: %d", len(raw))
	}
}

func loadRawPrivateKeyHex(file string) ([]byte, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(content))
	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
		trimmed = trimmed[2:]
	}
	if trimmed == "" {
		return nil, fmt.Errorf("empty private key file")
	}
	raw, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid hex data for private key: %w", err)
	}
	return raw, nil
}
