package main

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/btcec/v2"
	btcschnorr "github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/tos-network/gtos/accounts/keystore"
	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/cmd/utils"
	"github.com/tos-network/gtos/crypto"
	ed25519 "github.com/tos-network/gtos/crypto/ed25519"
	"github.com/urfave/cli/v2"
)

type outputInspect struct {
	Address    string
	SignerType string
	PublicKey  string
	PrivateKey string
}

var (
	privateFlag = &cli.BoolFlag{
		Name:  "private",
		Usage: "include the private key in the output",
	}
)

var commandInspect = &cli.Command{
	Name:      "inspect",
	Usage:     "inspect a keyfile",
	ArgsUsage: "<keyfile>",
	Description: `
Print various information about the keyfile.

Private key information can be printed by using the --private flag;
make sure to use this feature with great caution!`,
	Flags: []cli.Flag{
		passphraseFlag,
		jsonFlag,
		privateFlag,
	},
	Action: func(ctx *cli.Context) error {
		keyfilepath := ctx.Args().First()

		// Read key from file.
		keyjson, err := os.ReadFile(keyfilepath)
		if err != nil {
			utils.Fatalf("Failed to read the keyfile at '%s': %v", keyfilepath, err)
		}

		// Decrypt key with passphrase.
		passphrase := getPassphrase(ctx, false)
		key, err := keystore.DecryptKey(keyjson, passphrase)
		if err != nil {
			utils.Fatalf("Error decrypting key: %v", err)
		}

		showPrivate := ctx.Bool(privateFlag.Name)
		signerType, err := accountsigner.CanonicalSignerType(key.SignerType)
		if err != nil {
			utils.Fatalf("Unsupported signer type in keyfile: %v", err)
		}
		var publicKey []byte
		switch signerType {
		case accountsigner.SignerTypeSecp256k1:
			if key.PrivateKey == nil {
				utils.Fatalf("Missing ECDSA private key material")
			}
			publicKey = crypto.FromECDSAPub(&key.PrivateKey.PublicKey)
		case accountsigner.SignerTypeSecp256r1:
			if key.PrivateKey == nil || key.PrivateKey.PublicKey.X == nil || key.PrivateKey.PublicKey.Y == nil {
				utils.Fatalf("Missing secp256r1 private key material")
			}
			publicKey = elliptic.Marshal(elliptic.P256(), key.PrivateKey.PublicKey.X, key.PrivateKey.PublicKey.Y)
		case accountsigner.SignerTypeSchnorr:
			if key.PrivateKey == nil {
				utils.Fatalf("Missing schnorr private key material")
			}
			schnorrPriv, _ := btcec.PrivKeyFromBytes(crypto.FromECDSA(key.PrivateKey))
			publicKey = btcschnorr.SerializePubKey(schnorrPriv.PubKey())
		case accountsigner.SignerTypeEd25519:
			pub, ok := key.Ed25519PrivateKey.Public().(ed25519.PublicKey)
			if !ok {
				utils.Fatalf("Failed to derive ed25519 public key")
			}
			publicKey = append([]byte(nil), pub...)
		case accountsigner.SignerTypeBLS12381:
			publicKey, err = accountsigner.PublicKeyFromBLS12381Private(key.BLS12381PrivateKey)
			if err != nil {
				utils.Fatalf("Failed to derive bls12-381 public key: %v", err)
			}
		case accountsigner.SignerTypeElgamal:
			publicKey, err = accountsigner.PublicKeyFromElgamalPrivate(key.ElgamalPrivateKey)
			if err != nil {
				utils.Fatalf("Failed to derive elgamal public key: %v", err)
			}
		default:
			utils.Fatalf("Unsupported signer type in keyfile: %s", signerType)
		}
		out := outputInspect{
			Address:    key.Address.Hex(),
			SignerType: signerType,
			PublicKey:  hex.EncodeToString(publicKey),
		}
		if showPrivate {
			switch signerType {
			case accountsigner.SignerTypeSecp256k1, accountsigner.SignerTypeSchnorr, accountsigner.SignerTypeSecp256r1:
				out.PrivateKey = hex.EncodeToString(crypto.FromECDSA(key.PrivateKey))
			case accountsigner.SignerTypeEd25519:
				out.PrivateKey = hex.EncodeToString(key.Ed25519PrivateKey.Seed())
			case accountsigner.SignerTypeBLS12381:
				out.PrivateKey = hex.EncodeToString(key.BLS12381PrivateKey)
			case accountsigner.SignerTypeElgamal:
				out.PrivateKey = hex.EncodeToString(key.ElgamalPrivateKey)
			}
		}

		if ctx.Bool(jsonFlag.Name) {
			mustPrintJSON(out)
		} else {
			fmt.Println("Address:       ", out.Address)
			fmt.Println("Signer type:   ", out.SignerType)
			fmt.Println("Public key:    ", out.PublicKey)
			if showPrivate {
				fmt.Println("Private key:   ", out.PrivateKey)
			}
		}
		return nil
	},
}
