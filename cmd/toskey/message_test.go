package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
)

func TestMessageSignVerify(t *testing.T) {
	tmpdir := t.TempDir()

	keyfile := filepath.Join(tmpdir, "the-keyfile")
	message := "test message"

	// Create the key.
	generate := runTOSkey(t, "generate", "--lightkdf", keyfile)
	generate.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Repeat password: {{.InputLine "foobar"}}
`)
	_, matches := generate.ExpectRegexp(`Address: (0x[0-9a-fA-F]{64})\nSigner type: secp256k1\n`)
	address := matches[1]
	generate.ExpectExit()

	// Sign a message.
	sign := runTOSkey(t, "signmessage", keyfile, message)
	sign.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
`)
	_, matches = sign.ExpectRegexp(`Signature: ([0-9a-f]+)\n`)
	signature := matches[1]
	sign.ExpectExit()

	// Verify the message.
	verify := runTOSkey(t, "verifymessage", address, signature, message)
	_, matches = verify.ExpectRegexp(`
Signature verification successful!
Recovered public key: [0-9a-f]+
Recovered address: (0x[0-9a-fA-F]{64})
`)
	recovered := matches[1]
	verify.ExpectExit()

	if recovered != address {
		t.Error("recovered address doesn't match generated key")
	}
}

func TestGenerateSchnorr(t *testing.T) {
	tmpdir := t.TempDir()
	keyfile := filepath.Join(tmpdir, "the-schnorr-keyfile")

	generate := runTOSkey(t, "generate", "--lightkdf", "--signer", "schnorr", keyfile)
	generate.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Repeat password: {{.InputLine "foobar"}}
`)
	generate.ExpectRegexp(`Address: 0x[0-9a-fA-F]{64}\nSigner type: schnorr\n`)
	generate.ExpectExit()
}

func TestGenerateFromMnemonicDeterministic(t *testing.T) {
	tmpdir := t.TempDir()
	keyfile := filepath.Join(tmpdir, "the-mnemonic-keyfile")
	mnemonic := "test test test test test test test test test test test junk"

	generate := runTOSkey(t, "generate", "--lightkdf", "--mnemonic", mnemonic, keyfile)
	generate.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Repeat password: {{.InputLine "foobar"}}
`)
	generate.ExpectRegexp(`Address: 0x[0-9a-fA-F]{64}\nSigner type: secp256k1\nDerivation path: m/44'/60'/0'/0/0\n`)
	generate.ExpectExit()

	inspect := runTOSkey(t, "inspect", "--private", keyfile)
	inspect.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
`)
	_, matches := inspect.ExpectRegexp(`Private key:\s+([0-9a-f]+)\n`)
	inspect.ExpectExit()

	const wantPriv = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	if got := matches[1]; got != wantPriv {
		t.Fatalf("unexpected derived private key: have %s want %s", got, wantPriv)
	}
}

func TestGenerateSecp256r1(t *testing.T) {
	tmpdir := t.TempDir()
	keyfile := filepath.Join(tmpdir, "the-secp256r1-keyfile")

	generate := runTOSkey(t, "generate", "--lightkdf", "--signer", "secp256r1", keyfile)
	generate.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Repeat password: {{.InputLine "foobar"}}
`)
	generate.ExpectRegexp(`Address: 0x[0-9a-fA-F]{64}\nSigner type: secp256r1\n`)
	generate.ExpectExit()

	inspect := runTOSkey(t, "inspect", "--private", keyfile)
	inspect.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
`)
	inspect.ExpectRegexp(`Signer type:\s+secp256r1\n`)
	inspect.ExpectRegexp(`Private key:\s+[0-9a-f]+\n`)
	inspect.ExpectExit()
}

func TestGenerateElgamal(t *testing.T) {
	tmpdir := t.TempDir()
	keyfile := filepath.Join(tmpdir, "the-elgamal-keyfile")

	generate := runTOSkey(t, "generate", "--lightkdf", "--signer", "elgamal", keyfile)
	generate.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Repeat password: {{.InputLine "foobar"}}
`)
	generate.ExpectRegexp(`Address: 0x[0-9a-fA-F]{64}\nSigner type: elgamal\n`)
	generate.ExpectExit()

	inspect := runTOSkey(t, "inspect", "--private", keyfile)
	inspect.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
`)
	inspect.ExpectRegexp(`Signer type:\s+elgamal\n`)
	inspect.ExpectRegexp(`Private key:\s+[0-9a-f]+\n`)
	inspect.ExpectExit()
}

func TestGenerateEd25519FromMnemonic(t *testing.T) {
	tmpdir := t.TempDir()
	keyfile := filepath.Join(tmpdir, "the-ed25519-mnemonic-keyfile")
	mnemonic := "test test test test test test test test test test test junk"

	generate := runTOSkey(t, "generate", "--lightkdf", "--signer", "ed25519", "--mnemonic", mnemonic, keyfile)
	generate.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Repeat password: {{.InputLine "foobar"}}
`)
	generate.ExpectRegexp(`Address: 0x[0-9a-fA-F]{64}\nSigner type: ed25519\nDerivation path: m/44'/60'/0'/0/0\n`)
	generate.ExpectExit()

	inspect := runTOSkey(t, "inspect", "--private", keyfile)
	inspect.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
`)
	inspect.ExpectRegexp(`Signer type:\s+ed25519\n`)
	inspect.ExpectRegexp(`Private key:\s+[0-9a-f]{64}\n`)
	inspect.ExpectExit()
}

func TestGenerateBLS12381FromMnemonic(t *testing.T) {
	tmpdir := t.TempDir()
	keyfile := filepath.Join(tmpdir, "the-bls12381-mnemonic-keyfile")
	mnemonic := "test test test test test test test test test test test junk"

	generate := runTOSkey(t, "generate", "--lightkdf", "--signer", "bls12-381", "--mnemonic", mnemonic, keyfile)
	generate.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Repeat password: {{.InputLine "foobar"}}
`)
	generate.ExpectRegexp(`Address: 0x[0-9a-fA-F]{64}\nSigner type: bls12-381\nDerivation path: m/44'/60'/0'/0/0\n`)
	generate.ExpectExit()

	inspect := runTOSkey(t, "inspect", "--private", keyfile)
	inspect.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
`)
	inspect.ExpectRegexp(`Signer type:\s+bls12-381\n`)
	inspect.ExpectRegexp(`Private key:\s+[0-9a-f]{64}\n`)
	inspect.ExpectExit()
}

func TestGenerateSecp256r1FromPrivateKeyFile(t *testing.T) {
	tmpdir := t.TempDir()
	rawKeyFile := filepath.Join(tmpdir, "raw-secp256r1.key")
	keyfile := filepath.Join(tmpdir, "secp256r1-from-raw")
	const rawPrivHex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	if err := os.WriteFile(rawKeyFile, []byte(rawPrivHex+"\n"), 0600); err != nil {
		t.Fatalf("write raw key file: %v", err)
	}

	generate := runTOSkey(t, "generate", "--lightkdf", "--signer", "secp256r1", "--privatekey", rawKeyFile, keyfile)
	generate.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Repeat password: {{.InputLine "foobar"}}
`)
	generate.ExpectRegexp(`Address: 0x[0-9a-fA-F]{64}\nSigner type: secp256r1\n`)
	generate.ExpectExit()

	inspect := runTOSkey(t, "inspect", "--private", keyfile)
	inspect.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
`)
	_, matches := inspect.ExpectRegexp(`Private key:\s+([0-9a-f]+)\n`)
	inspect.ExpectExit()
	if matches[1] != rawPrivHex {
		t.Fatalf("unexpected imported secp256r1 private key: have %s want %s", matches[1], rawPrivHex)
	}
}

func TestGenerateEd25519FromPrivateKeyFile(t *testing.T) {
	tmpdir := t.TempDir()
	rawKeyFile := filepath.Join(tmpdir, "raw-ed25519.key")
	keyfile := filepath.Join(tmpdir, "ed25519-from-raw")
	const seedHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	if err := os.WriteFile(rawKeyFile, []byte(seedHex+"\n"), 0600); err != nil {
		t.Fatalf("write raw key file: %v", err)
	}

	generate := runTOSkey(t, "generate", "--lightkdf", "--signer", "ed25519", "--privatekey", rawKeyFile, keyfile)
	generate.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Repeat password: {{.InputLine "foobar"}}
`)
	generate.ExpectRegexp(`Address: 0x[0-9a-fA-F]{64}\nSigner type: ed25519\n`)
	generate.ExpectExit()

	inspect := runTOSkey(t, "inspect", "--private", keyfile)
	inspect.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
`)
	_, matches := inspect.ExpectRegexp(`Private key:\s+([0-9a-f]+)\n`)
	inspect.ExpectExit()
	if matches[1] != seedHex {
		t.Fatalf("unexpected imported ed25519 private key: have %s want %s", matches[1], seedHex)
	}
}

func TestGenerateBLS12381FromPrivateKeyFile(t *testing.T) {
	tmpdir := t.TempDir()
	rawKeyFile := filepath.Join(tmpdir, "raw-bls.key")
	keyfile := filepath.Join(tmpdir, "bls-from-raw")
	raw, err := accountsigner.GenerateBLS12381PrivateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate bls key: %v", err)
	}
	rawHex := hex.EncodeToString(raw)
	if err := os.WriteFile(rawKeyFile, []byte("0x"+rawHex+"\n"), 0600); err != nil {
		t.Fatalf("write raw key file: %v", err)
	}

	generate := runTOSkey(t, "generate", "--lightkdf", "--signer", "bls12-381", "--privatekey", rawKeyFile, keyfile)
	generate.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Repeat password: {{.InputLine "foobar"}}
`)
	generate.ExpectRegexp(`Address: 0x[0-9a-fA-F]{64}\nSigner type: bls12-381\n`)
	generate.ExpectExit()

	inspect := runTOSkey(t, "inspect", "--private", keyfile)
	inspect.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
`)
	_, matches := inspect.ExpectRegexp(`Private key:\s+([0-9a-f]+)\n`)
	inspect.ExpectExit()
	if matches[1] != rawHex {
		t.Fatalf("unexpected imported bls12-381 private key: have %s want %s", matches[1], rawHex)
	}
}

func TestGenerateElgamalFromPrivateKeyFile(t *testing.T) {
	tmpdir := t.TempDir()
	rawKeyFile := filepath.Join(tmpdir, "raw-elgamal.key")
	keyfile := filepath.Join(tmpdir, "elgamal-from-raw")
	raw, err := accountsigner.GenerateElgamalPrivateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate elgamal key: %v", err)
	}
	rawHex := hex.EncodeToString(raw)
	if err := os.WriteFile(rawKeyFile, []byte(rawHex+"\n"), 0600); err != nil {
		t.Fatalf("write raw key file: %v", err)
	}

	generate := runTOSkey(t, "generate", "--lightkdf", "--signer", "elgamal", "--privatekey", rawKeyFile, keyfile)
	generate.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Repeat password: {{.InputLine "foobar"}}
`)
	generate.ExpectRegexp(`Address: 0x[0-9a-fA-F]{64}\nSigner type: elgamal\n`)
	generate.ExpectExit()

	inspect := runTOSkey(t, "inspect", "--private", keyfile)
	inspect.Expect(`
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
`)
	_, matches := inspect.ExpectRegexp(`Private key:\s+([0-9a-f]+)\n`)
	inspect.ExpectExit()
	if matches[1] != rawHex {
		t.Fatalf("unexpected imported elgamal private key: have %s want %s", matches[1], rawHex)
	}
}
