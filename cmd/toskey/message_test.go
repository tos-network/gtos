package main

import (
	"path/filepath"
	"testing"
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
