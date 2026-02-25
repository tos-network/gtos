package main

import (
	"encoding/hex"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/crypto"
)

func TestDeriveECDSAFromMnemonicKnownVector(t *testing.T) {
	mnemonic := "test test test test test test test test test test test junk"
	priv, err := deriveECDSAFromMnemonic(mnemonic, "", "m/44'/60'/0'/0/0")
	if err != nil {
		t.Fatalf("derive mnemonic failed: %v", err)
	}
	got := hex.EncodeToString(crypto.FromECDSA(priv))
	want := "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	if got != want {
		t.Fatalf("unexpected private key: have %s want %s", got, want)
	}
}

func TestGenerateMnemonicBitsValidation(t *testing.T) {
	if _, err := generateMnemonic(129); err == nil {
		t.Fatalf("expected invalid mnemonic bits error")
	}
	if _, err := generateMnemonic(128); err != nil {
		t.Fatalf("expected valid mnemonic bits, got %v", err)
	}
}

func TestDeriveECDSAFromMnemonicInvalidPath(t *testing.T) {
	mnemonic := "test test test test test test test test test test test junk"
	if _, err := deriveECDSAFromMnemonic(mnemonic, "", "m/44'//0"); err == nil {
		t.Fatalf("expected invalid path error")
	}
}

func TestDeriveElgamalFromMnemonicDeterministic(t *testing.T) {
	mnemonic := "test test test test test test test test test test test junk"
	first, err := deriveElgamalPrivateFromMnemonic(mnemonic, "", "m/44'/60'/0'/0/0")
	if err != nil {
		t.Fatalf("derive elgamal failed: %v", err)
	}
	second, err := deriveElgamalPrivateFromMnemonic(mnemonic, "", "m/44'/60'/0'/0/0")
	if err != nil {
		t.Fatalf("derive elgamal failed: %v", err)
	}
	if hex.EncodeToString(first) != hex.EncodeToString(second) {
		t.Fatalf("elgamal derivation is not deterministic")
	}
}

func TestDeriveEd25519FromMnemonicDeterministic(t *testing.T) {
	mnemonic := "test test test test test test test test test test test junk"
	first, err := deriveEd25519PrivateFromMnemonic(mnemonic, "", "m/44'/60'/0'/0/0")
	if err != nil {
		t.Fatalf("derive ed25519 failed: %v", err)
	}
	second, err := deriveEd25519PrivateFromMnemonic(mnemonic, "", "m/44'/60'/0'/0/0")
	if err != nil {
		t.Fatalf("derive ed25519 failed: %v", err)
	}
	if hex.EncodeToString(first.Seed()) != hex.EncodeToString(second.Seed()) {
		t.Fatalf("ed25519 derivation is not deterministic")
	}
}

func TestDeriveBLS12381FromMnemonicDeterministic(t *testing.T) {
	mnemonic := "test test test test test test test test test test test junk"
	first, err := deriveBLS12381PrivateFromMnemonic(mnemonic, "", "m/44'/60'/0'/0/0")
	if err != nil {
		t.Fatalf("derive bls12-381 failed: %v", err)
	}
	second, err := deriveBLS12381PrivateFromMnemonic(mnemonic, "", "m/44'/60'/0'/0/0")
	if err != nil {
		t.Fatalf("derive bls12-381 failed: %v", err)
	}
	if hex.EncodeToString(first) != hex.EncodeToString(second) {
		t.Fatalf("bls12-381 derivation is not deterministic")
	}
	if _, err := accountsigner.PublicKeyFromBLS12381Private(first); err != nil {
		t.Fatalf("derived bls12-381 key is invalid: %v", err)
	}
}
