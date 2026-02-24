package keystore

import (
	"crypto/ed25519"
	"testing"

	"github.com/tos-network/gtos/accounts"
	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
)

func TestKeyStoreSignDPoSHashEd25519(t *testing.T) {
	dir := t.TempDir()
	ks := NewKeyStore(dir, veryLightScryptN, veryLightScryptP)
	passphrase := "passphrase"

	acc, err := ks.NewEd25519Account(passphrase)
	if err != nil {
		t.Fatalf("NewEd25519Account: %v", err)
	}
	if err := ks.Unlock(acc, passphrase); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer ks.Lock(acc.Address)

	digest := common.HexToHash("0x1234").Bytes()
	seal, err := ks.SignDPoSHash(acc, digest)
	if err != nil {
		t.Fatalf("SignDPoSHash: %v", err)
	}
	if len(seal) != ed25519.PublicKeySize+ed25519.SignatureSize {
		t.Fatalf("unexpected ed25519 DPoS seal length: have=%d want=%d", len(seal), ed25519.PublicKeySize+ed25519.SignatureSize)
	}
	pub := ed25519.PublicKey(seal[:ed25519.PublicKeySize])
	sig := seal[ed25519.PublicKeySize:]
	if !ed25519.Verify(pub, digest, sig) {
		t.Fatal("ed25519 DPoS signature verification failed")
	}
	addr, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeEd25519, pub)
	if err != nil {
		t.Fatalf("AddressFromSigner: %v", err)
	}
	if addr != acc.Address {
		t.Fatalf("unexpected derived address: have=%s want=%s", addr.Hex(), acc.Address.Hex())
	}
}

func TestKeyStoreSignDPoSHashSecp256k1(t *testing.T) {
	dir := t.TempDir()
	ks := NewKeyStore(dir, veryLightScryptN, veryLightScryptP)
	passphrase := "passphrase"

	acc, err := ks.NewAccount(passphrase)
	if err != nil {
		t.Fatalf("NewAccount: %v", err)
	}
	if err := ks.Unlock(acc, passphrase); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer ks.Lock(acc.Address)

	digest := common.HexToHash("0xabcd").Bytes()
	seal, err := ks.SignDPoSHash(acc, digest)
	if err != nil {
		t.Fatalf("SignDPoSHash: %v", err)
	}
	if len(seal) != crypto.SignatureLength {
		t.Fatalf("unexpected secp256k1 DPoS seal length: have=%d want=%d", len(seal), crypto.SignatureLength)
	}

	wallet := ks.Wallets()[0]
	reSeal, err := wallet.SignData(accounts.Account{Address: acc.Address}, accounts.MimetypeDPoS, digest)
	if err != nil {
		t.Fatalf("wallet.SignData(DPoS): %v", err)
	}
	if len(reSeal) != crypto.SignatureLength {
		t.Fatalf("unexpected wallet DPoS seal length: have=%d want=%d", len(reSeal), crypto.SignatureLength)
	}
}
