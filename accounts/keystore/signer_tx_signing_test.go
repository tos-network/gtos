package keystore

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
)

func newSignerTxForWallet(from common.Address, signerType string) *types.Transaction {
	to := common.HexToAddress("0x00000000000000000000000000000000000000f1")
	return types.NewTx(&types.SignerTx{
		ChainID:    big.NewInt(1),
		Nonce:      0,
		To:         &to,
		Value:      big.NewInt(1),
		Gas:        21000,
		GasPrice:   big.NewInt(1),
		From:       from,
		SignerType: signerType,
	})
}

func p256PubFromScalar(d *big.Int) []byte {
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	return elliptic.Marshal(elliptic.P256(), x, y)
}

func ed25519PubFromKey(priv ed25519.PrivateKey) []byte {
	return append([]byte(nil), priv.Public().(ed25519.PublicKey)...)
}

func TestKeyStoreSignTxSignerTxSecp256r1(t *testing.T) {
	_, ks := tmpKeyStore(t, true)
	passphrase := "pass"
	acc, err := ks.NewAccount(passphrase)
	if err != nil {
		t.Fatalf("new account failed: %v", err)
	}
	if err := ks.Unlock(acc, passphrase); err != nil {
		t.Fatalf("unlock failed: %v", err)
	}
	tx := newSignerTxForWallet(acc.Address, accountsigner.SignerTypeSecp256r1)
	signed, err := ks.SignTx(acc, tx, big.NewInt(1))
	if err != nil {
		t.Fatalf("sign tx failed: %v", err)
	}
	ks.mu.RLock()
	unlocked := ks.unlocked[acc.Address]
	ks.mu.RUnlock()
	pub := p256PubFromScalar(unlocked.PrivateKey.D)
	signer := types.LatestSignerForChainID(big.NewInt(1))
	v, r, s := signed.RawSignatureValues()
	if v.Sign() != 0 {
		t.Fatalf("unexpected v: %d", v.Uint64())
	}
	if !accountsigner.VerifyRawSignature(accountsigner.SignerTypeSecp256r1, pub, signer.Hash(signed), r, s) {
		t.Fatal("signature verification failed")
	}
}

func TestKeyStoreSignTxWithPassphraseSignerTxSecp256r1(t *testing.T) {
	_, ks := tmpKeyStore(t, true)
	passphrase := "pass"
	acc, err := ks.NewAccount(passphrase)
	if err != nil {
		t.Fatalf("new account failed: %v", err)
	}
	tx := newSignerTxForWallet(acc.Address, accountsigner.SignerTypeSecp256r1)
	signed, err := ks.SignTxWithPassphrase(acc, passphrase, tx, big.NewInt(1))
	if err != nil {
		t.Fatalf("sign tx with passphrase failed: %v", err)
	}
	a, key, err := ks.getDecryptedKey(acc, passphrase)
	if err != nil {
		t.Fatalf("decrypt key failed: %v", err)
	}
	defer zeroKey(key.PrivateKey)
	if a.Address != acc.Address {
		t.Fatalf("resolved account mismatch: have=%s want=%s", a.Address.Hex(), acc.Address.Hex())
	}
	pub := p256PubFromScalar(key.PrivateKey.D)
	signer := types.LatestSignerForChainID(big.NewInt(1))
	v, r, s := signed.RawSignatureValues()
	if v.Sign() != 0 {
		t.Fatalf("unexpected v: %d", v.Uint64())
	}
	if !accountsigner.VerifyRawSignature(accountsigner.SignerTypeSecp256r1, pub, signer.Hash(signed), r, s) {
		t.Fatal("signature verification failed")
	}
}

func TestKeyStoreSignTxSignerTxEd25519(t *testing.T) {
	_, ks := tmpKeyStore(t, true)
	passphrase := "pass"
	acc, err := ks.NewEd25519Account(passphrase)
	if err != nil {
		t.Fatalf("new account failed: %v", err)
	}
	if err := ks.Unlock(acc, passphrase); err != nil {
		t.Fatalf("unlock failed: %v", err)
	}
	tx := newSignerTxForWallet(acc.Address, accountsigner.SignerTypeEd25519)
	signed, err := ks.SignTx(acc, tx, big.NewInt(1))
	if err != nil {
		t.Fatalf("sign tx failed: %v", err)
	}
	ks.mu.RLock()
	unlocked := ks.unlocked[acc.Address]
	ks.mu.RUnlock()
	pub := ed25519PubFromKey(unlocked.Ed25519PrivateKey)
	signer := types.LatestSignerForChainID(big.NewInt(1))
	v, r, s := signed.RawSignatureValues()
	if v.Sign() != 0 {
		t.Fatalf("unexpected v: %d", v.Uint64())
	}
	if !accountsigner.VerifyRawSignature(accountsigner.SignerTypeEd25519, pub, signer.Hash(signed), r, s) {
		t.Fatal("signature verification failed")
	}
}

func TestKeyStoreSignTxWithPassphraseSignerTxEd25519(t *testing.T) {
	_, ks := tmpKeyStore(t, true)
	passphrase := "pass"
	acc, err := ks.NewEd25519Account(passphrase)
	if err != nil {
		t.Fatalf("new account failed: %v", err)
	}
	tx := newSignerTxForWallet(acc.Address, accountsigner.SignerTypeEd25519)
	signed, err := ks.SignTxWithPassphrase(acc, passphrase, tx, big.NewInt(1))
	if err != nil {
		t.Fatalf("sign tx with passphrase failed: %v", err)
	}
	a, key, err := ks.getDecryptedKey(acc, passphrase)
	if err != nil {
		t.Fatalf("decrypt key failed: %v", err)
	}
	defer zeroKey(key.PrivateKey)
	if a.Address != acc.Address {
		t.Fatalf("resolved account mismatch: have=%s want=%s", a.Address.Hex(), acc.Address.Hex())
	}
	pub := ed25519PubFromKey(key.Ed25519PrivateKey)
	signer := types.LatestSignerForChainID(big.NewInt(1))
	v, r, s := signed.RawSignatureValues()
	if v.Sign() != 0 {
		t.Fatalf("unexpected v: %d", v.Uint64())
	}
	if !accountsigner.VerifyRawSignature(accountsigner.SignerTypeEd25519, pub, signer.Hash(signed), r, s) {
		t.Fatal("signature verification failed")
	}
}

func TestKeyStoreSignTxSignerTxBLS12381(t *testing.T) {
	_, ks := tmpKeyStore(t, true)
	passphrase := "pass"
	acc, err := ks.NewBLS12381Account(passphrase)
	if err != nil {
		t.Fatalf("new account failed: %v", err)
	}
	if err := ks.Unlock(acc, passphrase); err != nil {
		t.Fatalf("unlock failed: %v", err)
	}
	tx := newSignerTxForWallet(acc.Address, accountsigner.SignerTypeBLS12381)
	signed, err := ks.SignTx(acc, tx, big.NewInt(1))
	if err != nil {
		t.Fatalf("sign tx failed: %v", err)
	}
	ks.mu.RLock()
	unlocked := ks.unlocked[acc.Address]
	ks.mu.RUnlock()
	pub, err := accountsigner.PublicKeyFromBLS12381Private(unlocked.BLS12381PrivateKey)
	if err != nil {
		t.Fatalf("derive bls public key failed: %v", err)
	}
	signer := types.LatestSignerForChainID(big.NewInt(1))
	v, r, s := signed.RawSignatureValues()
	if v.Sign() != 0 {
		t.Fatalf("unexpected v: %d", v.Uint64())
	}
	if !accountsigner.VerifyRawSignature(accountsigner.SignerTypeBLS12381, pub, signer.Hash(signed), r, s) {
		t.Fatal("signature verification failed")
	}
}

func TestKeyStoreSignTxWithPassphraseSignerTxBLS12381(t *testing.T) {
	_, ks := tmpKeyStore(t, true)
	passphrase := "pass"
	acc, err := ks.NewBLS12381Account(passphrase)
	if err != nil {
		t.Fatalf("new account failed: %v", err)
	}
	tx := newSignerTxForWallet(acc.Address, accountsigner.SignerTypeBLS12381)
	signed, err := ks.SignTxWithPassphrase(acc, passphrase, tx, big.NewInt(1))
	if err != nil {
		t.Fatalf("sign tx with passphrase failed: %v", err)
	}
	a, key, err := ks.getDecryptedKey(acc, passphrase)
	if err != nil {
		t.Fatalf("decrypt key failed: %v", err)
	}
	defer zeroKeyMaterial(key)
	if a.Address != acc.Address {
		t.Fatalf("resolved account mismatch: have=%s want=%s", a.Address.Hex(), acc.Address.Hex())
	}
	pub, err := accountsigner.PublicKeyFromBLS12381Private(key.BLS12381PrivateKey)
	if err != nil {
		t.Fatalf("derive bls public key failed: %v", err)
	}
	signer := types.LatestSignerForChainID(big.NewInt(1))
	v, r, s := signed.RawSignatureValues()
	if v.Sign() != 0 {
		t.Fatalf("unexpected v: %d", v.Uint64())
	}
	if !accountsigner.VerifyRawSignature(accountsigner.SignerTypeBLS12381, pub, signer.Hash(signed), r, s) {
		t.Fatal("signature verification failed")
	}
}
