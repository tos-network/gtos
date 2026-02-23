package types

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/crypto/ristretto255"
	"github.com/tos-network/gtos/rlp"
	"golang.org/x/crypto/sha3"
)

func TestSignerTxSecp256r1SignatureEncoding64(t *testing.T) {
	signer := LatestSignerForChainID(big.NewInt(1))
	to := common.HexToAddress("0x0000000000000000000000000000000000000001")
	tx := NewTx(&SignerTx{
		ChainID:    big.NewInt(1),
		Nonce:      1,
		To:         &to,
		Value:      big.NewInt(1),
		Gas:        21000,
		GasPrice:   big.NewInt(1),
		From:       common.HexToAddress("0x0000000000000000000000000000000000000002"),
		SignerType: "secp256r1",
	})
	sig := make([]byte, 64)
	sig[31] = 0x11
	sig[63] = 0x22

	signed, err := tx.WithSignature(signer, sig)
	if err != nil {
		t.Fatalf("with signature failed: %v", err)
	}
	v, r, s := signed.RawSignatureValues()
	if v.Sign() != 0 {
		t.Fatalf("expected v=0 for 64-byte secp256r1 sig")
	}
	if r.Uint64() != 0x11 || s.Uint64() != 0x22 {
		t.Fatalf("unexpected r/s values")
	}
}

func TestSignerTxSecp256r1SignatureEncoding65(t *testing.T) {
	signer := LatestSignerForChainID(big.NewInt(1))
	to := common.HexToAddress("0x0000000000000000000000000000000000000001")
	tx := NewTx(&SignerTx{
		ChainID:    big.NewInt(1),
		Nonce:      2,
		To:         &to,
		Value:      big.NewInt(1),
		Gas:        21000,
		GasPrice:   big.NewInt(1),
		From:       common.HexToAddress("0x0000000000000000000000000000000000000002"),
		SignerType: "secp256r1",
	})
	sig := make([]byte, 65)
	sig[31] = 0x33
	sig[63] = 0x44
	sig[64] = 0x01

	signed, err := tx.WithSignature(signer, sig)
	if err != nil {
		t.Fatalf("with signature failed: %v", err)
	}
	v, r, s := signed.RawSignatureValues()
	if v.Uint64() != 1 {
		t.Fatalf("unexpected v: %d", v.Uint64())
	}
	if r.Uint64() != 0x33 || s.Uint64() != 0x44 {
		t.Fatalf("unexpected r/s values")
	}
}

func TestSignerTxBLS12381SignatureEncoding96(t *testing.T) {
	signer := LatestSignerForChainID(big.NewInt(1))
	to := common.HexToAddress("0x0000000000000000000000000000000000000001")
	tx := NewTx(&SignerTx{
		ChainID:    big.NewInt(1),
		Nonce:      2,
		To:         &to,
		Value:      big.NewInt(1),
		Gas:        21000,
		GasPrice:   big.NewInt(1),
		From:       common.HexToAddress("0x0000000000000000000000000000000000000002"),
		SignerType: "bls12-381",
	})
	sig := make([]byte, 96)
	sig[47] = 0x55
	sig[95] = 0x66

	signed, err := tx.WithSignature(signer, sig)
	if err != nil {
		t.Fatalf("with signature failed: %v", err)
	}
	v, r, s := signed.RawSignatureValues()
	if v.Sign() != 0 {
		t.Fatalf("unexpected v: %d", v.Uint64())
	}
	if r.Uint64() != 0x55 || s.Uint64() != 0x66 {
		t.Fatalf("unexpected r/s values")
	}
}

func TestSignerTxElgamalSignatureEncoding64(t *testing.T) {
	signer := LatestSignerForChainID(big.NewInt(1))
	to := common.HexToAddress("0x0000000000000000000000000000000000000001")
	tx := NewTx(&SignerTx{
		ChainID:    big.NewInt(1),
		Nonce:      5,
		To:         &to,
		Value:      big.NewInt(1),
		Gas:        21000,
		GasPrice:   big.NewInt(1),
		From:       common.HexToAddress("0x0000000000000000000000000000000000000002"),
		SignerType: "elgamal",
	})
	sig := make([]byte, 64)
	sig[31] = 0x77
	sig[63] = 0x88

	signed, err := tx.WithSignature(signer, sig)
	if err != nil {
		t.Fatalf("with signature failed: %v", err)
	}
	v, r, s := signed.RawSignatureValues()
	if v.Sign() != 0 {
		t.Fatalf("expected v=0 for 64-byte elgamal sig")
	}
	if r.Uint64() != 0x77 || s.Uint64() != 0x88 {
		t.Fatalf("unexpected r/s values")
	}
}

func TestSignerTxSignTxSecp256r1WithLocalECDSAKey(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult(key.D.Bytes())
	pub := elliptic.Marshal(curve, x, y)
	signer := LatestSignerForChainID(big.NewInt(1))
	to := common.HexToAddress("0x0000000000000000000000000000000000000001")
	tx := NewTx(&SignerTx{
		ChainID:    big.NewInt(1),
		Nonce:      3,
		To:         &to,
		Value:      big.NewInt(1),
		Gas:        21000,
		GasPrice:   big.NewInt(1),
		From:       common.HexToAddress("0x0000000000000000000000000000000000000002"),
		SignerType: "secp256r1",
	})
	signed, err := SignTx(tx, signer, key)
	if err != nil {
		t.Fatalf("sign tx failed: %v", err)
	}
	v, r, s := signed.RawSignatureValues()
	if v.Sign() != 0 {
		t.Fatalf("unexpected v: %d", v.Uint64())
	}
	hash := signer.Hash(signed)
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: curve, X: x, Y: y}, hash[:], r, s) {
		t.Fatal("signature verification failed")
	}
	if len(pub) != 65 {
		t.Fatalf("unexpected pub size: %d", len(pub))
	}
}

func TestSignerTxSignTxEd25519WithLocalECDSAKey(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	signer := LatestSignerForChainID(big.NewInt(1))
	to := common.HexToAddress("0x0000000000000000000000000000000000000001")
	tx := NewTx(&SignerTx{
		ChainID:    big.NewInt(1),
		Nonce:      4,
		To:         &to,
		Value:      big.NewInt(1),
		Gas:        21000,
		GasPrice:   big.NewInt(1),
		From:       common.HexToAddress("0x0000000000000000000000000000000000000002"),
		SignerType: "ed25519",
	})
	signed, err := SignTx(tx, signer, key)
	if err != nil {
		t.Fatalf("sign tx failed: %v", err)
	}
	v, r, s := signed.RawSignatureValues()
	if v.Sign() != 0 {
		t.Fatalf("unexpected v: %d", v.Uint64())
	}
	edKey, err := asEd25519Key(key)
	if err != nil {
		t.Fatalf("failed to derive ed25519 key: %v", err)
	}
	sig := make([]byte, ed25519.SignatureSize)
	rb, sb := r.Bytes(), s.Bytes()
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):], sb)
	hash := signer.Hash(signed)
	if !ed25519.Verify(edKey.Public().(ed25519.PublicKey), hash[:], sig) {
		t.Fatal("ed25519 signature verification failed")
	}
}

func TestSignerTxSignTxElgamalWithLocalECDSAKey(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	signer := LatestSignerForChainID(big.NewInt(1))
	to := common.HexToAddress("0x0000000000000000000000000000000000000001")
	tx := NewTx(&SignerTx{
		ChainID:    big.NewInt(1),
		Nonce:      6,
		To:         &to,
		Value:      big.NewInt(1),
		Gas:        21000,
		GasPrice:   big.NewInt(1),
		From:       common.HexToAddress("0x0000000000000000000000000000000000000002"),
		SignerType: "elgamal",
	})
	signed, err := SignTx(tx, signer, key)
	if err != nil {
		t.Fatalf("sign tx failed: %v", err)
	}
	v, r, s := signed.RawSignatureValues()
	if v.Sign() != 0 {
		t.Fatalf("unexpected v: %d", v.Uint64())
	}

	elgPriv, err := asElgamalKey(key)
	if err != nil {
		t.Fatalf("failed to derive elgamal key: %v", err)
	}
	hash := signer.Hash(signed)
	if !verifyElgamalSignatureForTest(elgPriv, hash, r, s) {
		t.Fatal("elgamal signature verification failed")
	}
	wrongKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate wrong key: %v", err)
	}
	wrongElgPriv, err := asElgamalKey(wrongKey)
	if err != nil {
		t.Fatalf("failed to derive wrong elgamal key: %v", err)
	}
	if verifyElgamalSignatureForTest(wrongElgPriv, hash, r, s) {
		t.Fatal("elgamal signature unexpectedly verified with wrong pubkey")
	}
}

func verifyElgamalSignatureForTest(secretBytes []byte, hash common.Hash, r, s *big.Int) bool {
	if len(secretBytes) != 32 {
		return false
	}
	secret := ristretto255.NewScalar()
	if _, err := secret.SetCanonicalBytes(secretBytes); err != nil {
		return false
	}
	base := ristretto255.NewGeneratorElement().Bytes()
	digest := sha3.Sum512(base)
	h := ristretto255.NewIdentityElement()
	if _, err := h.SetUniformBytes(digest[:]); err != nil {
		return false
	}
	inv := ristretto255.NewScalar().Invert(secret)
	pub := ristretto255.NewIdentityElement().ScalarMult(inv, h)

	sSig := ristretto255.NewScalar()
	if _, err := sSig.SetCanonicalBytes(bigToFixedBytes(r, 32)); err != nil {
		return false
	}
	eSig := ristretto255.NewScalar()
	if _, err := eSig.SetCanonicalBytes(bigToFixedBytes(s, 32)); err != nil {
		return false
	}
	hs := ristretto255.NewIdentityElement().ScalarMult(sSig, h)
	negE := ristretto255.NewScalar().Negate(eSig)
	pubNegE := ristretto255.NewIdentityElement().ScalarMult(negE, pub)
	rPoint := ristretto255.NewIdentityElement().Add(hs, pubNegE)

	hasher := sha3.New512()
	hasher.Write(pub.Bytes())
	hasher.Write(hash[:])
	hasher.Write(rPoint.Bytes())
	eDigest := hasher.Sum(nil)
	calculated := ristretto255.NewScalar()
	if _, err := calculated.SetUniformBytes(eDigest); err != nil {
		return false
	}
	return eSig.Equal(calculated) == 1
}

func bigToFixedBytes(v *big.Int, size int) []byte {
	out := make([]byte, size)
	if v == nil || v.Sign() < 0 {
		return out
	}
	raw := v.Bytes()
	if len(raw) > size {
		raw = raw[len(raw)-size:]
	}
	copy(out[size-len(raw):], raw)
	return out
}

func TestReplayProtectionSigning(t *testing.T) {
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)

	signer := NewReplayProtectedSigner(big.NewInt(18))
	tx, err := SignTx(NewTransaction(0, addr, new(big.Int), 0, new(big.Int), nil), signer, key)
	if err != nil {
		t.Fatal(err)
	}

	from, err := Sender(signer, tx)
	if err != nil {
		t.Fatal(err)
	}
	if from != addr {
		t.Errorf("exected from and address to be equal. Got %x want %x", from, addr)
	}
}

func TestReplayProtectionChainId(t *testing.T) {
	t.Skip("legacy replay-protection chain-id behavior removed in signer-tx-only mode")
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)

	signer := NewReplayProtectedSigner(big.NewInt(18))
	tx, err := SignTx(NewTransaction(0, addr, new(big.Int), 0, new(big.Int), nil), signer, key)
	if err != nil {
		t.Fatal(err)
	}
	if !tx.Protected() {
		t.Fatal("expected tx to be protected")
	}

	if tx.ChainId().Cmp(signer.chainId) != 0 {
		t.Error("expected chainId to be", signer.chainId, "got", tx.ChainId())
	}

	var legacyTx Transaction
	if err := legacyTx.UnmarshalBinary(common.FromHex("f8498080808080011ca09b16de9d5bdee2cf56c28d16275a4da68cd30273e2525f3959f5d62557489921a0372ebd8fb3345f7db7b5a86d42e24d36e983e259b0664ceb8c227ec9af572f3d")); err != nil {
		t.Fatal(err)
	}

	if legacyTx.Protected() {
		t.Error("didn't expect tx to be protected")
	}

	if legacyTx.ChainId().Sign() != 0 {
		t.Error("expected chain id to be 0 got", legacyTx.ChainId())
	}

	if _, err := Sender(signer, &legacyTx); err != ErrTxTypeNotSupported {
		t.Errorf("expected sender error %v, got %v", ErrTxTypeNotSupported, err)
	}
}

func TestReplayProtectionSigningVitalik(t *testing.T) {
	t.Skip("legacy replay-protection vectors removed in signer-tx-only mode")
	// Test vectors come from http://vitalik.ca/files/replay-protected_testvec.txt
	for i, test := range []struct {
		txRlp, addr string
	}{
		{"f864808504a817c800825208943535353535353535353535353535353535353535808025a0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116da0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d", "0xf0f6f18bca1b28cd68e4357452947e021241e9ce"},
		{"f864018504a817c80182a410943535353535353535353535353535353535353535018025a0489efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bcaa0489efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6", "0x23ef145a395ea3fa3deb533b8a9e1b4c6c25d112"},
		{"f864028504a817c80282f618943535353535353535353535353535353535353535088025a02d7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5a02d7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5", "0x2e485e0c23b4c3c542628a5f672eeab0ad4888be"},
		{"f865038504a817c803830148209435353535353535353535353535353535353535351b8025a02a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4e0a02a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4de", "0x82a88539669a3fd524d669e858935de5e5410cf0"},
		{"f865048504a817c80483019a28943535353535353535353535353535353535353535408025a013600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c063a013600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c060", "0xf9358f2538fd5ccfeb848b64a96b743fcc930554"},
		{"f865058504a817c8058301ec309435353535353535353535353535353535353535357d8025a04eebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1a04eebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1", "0xa8f7aba377317440bc5b26198a363ad22af1f3a4"},
		{"f866068504a817c80683023e3894353535353535353535353535353535353535353581d88025a06455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2fa06455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2d", "0xf1f571dc362a0e5b2696b8e775f8491d3e50de35"},
		{"f867078504a817c807830290409435353535353535353535353535353535353535358201578025a052f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021a052f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021", "0xd37922162ab7cea97c97a87551ed02c9a38b7332"},
		{"f867088504a817c8088302e2489435353535353535353535353535353535353535358202008025a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c12a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c10", "0x9bddad43f934d313c2b79ca28a432dd2b7281029"},
		{"f867098504a817c809830334509435353535353535353535353535353535353535358202d98025a052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afba052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb", "0x3c24d7329e92f84f08556ceb6df1cdb0104ca49f"},
	} {
		signer := NewReplayProtectedSigner(big.NewInt(1))

		var tx *Transaction
		err := rlp.DecodeBytes(common.Hex2Bytes(test.txRlp), &tx)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}

		from, err := Sender(signer, tx)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}

		addr := common.HexToAddress(test.addr)
		if from != addr {
			t.Errorf("%d: expected %x got %x", i, addr, from)
		}
	}
}

func TestChainId(t *testing.T) {
	key, _ := defaultTestKey()

	tx := NewTransaction(0, common.Address{}, new(big.Int), 0, new(big.Int), nil)

	var err error
	tx, err = SignTx(tx, NewReplayProtectedSigner(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Sender(NewReplayProtectedSigner(big.NewInt(2)), tx)
	if err != ErrInvalidChainId {
		t.Error("expected error:", ErrInvalidChainId)
	}

	_, err = Sender(NewReplayProtectedSigner(big.NewInt(1)), tx)
	if err != nil {
		t.Error("expected no error")
	}
}
