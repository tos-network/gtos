package accountsigner

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	btcschnorr "github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/crypto"
)

func TestNormalizeSignerExtendedTypes(t *testing.T) {
	secpKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate secp256k1 key: %v", err)
	}
	btcecPriv, _ := btcec.PrivKeyFromBytes(crypto.FromECDSA(secpKey))
	schnorrPub := btcschnorr.SerializePubKey(btcecPriv.PubKey())
	secpCompressed := crypto.CompressPubkey(&secpKey.PublicKey)

	blsPriv, err := GenerateBLS12381PrivateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate bls private key: %v", err)
	}
	blsPub, err := PublicKeyFromBLS12381Private(blsPriv)
	if err != nil {
		t.Fatalf("failed to derive bls public key: %v", err)
	}
	elgamalPriv, err := GenerateElgamalPrivateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate elgamal private key: %v", err)
	}
	elgamalPub, err := PublicKeyFromElgamalPrivate(elgamalPriv)
	if err != nil {
		t.Fatalf("failed to derive elgamal public key: %v", err)
	}
	tests := []struct {
		name         string
		signerType   string
		signerValue  string
		wantType     string
		wantValueLen int
		wantValue    string
	}{
		{
			name:         "schnorr canonicalizes",
			signerType:   " schnorr ",
			signerValue:  hexutil.Encode(secpCompressed),
			wantType:     SignerTypeSchnorr,
			wantValueLen: btcschnorr.PubKeyBytesLen,
			wantValue:    hexutil.Encode(schnorrPub),
		},
		{
			name:         "bls12381 alias canonicalizes",
			signerType:   "BLS12381",
			signerValue:  hexutil.Encode(blsPub),
			wantType:     SignerTypeBLS12381,
			wantValueLen: 48,
		},
		{
			name:         "elgamal canonicalizes",
			signerType:   " ELGAMAL ",
			signerValue:  hexutil.Encode(elgamalPub),
			wantType:     SignerTypeElgamal,
			wantValueLen: 32,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotPub, gotValue, err := NormalizeSigner(tc.signerType, tc.signerValue)
			if err != nil {
				t.Fatalf("NormalizeSigner failed: %v", err)
			}
			if gotType != tc.wantType {
				t.Fatalf("unexpected signer type have=%q want=%q", gotType, tc.wantType)
			}
			if len(gotPub) != tc.wantValueLen {
				t.Fatalf("unexpected pubkey len have=%d want=%d", len(gotPub), tc.wantValueLen)
			}
			wantValue := hexutil.Encode(gotPub)
			if tc.wantValue != "" {
				wantValue = tc.wantValue
			}
			if gotValue != wantValue {
				t.Fatalf("unexpected canonical signer value have=%q want=%q", gotValue, wantValue)
			}
		})
	}
}

func TestNormalizeSignerRejectsInvalidExtendedTypes(t *testing.T) {
	tests := []struct {
		name        string
		signerType  string
		signerValue string
	}{
		{
			name:        "bls wrong length",
			signerType:  SignerTypeBLS12381,
			signerValue: "0x" + strings.Repeat("11", 47),
		},
		{
			name:        "frost removed",
			signerType:  "frost",
			signerValue: "0x" + strings.Repeat("22", 32),
		},
		{
			name:        "pqc removed",
			signerType:  "pqc",
			signerValue: "0x" + strings.Repeat("33", 128),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := NormalizeSigner(tc.signerType, tc.signerValue)
			if err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestSupportsCurrentTxSignatureType(t *testing.T) {
	if !SupportsCurrentTxSignatureType(SignerTypeSecp256k1) {
		t.Fatalf("expected secp256k1 support")
	}
	if !SupportsCurrentTxSignatureType(SignerTypeSchnorr) {
		t.Fatalf("expected schnorr support")
	}
	if !SupportsCurrentTxSignatureType(SignerTypeSecp256r1) {
		t.Fatalf("expected secp256r1 support")
	}
	if !SupportsCurrentTxSignatureType(SignerTypeEd25519) {
		t.Fatalf("expected ed25519 support")
	}
	if !SupportsCurrentTxSignatureType(SignerTypeBLS12381) {
		t.Fatalf("expected bls12-381 support")
	}
	if !SupportsCurrentTxSignatureType(SignerTypeElgamal) {
		t.Fatalf("expected elgamal support")
	}
}

func TestSignAndVerifySchnorrHash(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate secp256k1 key: %v", err)
	}
	priv, _ := btcec.PrivKeyFromBytes(crypto.FromECDSA(key))
	pub := btcschnorr.SerializePubKey(priv.PubKey())
	msg := common.HexToHash("0x1234567890")

	sig, err := btcschnorr.Sign(priv, msg[:])
	if err != nil {
		t.Fatalf("failed to sign schnorr hash: %v", err)
	}
	sigBytes := sig.Serialize()
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	if !VerifyRawSignature(SignerTypeSchnorr, pub, msg, r, s) {
		t.Fatalf("schnorr signature verification failed")
	}

	sigBytes[0] ^= 0x01
	rBad := new(big.Int).SetBytes(sigBytes[:32])
	sBad := new(big.Int).SetBytes(sigBytes[32:])
	if VerifyRawSignature(SignerTypeSchnorr, pub, msg, rBad, sBad) {
		t.Fatalf("mutated schnorr signature unexpectedly verified")
	}
}

func TestSignAndVerifyBLS12381Hash(t *testing.T) {
	priv, err := GenerateBLS12381PrivateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate bls private key: %v", err)
	}
	pub, err := PublicKeyFromBLS12381Private(priv)
	if err != nil {
		t.Fatalf("failed to derive bls public key: %v", err)
	}
	msg := common.HexToHash("0x1234abcd")
	sig, err := SignBLS12381Hash(priv, msg)
	if err != nil {
		t.Fatalf("failed to sign hash: %v", err)
	}
	r, s, err := SplitBLS12381Signature(sig)
	if err != nil {
		t.Fatalf("failed to split signature: %v", err)
	}
	if !VerifyRawSignature(SignerTypeBLS12381, pub, msg, r, s) {
		t.Fatalf("bls12-381 signature verification failed")
	}
	joined, err := JoinBLS12381Signature(r, s)
	if err != nil {
		t.Fatalf("failed to join signature: %v", err)
	}
	if hexutil.Encode(joined) != hexutil.Encode(sig) {
		t.Fatalf("joined signature mismatch")
	}
}

func TestBLS12381FastAggregate(t *testing.T) {
	msg := common.HexToHash("0x7777")
	var (
		pubs [][]byte
		sigs [][]byte
	)
	for i := 0; i < 3; i++ {
		priv, err := GenerateBLS12381PrivateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate bls private key: %v", err)
		}
		pub, err := PublicKeyFromBLS12381Private(priv)
		if err != nil {
			t.Fatalf("failed to derive bls public key: %v", err)
		}
		sig, err := SignBLS12381Hash(priv, msg)
		if err != nil {
			t.Fatalf("failed to sign hash: %v", err)
		}
		pubs = append(pubs, pub)
		sigs = append(sigs, sig)
	}
	aggPub, err := AggregateBLS12381PublicKeys(pubs)
	if err != nil {
		t.Fatalf("failed to aggregate pubkeys: %v", err)
	}
	aggSig, err := AggregateBLS12381Signatures(sigs)
	if err != nil {
		t.Fatalf("failed to aggregate signatures: %v", err)
	}
	if !VerifyBLS12381FastAggregate(pubs, aggSig, msg) {
		t.Fatalf("fast aggregate verification failed")
	}
	r, s, err := SplitBLS12381Signature(aggSig)
	if err != nil {
		t.Fatalf("failed to split aggregate signature: %v", err)
	}
	if !VerifyRawSignature(SignerTypeBLS12381, aggPub, msg, r, s) {
		t.Fatalf("aggregate signature verify via tx-style RS failed")
	}
}

func TestEncodeSecp256r1Signature(t *testing.T) {
	r := new(big.Int).SetUint64(1234)
	s := new(big.Int).SetUint64(5678)
	sig, err := EncodeSecp256r1Signature(r, s)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("unexpected signature length: %d", len(sig))
	}
	if sig[64] != 0 {
		t.Fatalf("unexpected V byte: %d", sig[64])
	}
}

func TestEncodeSecp256r1ASN1Signature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	msg := common.HexToHash("0x010203")
	sigDER, err := ecdsa.SignASN1(rand.Reader, key, msg[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	sigRSV, err := EncodeSecp256r1ASN1Signature(sigDER)
	if err != nil {
		t.Fatalf("encode asn1 failed: %v", err)
	}
	if len(sigRSV) != 65 {
		t.Fatalf("unexpected signature length: %d", len(sigRSV))
	}
	r := new(big.Int).SetBytes(sigRSV[:32])
	s := new(big.Int).SetBytes(sigRSV[32:64])
	pub := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	if !VerifyRawSignature(SignerTypeSecp256r1, pub, msg, r, s) {
		t.Fatalf("encoded signature does not verify")
	}
}

func TestSignSecp256r1Hash(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	msg := common.HexToHash("0xdeadbeef")
	sig, err := SignSecp256r1Hash(key, msg)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("unexpected signature length: %d", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	pub := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	if !VerifyRawSignature(SignerTypeSecp256r1, pub, msg, r, s) {
		t.Fatalf("signature verification failed")
	}
}

func TestSignSecp256r1HashRejectsNonP256Key(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate secp256k1 key: %v", err)
	}
	_, err = SignSecp256r1Hash(key, common.HexToHash("0x01"))
	if err == nil {
		t.Fatalf("expected key validation error")
	}
}

func TestSignAndVerifyElgamalHash(t *testing.T) {
	priv, err := GenerateElgamalPrivateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate elgamal private key: %v", err)
	}
	pub, err := PublicKeyFromElgamalPrivate(priv)
	if err != nil {
		t.Fatalf("failed to derive elgamal public key: %v", err)
	}
	msg := common.HexToHash("0xa1b2c3d4")
	sig, err := SignElgamalHash(priv, msg)
	if err != nil {
		t.Fatalf("failed to sign hash: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("unexpected signature length: %d", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !VerifyRawSignature(SignerTypeElgamal, pub, msg, r, s) {
		t.Fatalf("elgamal signature verification failed")
	}
	sig[0] ^= 0x01
	rBad := new(big.Int).SetBytes(sig[:32])
	sBad := new(big.Int).SetBytes(sig[32:])
	if VerifyRawSignature(SignerTypeElgamal, pub, msg, rBad, sBad) {
		t.Fatalf("mutated elgamal signature unexpectedly verified")
	}
}

func TestSignatureMetaRoundTripSupportedSigners(t *testing.T) {
	secp256k1Key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate secp256k1 key: %v", err)
	}
	schnorrPriv, _ := btcec.PrivKeyFromBytes(crypto.FromECDSA(secp256k1Key))
	schnorrPub := btcschnorr.SerializePubKey(schnorrPriv.PubKey())
	secp256r1Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate secp256r1 key: %v", err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	blsPriv, err := GenerateBLS12381PrivateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate bls private key: %v", err)
	}
	blsPub, err := PublicKeyFromBLS12381Private(blsPriv)
	if err != nil {
		t.Fatalf("failed to derive bls public key: %v", err)
	}
	elgamalPriv, err := GenerateElgamalPrivateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate elgamal private key: %v", err)
	}
	elgamalPub, err := PublicKeyFromElgamalPrivate(elgamalPriv)
	if err != nil {
		t.Fatalf("failed to derive elgamal public key: %v", err)
	}

	tests := []struct {
		name       string
		signerType string
		pub        []byte
	}{
		{name: "secp256k1", signerType: SignerTypeSecp256k1, pub: crypto.FromECDSAPub(&secp256k1Key.PublicKey)},
		{name: "schnorr", signerType: SignerTypeSchnorr, pub: append([]byte(nil), schnorrPub...)},
		{name: "secp256r1", signerType: SignerTypeSecp256r1, pub: elliptic.Marshal(elliptic.P256(), secp256r1Key.X, secp256r1Key.Y)},
		{name: "ed25519", signerType: SignerTypeEd25519, pub: append([]byte(nil), edPub...)},
		{name: "bls12-381", signerType: SignerTypeBLS12381, pub: append([]byte(nil), blsPub...)},
		{name: "elgamal", signerType: SignerTypeElgamal, pub: append([]byte(nil), elgamalPub...)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectedType, expectedPub, _, err := NormalizeSigner(tc.signerType, hexutil.Encode(tc.pub))
			if err != nil {
				t.Fatalf("normalize input signer failed: %v", err)
			}
			meta, err := EncodeSignatureMeta(tc.signerType, tc.pub)
			if err != nil {
				t.Fatalf("encode signature meta failed: %v", err)
			}
			gotType, gotPub, ok, err := DecodeSignatureMeta(meta)
			if err != nil {
				t.Fatalf("decode signature meta failed: %v", err)
			}
			if !ok {
				t.Fatalf("expected metadata decode to be active")
			}
			if gotType != expectedType {
				t.Fatalf("signer type mismatch have=%q want=%q", gotType, expectedType)
			}
			if hexutil.Encode(gotPub) != hexutil.Encode(expectedPub) {
				t.Fatalf("pubkey mismatch have=%s want=%s", hexutil.Encode(gotPub), hexutil.Encode(expectedPub))
			}
		})
	}
}

func TestDecodeSignatureMetaRejectsUnknownAlg(t *testing.T) {
	raw := append([]byte(nil), signatureMetaPrefix...)
	raw = append(raw, 0xff)
	raw = append(raw, []byte{0x01, 0x02, 0x03}...)
	_, _, ok, err := DecodeSignatureMeta(new(big.Int).SetBytes(raw))
	if ok {
		t.Fatalf("expected metadata decode to be inactive on unknown alg")
	}
	if !errors.Is(err, ErrInvalidSignatureMeta) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeSignatureMetaLegacyValue(t *testing.T) {
	typ, pub, ok, err := DecodeSignatureMeta(big.NewInt(27))
	if err != nil {
		t.Fatalf("unexpected error for legacy value: %v", err)
	}
	if ok || typ != "" || pub != nil {
		t.Fatalf("unexpected legacy decode result ok=%v type=%q pub=%x", ok, typ, pub)
	}
}
