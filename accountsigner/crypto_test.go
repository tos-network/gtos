package accountsigner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"strings"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/crypto"
)

func TestNormalizeSignerExtendedTypes(t *testing.T) {
	tests := []struct {
		name         string
		signerType   string
		signerValue  string
		wantType     string
		wantValueLen int
	}{
		{
			name:         "bls12381 alias canonicalizes",
			signerType:   "BLS12381",
			signerValue:  "0x" + strings.Repeat("11", 48),
			wantType:     SignerTypeBLS12381,
			wantValueLen: 48,
		},
		{
			name:         "frost accepts opaque key material",
			signerType:   SignerTypeFROST,
			signerValue:  "0x" + strings.Repeat("22", 32),
			wantType:     SignerTypeFROST,
			wantValueLen: 32,
		},
		{
			name:         "pqc accepts larger key material",
			signerType:   SignerTypePQC,
			signerValue:  "0x" + strings.Repeat("33", 128),
			wantType:     SignerTypePQC,
			wantValueLen: 128,
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
			if gotValue != hexutil.Encode(gotPub) {
				t.Fatalf("unexpected canonical signer value have=%q want=%q", gotValue, hexutil.Encode(gotPub))
			}
		})
	}
}

func TestNormalizeSignerRejectsInvalidExtendedLengths(t *testing.T) {
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
			name:        "frost too short",
			signerType:  SignerTypeFROST,
			signerValue: "0x" + strings.Repeat("22", 8),
		},
		{
			name:        "pqc too short",
			signerType:  SignerTypePQC,
			signerValue: "0x" + strings.Repeat("33", 16),
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
	if !SupportsCurrentTxSignatureType(SignerTypeSecp256r1) {
		t.Fatalf("expected secp256r1 support")
	}
	if !SupportsCurrentTxSignatureType(SignerTypeEd25519) {
		t.Fatalf("expected ed25519 support")
	}
	if SupportsCurrentTxSignatureType(SignerTypeBLS12381) {
		t.Fatalf("did not expect bls12-381 support in current tx signature format")
	}
	if SupportsCurrentTxSignatureType(SignerTypeFROST) {
		t.Fatalf("did not expect frost support in current tx signature format")
	}
	if SupportsCurrentTxSignatureType(SignerTypePQC) {
		t.Fatalf("did not expect pqc support in current tx signature format")
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
