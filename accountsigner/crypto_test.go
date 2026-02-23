package accountsigner

import (
	"strings"
	"testing"

	"github.com/tos-network/gtos/common/hexutil"
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
