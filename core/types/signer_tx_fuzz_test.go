package types

import (
	"testing"

	"github.com/tos-network/gtos/crypto"
)

func FuzzDecodeSignerTxSignatureNoPanic(f *testing.F) {
	f.Add("secp256k1", make([]byte, crypto.SignatureLength))
	f.Add("schnorr", make([]byte, 64))
	f.Add("secp256r1", make([]byte, 64))
	f.Add("ed25519", make([]byte, 64))
	f.Add("bls12-381", make([]byte, 96))
	f.Add("elgamal", make([]byte, 64))
	f.Add("unknown", make([]byte, crypto.SignatureLength))

	f.Fuzz(func(t *testing.T, signerType string, sig []byte) {
		if len(sig) > 1024 {
			return
		}
		r, s, v, err := decodeSignerTxSignature(signerType, sig)
		if err != nil {
			return
		}
		if r == nil || s == nil || v == nil {
			t.Fatalf("decoded signature must return non-nil r/s/v")
		}
		// Must not panic on any accepted decode output.
		_ = sanityCheckSignerTxSignature(signerType, v, r, s)

		canonical, err := canonicalSignerType(signerType)
		if err != nil {
			if len(sig) != crypto.SignatureLength {
				t.Fatalf("unknown signer decoded with unexpected signature len=%d", len(sig))
			}
			return
		}
		switch canonical {
		case "secp256k1":
			if len(sig) != crypto.SignatureLength {
				t.Fatalf("secp256k1 accepted unexpected signature len=%d", len(sig))
			}
		case "schnorr", "secp256r1", "ed25519", "elgamal":
			if len(sig) != 64 && len(sig) != crypto.SignatureLength {
				t.Fatalf("%s accepted unexpected signature len=%d", canonical, len(sig))
			}
		case "bls12-381":
			if len(sig) != 96 {
				t.Fatalf("bls12-381 accepted unexpected signature len=%d", len(sig))
			}
		}
	})
}

func FuzzTransactionUnmarshalJSONSignerTx(f *testing.F) {
	f.Add([]byte(`{"type":"0x0","chainId":"0x2a","nonce":"0x0","gas":"0x5208","to":"0x969b0a11b8a56bacf1ac18f219e7e376e7c213b7e7e7e46cc70a5dd086daff2a","value":"0x0","input":"0x","from":"0x85b1f044bab6d30f3a19c1501563915e194d8cfba1943570603f7606a3115508","signerType":"secp256k1","v":"0x0","r":"0x0","s":"0x0"}`))
	f.Add([]byte(`{"type":"0x0","chainId":"0x2a","nonce":"0x1","gas":"0x5208","to":"0x969b0a11b8a56bacf1ac18f219e7e376e7c213b7e7e7e46cc70a5dd086daff2a","value":"0x0","input":"0x","from":"0x85b1f044bab6d30f3a19c1501563915e194d8cfba1943570603f7606a3115508","signerType":"bls12-381","v":"0x0","r":"0x1","s":"0x1"}`))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4096 {
			return
		}
		var tx Transaction
		if err := tx.UnmarshalJSON(input); err != nil {
			return
		}
		if tx.Type() != SignerTxType {
			t.Fatalf("unexpected tx type %d", tx.Type())
		}
		if tx.ChainId() == nil {
			t.Fatalf("decoded signer tx has nil chain id")
		}
		if signerType, ok := tx.SignerType(); !ok || signerType == "" {
			t.Fatalf("decoded signer tx missing signerType")
		}
		if _, ok := tx.SignerFrom(); !ok {
			t.Fatalf("decoded signer tx missing from")
		}
		if _, err := tx.MarshalBinary(); err != nil {
			t.Fatalf("decoded signer tx cannot marshal: %v", err)
		}
	})
}
