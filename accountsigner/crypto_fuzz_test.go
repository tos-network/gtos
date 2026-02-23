package accountsigner

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
)

func FuzzNormalizeSignerNoPanic(f *testing.F) {
	f.Add("secp256k1", "0x04d7f5f4f3e9f4dc6f4a4d8ff4d2df5d4ad5dc9b145f95be2da233c6f0ca6c584b43870bc5f5ca22d7082ec9f3bd26f6dfd1d5cdbf15f4bbac7d66169f4f7de0d7")
	f.Add("secp256r1", "0x04f5d4c3b2a1988776655443322110ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100ff")
	f.Add("ed25519", "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	f.Add("bls12-381", "0x8bb4b8f4f6c6dc9b5dbfb7d6e0be8f1a4f6b2af5f0f7eddb3f4ed2f7b8fd45f1458be9f6854a2b2f0d1a3cf4d6f9a251")
	f.Add("elgamal", "0xe2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76")

	f.Fuzz(func(t *testing.T, signerType, signerValue string) {
		if len(signerType) > 128 || len(signerValue) > 4096 {
			return
		}
		typ, pub, canonicalValue, err := NormalizeSigner(signerType, signerValue)
		if err != nil {
			return
		}
		if typ == "" || len(pub) == 0 {
			t.Fatalf("normalized signer has empty type/pub")
		}
		if !SupportsCurrentTxSignatureType(typ) {
			t.Fatalf("normalized unsupported signer type %q", typ)
		}
		decoded, err := hexutil.Decode(canonicalValue)
		if err != nil {
			t.Fatalf("canonical value decode failed: %v", err)
		}
		if hexutil.Encode(decoded) != canonicalValue {
			t.Fatalf("canonical value is not normalized hex")
		}
		if hexutil.Encode(pub) != canonicalValue {
			t.Fatalf("canonical value does not match normalized pub")
		}
		if _, err := AddressFromSigner(typ, pub); err != nil {
			t.Fatalf("failed deriving address from normalized signer: %v", err)
		}
	})
}

func FuzzDecodeSignatureMetaNoPanic(f *testing.F) {
	f.Add([]byte{0x1b})
	f.Add(append(append([]byte(nil), signatureMetaPrefix...), signatureMetaAlgSecp256k1))
	f.Add(append(append([]byte(nil), signatureMetaPrefix...), signatureMetaAlgBLS12381))
	f.Add(append(append([]byte(nil), signatureMetaPrefix...), signatureMetaAlgElgamal))

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1024 {
			return
		}
		v := new(big.Int).SetBytes(raw)
		typ, pub, ok, err := DecodeSignatureMeta(v)
		if err != nil {
			return
		}
		if !ok {
			if typ != "" || pub != nil {
				t.Fatalf("legacy decode returned signer data")
			}
			return
		}
		if typ == "" || len(pub) == 0 {
			t.Fatalf("active metadata decode returned empty signer info")
		}
		reenc, err := EncodeSignatureMeta(typ, pub)
		if err != nil {
			t.Fatalf("re-encode metadata failed: %v", err)
		}
		typ2, pub2, ok2, err := DecodeSignatureMeta(reenc)
		if err != nil {
			t.Fatalf("re-decode metadata failed: %v", err)
		}
		if !ok2 || typ2 != typ || hexutil.Encode(pub2) != hexutil.Encode(pub) {
			t.Fatalf("metadata round-trip mismatch")
		}
	})
}

func FuzzVerifyRawSignatureNoPanic(f *testing.F) {
	f.Add("secp256k1", []byte{0x04}, []byte{0x01}, []byte{0x01}, []byte{0x01})
	f.Add("secp256r1", []byte{0x04}, []byte{0x02}, []byte{0x01}, []byte{0x01})
	f.Add("ed25519", make([]byte, 32), []byte{0x03}, []byte{0x01}, []byte{0x01})
	f.Add("bls12-381", make([]byte, 48), []byte{0x04}, []byte{0x01}, []byte{0x01})
	f.Add("elgamal", []byte{
		0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71,
		0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
		0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d,
		0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
	}, []byte{0x05}, []byte{0x01}, []byte{0x01})

	f.Fuzz(func(t *testing.T, signerType string, pub []byte, hashBytes []byte, rBytes []byte, sBytes []byte) {
		if len(signerType) > 64 || len(pub) > 512 || len(hashBytes) > 128 || len(rBytes) > 128 || len(sBytes) > 128 {
			return
		}
		hash := common.BytesToHash(hashBytes)
		r := new(big.Int).SetBytes(rBytes)
		s := new(big.Int).SetBytes(sBytes)
		_ = VerifyRawSignature(signerType, pub, hash, r, s)
	})
}
