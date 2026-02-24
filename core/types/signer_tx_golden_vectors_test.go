package types

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"

	blst "github.com/supranational/blst/bindings/go"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/crypto"
)

type signerTxGoldenFile struct {
	Valid            []signerTxGoldenValid   `json:"valid"`
	InvalidDecode    []signerTxGoldenInvalid `json:"invalidDecode"`
	Canonicalization []signerTxCanonicalCase `json:"canonicalization"`
}

type signerTxGoldenValid struct {
	Name      string              `json:"name"`
	Tx        signerTxGoldenInput `json:"tx"`
	SignHash  string              `json:"signHash"`
	PubKey    string              `json:"pubKey"`
	Signature string              `json:"signature"`
	V         string              `json:"v"`
	R         string              `json:"r"`
	S         string              `json:"s"`
	TxHash    string              `json:"txHash"`
	RawTx     string              `json:"rawTx"`
}

type signerTxGoldenInput struct {
	ChainID    string `json:"chainId"`
	Nonce      uint64 `json:"nonce"`
	Gas        uint64 `json:"gas"`
	To         string `json:"to"`
	Value      string `json:"value"`
	Data       string `json:"data"`
	From       string `json:"from"`
	SignerType string `json:"signerType"`
}

type signerTxGoldenInvalid struct {
	Name       string `json:"name"`
	SignerType string `json:"signerType"`
	Signature  string `json:"signature"`
	Kind       string `json:"kind"`
}

type signerTxCanonicalCase struct {
	Input     string `json:"input"`
	Canonical string `json:"canonical"`
	Valid     bool   `json:"valid"`
}

func loadSignerTxGoldenFile(t *testing.T) signerTxGoldenFile {
	t.Helper()

	blob, err := os.ReadFile("testdata/signer_tx_golden_vectors.json")
	if err != nil {
		t.Fatalf("failed to read signer tx golden vectors: %v", err)
	}
	var out signerTxGoldenFile
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatalf("failed to decode signer tx golden vectors: %v", err)
	}
	return out
}

func mustDecodeHexBig(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 0)
	if !ok {
		t.Fatalf("invalid hex bigint %q", s)
	}
	return v
}

func mustBuildUnsignedGoldenTx(t *testing.T, in signerTxGoldenInput) (*Transaction, *big.Int) {
	t.Helper()

	chainID := mustDecodeHexBig(t, in.ChainID)
	value := mustDecodeHexBig(t, in.Value)
	to := common.HexToAddress(in.To)
	return NewTx(&SignerTx{
		ChainID:    new(big.Int).Set(chainID),
		Nonce:      in.Nonce,
		Gas:        in.Gas,
		To:         &to,
		Value:      value,
		Data:       common.FromHex(in.Data),
		AccessList: nil,
		From:       common.HexToAddress(in.From),
		SignerType: in.SignerType,
		V:          new(big.Int),
		R:          new(big.Int),
		S:          new(big.Int),
	}), chainID
}

func rsBytes(r, s *big.Int, size int) []byte {
	out := make([]byte, size*2)
	rb, sb := r.Bytes(), s.Bytes()
	copy(out[size-len(rb):size], rb)
	copy(out[len(out)-len(sb):], sb)
	return out
}

func verifyRawByType(signerType string, pub []byte, hash common.Hash, r, s *big.Int) bool {
	switch signerType {
	case "secp256k1":
		return crypto.VerifySignature(pub, hash[:], rsBytes(r, s, 32))
	case "secp256r1":
		x, y := elliptic.Unmarshal(elliptic.P256(), pub)
		if x == nil || y == nil {
			return false
		}
		return ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, hash[:], r, s)
	case "ed25519":
		return ed25519.Verify(ed25519.PublicKey(pub), hash[:], rsBytes(r, s, 32))
	case "bls12-381":
		sig := rsBytes(r, s, 48)
		var dummy blst.P2Affine
		return dummy.VerifyCompressed(sig, true, pub, true, hash[:], []byte("GTOS_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_"))
	default:
		return false
	}
}

func TestSignerTxGoldenVectorsValid(t *testing.T) {
	vectors := loadSignerTxGoldenFile(t)
	for _, tc := range vectors.Valid {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			canonical, err := canonicalSignerType(tc.Tx.SignerType)
			if err != nil {
				t.Fatalf("canonical signer type failed: %v", err)
			}

			tx, chainID := mustBuildUnsignedGoldenTx(t, tc.Tx)
			signer := LatestSignerForChainID(chainID)

			signHash := signer.Hash(tx)
			if signHash.Hex() != tc.SignHash {
				t.Fatalf("sign hash mismatch have=%s want=%s", signHash.Hex(), tc.SignHash)
			}

			sig, err := hexutil.Decode(tc.Signature)
			if err != nil {
				t.Fatalf("invalid signature hex: %v", err)
			}
			signed, err := tx.WithSignature(signer, sig)
			if err != nil {
				t.Fatalf("with signature failed: %v", err)
			}
			v, r, s := signed.RawSignatureValues()
			if v.Cmp(mustDecodeHexBig(t, tc.V)) != 0 {
				t.Fatalf("v mismatch have=%s want=%s", hexutil.EncodeBig(v), tc.V)
			}
			if r.Cmp(mustDecodeHexBig(t, tc.R)) != 0 {
				t.Fatalf("r mismatch have=%s want=%s", hexutil.EncodeBig(r), tc.R)
			}
			if s.Cmp(mustDecodeHexBig(t, tc.S)) != 0 {
				t.Fatalf("s mismatch have=%s want=%s", hexutil.EncodeBig(s), tc.S)
			}

			if signed.Hash().Hex() != tc.TxHash {
				t.Fatalf("tx hash mismatch have=%s want=%s", signed.Hash().Hex(), tc.TxHash)
			}
			raw, err := signed.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal tx failed: %v", err)
			}
			if hexutil.Encode(raw) != tc.RawTx {
				t.Fatalf("raw tx mismatch have=%s want=%s", hexutil.Encode(raw), tc.RawTx)
			}

			pubRaw, err := hexutil.Decode(tc.PubKey)
			if err != nil {
				t.Fatalf("invalid pubkey hex: %v", err)
			}
			if !verifyRawByType(canonical, pubRaw, signHash, r, s) {
				t.Fatalf("raw signature verify failed for %s", canonical)
			}

			if canonical == "secp256k1" {
				from, err := Sender(signer, signed)
				if err != nil {
					t.Fatalf("sender recovery failed: %v", err)
				}
				if from != common.HexToAddress(tc.Tx.From) {
					t.Fatalf("sender mismatch have=%s want=%s", from.Hex(), tc.Tx.From)
				}
			} else {
				if _, err := Sender(signer, signed); !errors.Is(err, ErrTxTypeNotSupported) {
					t.Fatalf("expected sender recovery to be unsupported for %s, got %v", canonical, err)
				}
			}
		})
	}
}

func TestSignerTxGoldenVectorsInvalidDecode(t *testing.T) {
	vectors := loadSignerTxGoldenFile(t)
	for _, tc := range vectors.InvalidDecode {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Kind != "decode_error" {
				t.Fatalf("unknown invalid vector kind %q", tc.Kind)
			}
			sig, err := hexutil.Decode(tc.Signature)
			if err != nil {
				t.Fatalf("invalid signature hex: %v", err)
			}
			_, _, _, err = decodeSignerTxSignature(tc.SignerType, sig)
			if !errors.Is(err, ErrInvalidSig) {
				t.Fatalf("expected ErrInvalidSig, got %v", err)
			}
		})
	}
}

func TestSignerTxGoldenVectorsCanonicalization(t *testing.T) {
	vectors := loadSignerTxGoldenFile(t)
	for _, tc := range vectors.Canonicalization {
		tc := tc
		t.Run(tc.Input, func(t *testing.T) {
			got, err := canonicalSignerType(tc.Input)
			if tc.Valid {
				if err != nil {
					t.Fatalf("expected valid canonicalization, got error %v", err)
				}
				if got != tc.Canonical {
					t.Fatalf("canonical signer type mismatch have=%q want=%q", got, tc.Canonical)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected canonicalization failure for %q", tc.Input)
			}
		})
	}
}

func TestSignerTxGoldenVectorsMutatedSignaturesFailVerify(t *testing.T) {
	vectors := loadSignerTxGoldenFile(t)
	for _, tc := range vectors.Valid {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			canonical, err := canonicalSignerType(tc.Tx.SignerType)
			if err != nil {
				t.Fatalf("canonical signer type failed: %v", err)
			}
			tx, chainID := mustBuildUnsignedGoldenTx(t, tc.Tx)
			signer := LatestSignerForChainID(chainID)
			signHash := signer.Hash(tx)

			pubRaw, err := hexutil.Decode(tc.PubKey)
			if err != nil {
				t.Fatalf("invalid pubkey hex: %v", err)
			}

			mutated, err := hexutil.Decode(tc.Signature)
			if err != nil {
				t.Fatalf("invalid signature hex: %v", err)
			}
			mutated[0] ^= 0x01
			r, s, _, err := decodeSignerTxSignature(canonical, mutated)
			if err != nil {
				t.Fatalf("mutated signature decode failed: %v", err)
			}
			if verifyRawByType(canonical, pubRaw, signHash, r, s) {
				t.Fatalf("mutated signature unexpectedly verified")
			}
		})
	}
}
