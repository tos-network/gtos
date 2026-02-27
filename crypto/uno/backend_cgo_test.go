//go:build cgo && ed25519c

package uno

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type openingVectorCase struct {
	Name          string `json:"name"`
	PrivHex       string `json:"priv_hex"`
	OpeningHex    string `json:"opening_hex"`
	Amount        uint64 `json:"amount"`
	WantPubHex    string `json:"want_pub_hex"`
	WantComHex    string `json:"want_com_hex"`
	WantHandleHex string `json:"want_handle_hex"`
	WantCtHex     string `json:"want_ct_hex"`
}

type ctOpsVectorCase struct {
	PrivHex         string `json:"priv_hex"`
	PubHex          string `json:"pub_hex"`
	Opening1Hex     string `json:"opening1_hex"`
	Opening2Hex     string `json:"opening2_hex"`
	Ct9Hex          string `json:"ct9_hex"`
	Ct4Hex          string `json:"ct4_hex"`
	AddHex          string `json:"add_hex"`
	AddAmountHex    string `json:"add_amount_hex"`
	Scalar5Hex      string `json:"scalar5_hex"`
	Scalar2Hex      string `json:"scalar2_hex"`
	AddScalarHex    string `json:"add_scalar_hex"`
	SubScalarHex    string `json:"sub_scalar_hex"`
	MulScalarHex    string `json:"mul_scalar_hex"`
	ZeroHex         string `json:"zero_hex"`
	DecryptPointHex string `json:"decrypt_point_hex"`
}

type deterministicFixture struct {
	WithOpening []openingVectorCase `json:"with_opening"`
	CtOps       ctOpsVectorCase     `json:"ct_ops"`
}

func loadXelisCtOpsFixture(t *testing.T) ctOpsVectorCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/xelis_vectors.json")
	if err != nil {
		t.Fatalf("read xelis fixture: %v", err)
	}
	var fx ctOpsVectorCase
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal xelis fixture: %v", err)
	}
	return fx
}

func mustDecodeHex(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("decode hex %q: %v", h, err)
	}
	return b
}

func loadFixture(t *testing.T) deterministicFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/ed25519c_vectors.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx deterministicFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(fx.WithOpening) == 0 {
		t.Fatal("fixture has no with_opening vectors")
	}
	return fx
}

func TestBackendEnabledWithCgo(t *testing.T) {
	if !BackendEnabled() {
		t.Fatal("expected UNO backend enabled with cgo build")
	}
}

func TestElgamalRoundTripOpsWithCgo(t *testing.T) {
	priv := bytes.Repeat([]byte{1}, 32)
	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	ct5, err := Encrypt(pub, 5)
	if err != nil {
		t.Fatalf("Encrypt(5): %v", err)
	}
	ct3, err := Encrypt(pub, 3)
	if err != nil {
		t.Fatalf("Encrypt(3): %v", err)
	}
	sum, err := AddCompressedCiphertexts(ct5, ct3)
	if err != nil {
		t.Fatalf("AddCompressedCiphertexts: %v", err)
	}
	back, err := SubCompressedCiphertexts(sum, ct3)
	if err != nil {
		t.Fatalf("SubCompressedCiphertexts: %v", err)
	}
	norm5, err := NormalizeCompressed(ct5)
	if err != nil {
		t.Fatalf("NormalizeCompressed(ct5): %v", err)
	}
	normBack, err := NormalizeCompressed(back)
	if err != nil {
		t.Fatalf("NormalizeCompressed(back): %v", err)
	}
	if !bytes.Equal(norm5, normBack) {
		t.Fatal("ct add/sub roundtrip mismatch")
	}

	added, err := AddAmountCompressed(ct5, 2)
	if err != nil {
		t.Fatalf("AddAmountCompressed: %v", err)
	}
	restored, err := SubAmountCompressed(added, 2)
	if err != nil {
		t.Fatalf("SubAmountCompressed: %v", err)
	}
	normRestored, err := NormalizeCompressed(restored)
	if err != nil {
		t.Fatalf("NormalizeCompressed(restored): %v", err)
	}
	if !bytes.Equal(norm5, normRestored) {
		t.Fatal("ct add/sub amount roundtrip mismatch")
	}
}

func TestProofVerifyBackendPathWithCgo(t *testing.T) {
	// Zero bytes are invalid proofs; with cgo path enabled we should not hit backend-unavailable.
	err := VerifyShieldProof(make([]byte, 96), make([]byte, 32), make([]byte, 32), make([]byte, 32), 1)
	if err == nil {
		t.Fatal("expected invalid proof error")
	}
	if errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("unexpected backend unavailable: %v", err)
	}
}

func TestEncryptWithOpeningConsistencyWithCommitmentAndHandle(t *testing.T) {
	priv := make([]byte, 32)
	priv[0] = 7
	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	opening := make([]byte, 32)
	opening[0] = 1 // canonical scalar value 1

	commitment, err := PedersenCommitmentWithOpening(opening, 9)
	if err != nil {
		t.Fatalf("PedersenCommitmentWithOpening: %v", err)
	}
	handle, err := DecryptHandleWithOpening(pub, opening)
	if err != nil {
		t.Fatalf("DecryptHandleWithOpening: %v", err)
	}
	ct, err := EncryptWithOpening(pub, 9, opening)
	if err != nil {
		t.Fatalf("EncryptWithOpening: %v", err)
	}
	if len(ct) != 64 {
		t.Fatalf("unexpected ciphertext length %d", len(ct))
	}
	if !bytes.Equal(ct[:32], commitment) {
		t.Fatal("ciphertext commitment does not match derived commitment")
	}
	if !bytes.Equal(ct[32:], handle) {
		t.Fatal("ciphertext handle does not match derived decrypt handle")
	}
}

func TestDeterministicVectorsWithOpening(t *testing.T) {
	fx := loadFixture(t)

	for _, tc := range fx.WithOpening {
		t.Run(tc.Name, func(t *testing.T) {
			priv := mustDecodeHex(t, tc.PrivHex)
			opening := mustDecodeHex(t, tc.OpeningHex)

			pub, err := PublicKeyFromPrivate(priv)
			if err != nil {
				t.Fatalf("PublicKeyFromPrivate: %v", err)
			}
			if !bytes.Equal(pub, mustDecodeHex(t, tc.WantPubHex)) {
				t.Fatalf("pub mismatch: got=%x want=%s", pub, tc.WantPubHex)
			}

			commitment, err := PedersenCommitmentWithOpening(opening, tc.Amount)
			if err != nil {
				t.Fatalf("PedersenCommitmentWithOpening: %v", err)
			}
			if !bytes.Equal(commitment, mustDecodeHex(t, tc.WantComHex)) {
				t.Fatalf("commitment mismatch: got=%x want=%s", commitment, tc.WantComHex)
			}

			handle, err := DecryptHandleWithOpening(pub, opening)
			if err != nil {
				t.Fatalf("DecryptHandleWithOpening: %v", err)
			}
			if !bytes.Equal(handle, mustDecodeHex(t, tc.WantHandleHex)) {
				t.Fatalf("handle mismatch: got=%x want=%s", handle, tc.WantHandleHex)
			}

			ct, err := EncryptWithOpening(pub, tc.Amount, opening)
			if err != nil {
				t.Fatalf("EncryptWithOpening: %v", err)
			}
			if !bytes.Equal(ct, mustDecodeHex(t, tc.WantCtHex)) {
				t.Fatalf("ciphertext mismatch: got=%x want=%s", ct, tc.WantCtHex)
			}
		})
	}
}

func TestDeterministicCiphertextOpsVectors(t *testing.T) {
	fx := loadFixture(t)
	priv := mustDecodeHex(t, fx.CtOps.PrivHex)
	pub := mustDecodeHex(t, fx.CtOps.PubHex)
	opening1 := mustDecodeHex(t, fx.CtOps.Opening1Hex)
	opening2 := mustDecodeHex(t, fx.CtOps.Opening2Hex)

	ct9, err := EncryptWithOpening(pub, 9, opening1)
	if err != nil {
		t.Fatalf("EncryptWithOpening(ct9): %v", err)
	}
	wantCt9 := mustDecodeHex(t, fx.CtOps.Ct9Hex)
	if !bytes.Equal(ct9, wantCt9) {
		t.Fatalf("ct9 mismatch: got=%x want=%x", ct9, wantCt9)
	}

	ct4, err := EncryptWithOpening(pub, 4, opening2)
	if err != nil {
		t.Fatalf("EncryptWithOpening(ct4): %v", err)
	}
	wantCt4 := mustDecodeHex(t, fx.CtOps.Ct4Hex)
	if !bytes.Equal(ct4, wantCt4) {
		t.Fatalf("ct4 mismatch: got=%x want=%x", ct4, wantCt4)
	}

	add, err := AddCompressedCiphertexts(ct9, ct4)
	if err != nil {
		t.Fatalf("AddCompressedCiphertexts: %v", err)
	}
	wantAdd := mustDecodeHex(t, fx.CtOps.AddHex)
	if !bytes.Equal(add, wantAdd) {
		t.Fatalf("add mismatch: got=%x want=%x", add, wantAdd)
	}

	sub, err := SubCompressedCiphertexts(add, ct4)
	if err != nil {
		t.Fatalf("SubCompressedCiphertexts: %v", err)
	}
	wantSub := wantCt9
	if !bytes.Equal(sub, wantSub) {
		t.Fatalf("sub mismatch: got=%x want=%x", sub, wantSub)
	}

	addAmt, err := AddAmountCompressed(ct9, 5)
	if err != nil {
		t.Fatalf("AddAmountCompressed: %v", err)
	}
	wantAddAmt := mustDecodeHex(t, fx.CtOps.AddAmountHex)
	if !bytes.Equal(addAmt, wantAddAmt) {
		t.Fatalf("add amount mismatch: got=%x want=%x", addAmt, wantAddAmt)
	}

	addScalar, err := AddScalarCompressed(ct9, mustDecodeHex(t, fx.CtOps.Scalar5Hex))
	if err != nil {
		t.Fatalf("AddScalarCompressed: %v", err)
	}
	wantAddScalar := mustDecodeHex(t, fx.CtOps.AddScalarHex)
	if !bytes.Equal(addScalar, wantAddScalar) {
		t.Fatalf("add scalar mismatch: got=%x want=%x", addScalar, wantAddScalar)
	}

	subAmt, err := SubAmountCompressed(addAmt, 5)
	if err != nil {
		t.Fatalf("SubAmountCompressed: %v", err)
	}
	wantSubAmt := wantCt9
	if !bytes.Equal(subAmt, wantSubAmt) {
		t.Fatalf("sub amount mismatch: got=%x want=%x", subAmt, wantSubAmt)
	}

	subScalar, err := SubScalarCompressed(addScalar, mustDecodeHex(t, fx.CtOps.Scalar5Hex))
	if err != nil {
		t.Fatalf("SubScalarCompressed: %v", err)
	}
	wantSubScalar := mustDecodeHex(t, fx.CtOps.SubScalarHex)
	if !bytes.Equal(subScalar, wantSubScalar) {
		t.Fatalf("sub scalar mismatch: got=%x want=%x", subScalar, wantSubScalar)
	}

	mulScalar, err := MulScalarCompressed(ct9, mustDecodeHex(t, fx.CtOps.Scalar2Hex))
	if err != nil {
		t.Fatalf("MulScalarCompressed: %v", err)
	}
	wantMulScalar := mustDecodeHex(t, fx.CtOps.MulScalarHex)
	if !bytes.Equal(mulScalar, wantMulScalar) {
		t.Fatalf("mul scalar mismatch: got=%x want=%x", mulScalar, wantMulScalar)
	}

	pt9, err := DecryptToPoint(priv, ct9)
	if err != nil {
		t.Fatalf("DecryptToPoint: %v", err)
	}
	wantPt9 := mustDecodeHex(t, fx.CtOps.DecryptPointHex)
	if !bytes.Equal(pt9, wantPt9) {
		t.Fatalf("decrypt point mismatch: got=%x want=%x", pt9, wantPt9)
	}
}

func TestXelisDifferentialCiphertextOpsVectors(t *testing.T) {
	fx := loadXelisCtOpsFixture(t)
	priv := mustDecodeHex(t, fx.PrivHex)
	wantPub := mustDecodeHex(t, fx.PubHex)
	opening1 := mustDecodeHex(t, fx.Opening1Hex)
	opening2 := mustDecodeHex(t, fx.Opening2Hex)

	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	if !bytes.Equal(pub, wantPub) {
		t.Fatalf("pub mismatch: got=%x want=%x", pub, wantPub)
	}

	ct9, err := EncryptWithOpening(pub, 9, opening1)
	if err != nil {
		t.Fatalf("EncryptWithOpening(ct9): %v", err)
	}
	wantCt9 := mustDecodeHex(t, fx.Ct9Hex)
	if !bytes.Equal(ct9, wantCt9) {
		t.Fatalf("ct9 mismatch: got=%x want=%x", ct9, wantCt9)
	}

	ct4, err := EncryptWithOpening(pub, 4, opening2)
	if err != nil {
		t.Fatalf("EncryptWithOpening(ct4): %v", err)
	}
	wantCt4 := mustDecodeHex(t, fx.Ct4Hex)
	if !bytes.Equal(ct4, wantCt4) {
		t.Fatalf("ct4 mismatch: got=%x want=%x", ct4, wantCt4)
	}

	add, err := AddCompressedCiphertexts(ct9, ct4)
	if err != nil {
		t.Fatalf("AddCompressedCiphertexts: %v", err)
	}
	if want := mustDecodeHex(t, fx.AddHex); !bytes.Equal(add, want) {
		t.Fatalf("add mismatch: got=%x want=%x", add, want)
	}

	addAmt, err := AddAmountCompressed(ct9, 5)
	if err != nil {
		t.Fatalf("AddAmountCompressed: %v", err)
	}
	if want := mustDecodeHex(t, fx.AddAmountHex); !bytes.Equal(addAmt, want) {
		t.Fatalf("add amount mismatch: got=%x want=%x", addAmt, want)
	}

	addScalar, err := AddScalarCompressed(ct9, mustDecodeHex(t, fx.Scalar5Hex))
	if err != nil {
		t.Fatalf("AddScalarCompressed: %v", err)
	}
	if want := mustDecodeHex(t, fx.AddScalarHex); !bytes.Equal(addScalar, want) {
		t.Fatalf("add scalar mismatch: got=%x want=%x", addScalar, want)
	}

	subScalar, err := SubScalarCompressed(ct9, mustDecodeHex(t, fx.Scalar2Hex))
	if err != nil {
		t.Fatalf("SubScalarCompressed: %v", err)
	}
	if want := mustDecodeHex(t, fx.SubScalarHex); !bytes.Equal(subScalar, want) {
		t.Fatalf("sub scalar mismatch: got=%x want=%x", subScalar, want)
	}

	mulScalar, err := MulScalarCompressed(ct9, mustDecodeHex(t, fx.Scalar2Hex))
	if err != nil {
		t.Fatalf("MulScalarCompressed: %v", err)
	}
	if want := mustDecodeHex(t, fx.MulScalarHex); !bytes.Equal(mulScalar, want) {
		t.Fatalf("mul scalar mismatch: got=%x want=%x", mulScalar, want)
	}

	zero, err := ZeroCiphertextCompressed()
	if err != nil {
		t.Fatalf("ZeroCiphertextCompressed: %v", err)
	}
	if want := mustDecodeHex(t, fx.ZeroHex); !bytes.Equal(zero, want) {
		t.Fatalf("zero mismatch: got=%x want=%x", zero, want)
	}

	decryptedPoint, err := DecryptToPoint(priv, ct9)
	if err != nil {
		t.Fatalf("DecryptToPoint: %v", err)
	}
	if want := mustDecodeHex(t, fx.DecryptPointHex); !bytes.Equal(decryptedPoint, want) {
		t.Fatalf("decrypt point mismatch: got=%x want=%x", decryptedPoint, want)
	}
}

func TestInvalidInputMappingWithCgo(t *testing.T) {
	cases := []struct {
		name string
		fn   func() error
	}{
		{
			name: "AddCompressedCiphertexts bad len",
			fn: func() error {
				_, err := AddCompressedCiphertexts(make([]byte, 63), make([]byte, 64))
				return err
			},
		},
		{
			name: "SubAmountCompressed bad len",
			fn: func() error {
				_, err := SubAmountCompressed(make([]byte, 65), 1)
				return err
			},
		},
		{
			name: "AddScalarCompressed bad scalar len",
			fn: func() error {
				_, err := AddScalarCompressed(make([]byte, 64), make([]byte, 31))
				return err
			},
		},
		{
			name: "MulScalarCompressed bad ct len",
			fn: func() error {
				_, err := MulScalarCompressed(make([]byte, 63), make([]byte, 32))
				return err
			},
		},
		{
			name: "PublicKeyFromPrivate bad len",
			fn: func() error {
				_, err := PublicKeyFromPrivate(make([]byte, 31))
				return err
			},
		},
		{
			name: "EncryptWithOpening bad pub",
			fn: func() error {
				_, err := EncryptWithOpening(make([]byte, 31), 1, make([]byte, 32))
				return err
			},
		},
		{
			name: "EncryptWithOpening bad opening",
			fn: func() error {
				_, err := EncryptWithOpening(make([]byte, 32), 1, make([]byte, 31))
				return err
			},
		},
		{
			name: "PedersenCommitmentWithOpening bad len",
			fn: func() error {
				_, err := PedersenCommitmentWithOpening(make([]byte, 31), 1)
				return err
			},
		},
		{
			name: "DecryptHandleWithOpening bad len",
			fn: func() error {
				_, err := DecryptHandleWithOpening(make([]byte, 32), make([]byte, 31))
				return err
			},
		},
		{
			name: "VerifyShieldProof bad len",
			fn: func() error {
				return VerifyShieldProof(make([]byte, 95), make([]byte, 32), make([]byte, 32), make([]byte, 32), 1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("expected ErrInvalidInput, got %v", err)
			}
		})
	}
}

func TestScalarOpsConsistencyWithCgo(t *testing.T) {
	fx := loadFixture(t)
	priv := bytes.Repeat([]byte{1}, 32)
	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	ct, err := Encrypt(pub, 9)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	scalarFive := mustDecodeHex(t, fx.CtOps.Scalar5Hex)
	scalarTwo := mustDecodeHex(t, fx.CtOps.Scalar2Hex)

	byScalar, err := AddScalarCompressed(ct, scalarFive)
	if err != nil {
		t.Fatalf("AddScalarCompressed: %v", err)
	}
	byAmount, err := AddAmountCompressed(ct, 5)
	if err != nil {
		t.Fatalf("AddAmountCompressed: %v", err)
	}
	normScalar, err := NormalizeCompressed(byScalar)
	if err != nil {
		t.Fatalf("NormalizeCompressed(scalar): %v", err)
	}
	normAmount, err := NormalizeCompressed(byAmount)
	if err != nil {
		t.Fatalf("NormalizeCompressed(amount): %v", err)
	}
	if !bytes.Equal(normScalar, normAmount) {
		t.Fatal("add scalar and add amount mismatch")
	}

	back, err := SubScalarCompressed(byScalar, scalarFive)
	if err != nil {
		t.Fatalf("SubScalarCompressed: %v", err)
	}
	normBack, err := NormalizeCompressed(back)
	if err != nil {
		t.Fatalf("NormalizeCompressed(back): %v", err)
	}
	normOrig, err := NormalizeCompressed(ct)
	if err != nil {
		t.Fatalf("NormalizeCompressed(orig): %v", err)
	}
	if !bytes.Equal(normBack, normOrig) {
		t.Fatal("sub scalar did not revert add scalar")
	}

	doubled, err := AddCompressedCiphertexts(ct, ct)
	if err != nil {
		t.Fatalf("AddCompressedCiphertexts: %v", err)
	}
	multiplied, err := MulScalarCompressed(ct, scalarTwo)
	if err != nil {
		t.Fatalf("MulScalarCompressed: %v", err)
	}
	normDouble, err := NormalizeCompressed(doubled)
	if err != nil {
		t.Fatalf("NormalizeCompressed(double): %v", err)
	}
	normMul, err := NormalizeCompressed(multiplied)
	if err != nil {
		t.Fatalf("NormalizeCompressed(mul): %v", err)
	}
	if !bytes.Equal(normDouble, normMul) {
		t.Fatal("mul scalar(2) and ciphertext doubling mismatch")
	}
}

func TestGeneratedOpeningAndKeypairConsistency(t *testing.T) {
	opening, err := GenerateOpening()
	if err != nil {
		t.Fatalf("GenerateOpening: %v", err)
	}
	if len(opening) != 32 {
		t.Fatalf("unexpected opening length: %d", len(opening))
	}
	allZero := true
	for _, b := range opening {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("generated opening must be non-zero")
	}

	amount := uint64(777)
	commitment, opening2, err := CommitmentNew(amount)
	if err != nil {
		t.Fatalf("CommitmentNew: %v", err)
	}
	commitmentByOpening, err := PedersenCommitmentWithOpening(opening2, amount)
	if err != nil {
		t.Fatalf("PedersenCommitmentWithOpening: %v", err)
	}
	if !bytes.Equal(commitment, commitmentByOpening) {
		t.Fatal("CommitmentNew mismatch with CommitmentWithOpening")
	}

	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	derivedPub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	if !bytes.Equal(pub, derivedPub) {
		t.Fatal("generated keypair pubkey mismatch with derived pubkey")
	}

	ct, opening3, err := EncryptWithGeneratedOpening(pub, amount)
	if err != nil {
		t.Fatalf("EncryptWithGeneratedOpening: %v", err)
	}
	ctByOpening, err := EncryptWithOpening(pub, amount, opening3)
	if err != nil {
		t.Fatalf("EncryptWithOpening: %v", err)
	}
	if !bytes.Equal(ct, ctByOpening) {
		t.Fatal("EncryptWithGeneratedOpening mismatch with EncryptWithOpening")
	}

	addrMainnet, err := PublicKeyToAddress(pub, true)
	if err != nil {
		t.Fatalf("PublicKeyToAddress(mainnet): %v", err)
	}
	addrMainnet2, err := PublicKeyToAddress(pub, true)
	if err != nil {
		t.Fatalf("PublicKeyToAddress(mainnet second): %v", err)
	}
	if addrMainnet == "" || addrMainnet != addrMainnet2 {
		t.Fatal("mainnet address must be non-empty and deterministic")
	}
	addrTestnet, err := PublicKeyToAddress(pub, false)
	if err != nil {
		t.Fatalf("PublicKeyToAddress(testnet): %v", err)
	}
	if addrTestnet == "" {
		t.Fatal("testnet address must be non-empty")
	}
	if addrMainnet == addrTestnet {
		t.Fatal("mainnet and testnet addresses should differ")
	}
}

func TestZeroCiphertextPropertiesWithCgo(t *testing.T) {
	fx := loadFixture(t)
	zero, err := ZeroCiphertextCompressed()
	if err != nil {
		t.Fatalf("ZeroCiphertextCompressed: %v", err)
	}
	if len(zero) != 64 {
		t.Fatalf("unexpected zero ciphertext length %d", len(zero))
	}
	normZero, err := NormalizeCompressed(zero)
	if err != nil {
		t.Fatalf("NormalizeCompressed(zero): %v", err)
	}
	if !bytes.Equal(zero, normZero) {
		t.Fatal("zero ciphertext should already be normalized")
	}
	wantZero := mustDecodeHex(t, fx.CtOps.ZeroHex)
	if !bytes.Equal(zero, wantZero) {
		t.Fatalf("zero ciphertext mismatch: got=%x want=%x", zero, wantZero)
	}

	priv := bytes.Repeat([]byte{1}, 32)
	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	ct, err := Encrypt(pub, 11)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	add, err := AddCompressedCiphertexts(ct, zero)
	if err != nil {
		t.Fatalf("AddCompressedCiphertexts(ct, zero): %v", err)
	}
	sub, err := SubCompressedCiphertexts(ct, zero)
	if err != nil {
		t.Fatalf("SubCompressedCiphertexts(ct, zero): %v", err)
	}
	normCt, err := NormalizeCompressed(ct)
	if err != nil {
		t.Fatalf("NormalizeCompressed(ct): %v", err)
	}
	normAdd, err := NormalizeCompressed(add)
	if err != nil {
		t.Fatalf("NormalizeCompressed(add): %v", err)
	}
	normSub, err := NormalizeCompressed(sub)
	if err != nil {
		t.Fatalf("NormalizeCompressed(sub): %v", err)
	}
	if !bytes.Equal(normCt, normAdd) || !bytes.Equal(normCt, normSub) {
		t.Fatal("zero ciphertext identity property failed")
	}
}
