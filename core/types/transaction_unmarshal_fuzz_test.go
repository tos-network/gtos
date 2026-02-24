package types

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
)

func signerTxFuzzSeedRaw() []byte {
	to := common.HexToAddress("0x969b0a11b8a56bacf1ac18f219e7e376e7c213b7e7e7e46cc70a5dd086daff2a")
	from := common.HexToAddress("0x85b1f044bab6d30f3a19c1501563915e194d8cfba1943570603f7606a3115508")
	tx := NewTx(&SignerTx{
		ChainID:    big.NewInt(42),
		Nonce:      1,
		Gas:        21_000,
		To:         &to,
		Value:      big.NewInt(0),
		Data:       []byte{0x01, 0x02},
		AccessList: nil,
		From:       from,
		SignerType: "secp256k1",
		V:          big.NewInt(0),
		R:          big.NewInt(1),
		S:          big.NewInt(1),
	})
	raw, err := tx.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return raw
}

func FuzzTransactionUnmarshalBinarySignerTx(f *testing.F) {
	f.Add([]byte{SignerTxType})
	f.Add(signerTxFuzzSeedRaw())
	f.Add([]byte{SignerTxType, 0x80})

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 8192 {
			return
		}
		var tx Transaction
		if err := tx.UnmarshalBinary(input); err != nil {
			return
		}
		if tx.Type() != SignerTxType {
			t.Fatalf("decoded unexpected tx type=%d", tx.Type())
		}
		if tx.ChainId() == nil {
			t.Fatalf("decoded signer tx has nil chain id")
		}
		if _, ok := tx.SignerFrom(); !ok {
			t.Fatalf("decoded signer tx missing from")
		}
		if signerType, ok := tx.SignerType(); !ok || signerType == "" {
			t.Fatalf("decoded signer tx missing signerType")
		}
		raw, err := tx.MarshalBinary()
		if err != nil {
			t.Fatalf("decoded signer tx cannot marshal: %v", err)
		}
		var roundTrip Transaction
		if err := roundTrip.UnmarshalBinary(raw); err != nil {
			t.Fatalf("round-trip unmarshal failed: %v", err)
		}
	})
}
