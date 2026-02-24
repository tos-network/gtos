package types

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/rlp"
)

type devnull struct{ len int }

func (d *devnull) Write(p []byte) (int, error) {
	d.len += len(p)
	return len(p), nil
}

func BenchmarkEncodeRLP(b *testing.B) {
	benchRLP(b, true)
}

func BenchmarkDecodeRLP(b *testing.B) {
	benchRLP(b, false)
}

func benchRLP(b *testing.B, encode bool) {
	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	to := common.HexToAddress("0xe8b0087eec10090b15f4fc4bc96aaa54e2d44c299564da76e1cd3184a2386b8d")
	signer := NewLondonSigner(big.NewInt(1337))
	for _, tc := range []struct {
		name string
		obj  interface{}
	}{
		{
			"legacy-header",
			&Header{
				Difficulty: big.NewInt(10000000000),
				Number:     big.NewInt(1000),
				GasLimit:   8_000_000,
				GasUsed:    8_000_000,
				Time:       555,
				Extra:      make([]byte, 32),
			},
		},
		{
			"london-header",
			&Header{
				Difficulty: big.NewInt(10000000000),
				Number:     big.NewInt(1000),
				GasLimit:   8_000_000,
				GasUsed:    8_000_000,
				Time:       555,
				Extra:      make([]byte, 32),
				BaseFee:    big.NewInt(10000000000),
			},
		},
		{
			"receipt-for-storage",
			&ReceiptForStorage{
				Status:            ReceiptStatusSuccessful,
				CumulativeGasUsed: 0x888888888,
				Logs:              make([]*Log, 0),
			},
		},
		{
			"receipt-full",
			&Receipt{
				Status:            ReceiptStatusSuccessful,
				CumulativeGasUsed: 0x888888888,
				Logs:              make([]*Log, 0),
			},
		},
		{
			"signer-transaction",
			MustSignNewTx(key, signer,
				&SignerTx{
					ChainID:    big.NewInt(1337),
					Nonce:      1,
					Gas:        1000000,
					To:         &to,
					Value:      big.NewInt(1),
					From:       crypto.PubkeyToAddress(key.PublicKey),
					SignerType: "secp256k1",
				}),
		},
	} {
		if encode {
			b.Run(tc.name, func(b *testing.B) {
				b.ReportAllocs()
				var null = &devnull{}
				for i := 0; i < b.N; i++ {
					rlp.Encode(null, tc.obj)
				}
				b.SetBytes(int64(null.len / b.N))
			})
		} else {
			data, _ := rlp.EncodeToBytes(tc.obj)
			// Test decoding
			b.Run(tc.name, func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if err := rlp.DecodeBytes(data, tc.obj); err != nil {
						b.Fatal(err)
					}
				}
				b.SetBytes(int64(len(data)))
			})
		}
	}
}
