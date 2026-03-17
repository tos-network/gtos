package auditreceipt

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/internal/testfixtures"
)

func benchHeader() *types.Header {
	return &types.Header{
		Number: big.NewInt(1_000_000),
		Time:   1700000000,
	}
}

func benchReceipt(txHash common.Hash) *types.Receipt {
	return &types.Receipt{
		Type:              types.SignerTxType,
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: 50000,
		GasUsed:           50000,
		TxHash:            txHash,
	}
}

func benchTx() *types.Transaction {
	to := testfixtures.Secp256k1AddrC
	return types.NewTx(&types.SignerTx{
		ChainID:    big.NewInt(1),
		Nonce:      42,
		Gas:        50000,
		To:         &to,
		Value:      big.NewInt(1_000_000),
		Data:       []byte{0x01, 0x02, 0x03},
		From:       testfixtures.Secp256k1AddrA,
		SignerType: "secp256k1",
		V:          big.NewInt(0),
		R:          big.NewInt(0),
		S:          big.NewInt(0),
		SponsorV:   big.NewInt(0),
		SponsorR:   big.NewInt(0),
		SponsorS:   big.NewInt(0),
	})
}

func BenchmarkBuildFromReceipt(b *testing.B) {
	tx := benchTx()
	txHash := tx.Hash()
	receipt := benchReceipt(txHash)
	header := benchHeader()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildFromReceipt(receipt, tx, header)
	}
}

func BenchmarkComputeReceiptHash(b *testing.B) {
	ar := &AuditReceipt{
		TxHash:      common.HexToHash("0xdeadbeefdeadbeef"),
		BlockNumber: 1_000_000,
		Status:      1,
		GasUsed:     50000,
		From:        testfixtures.Secp256k1AddrA,
		To:          testfixtures.Secp256k1AddrC,
		Sponsor:     testfixtures.Secp256k1AddrB,
		Value:       big.NewInt(1_000_000),
		SettledAt:   1700000000,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeReceiptHash(ar)
	}
}

func BenchmarkBuildSessionProof(b *testing.B) {
	txHash := common.HexToHash("0xdeadbeefdeadbeef")
	account := testfixtures.Secp256k1AddrA

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildSessionProof(txHash, "session-bench-001", "app", "terminal-xyz", 3, account, 1700000000)
	}
}
