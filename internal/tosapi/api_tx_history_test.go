package tosapi

import (
	"context"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
)

type txHistoryBackendMock struct {
	*backendMock
	tx          *types.Transaction
	blockHash   common.Hash
	blockNumber uint64
	index       uint64

	headerByHashCalled bool
	receiptsCalled     bool
}

func (b *txHistoryBackendMock) GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	if b.tx == nil || txHash != b.tx.Hash() {
		return nil, common.Hash{}, 0, 0, nil
	}
	return b.tx, b.blockHash, b.blockNumber, b.index, nil
}

func (b *txHistoryBackendMock) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	b.headerByHashCalled = true
	return &types.Header{Number: new(big.Int).SetUint64(b.blockNumber), BaseFee: big.NewInt(1)}, nil
}

func (b *txHistoryBackendMock) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	b.receiptsCalled = true
	return types.Receipts{
		&types.Receipt{
			GasUsed:           21_000,
			CumulativeGasUsed: 21_000,
			Status:            types.ReceiptStatusSuccessful,
		},
	}, nil
}

func newHistoryTestTx() *types.Transaction {
	from := common.HexToAddress("0x74c5f09f80cc62940a4f392f067a68b40696c06bf8e31f973efee01156caea5f")
	to := common.HexToAddress("0xd885744b9cb252077d755ad317c5185167401ed00cf5f5b2fc97d9bbfdb7d025")
	return types.NewTx(&types.SignerTx{
		ChainID:    big.NewInt(42),
		Nonce:      0,
		GasPrice:   big.NewInt(1),
		Gas:        21_000,
		To:         &to,
		Value:      big.NewInt(1),
		Data:       nil,
		From:       from,
		SignerType: "secp256k1",
		V:          big.NewInt(0),
		R:          big.NewInt(1),
		S:          big.NewInt(1),
	})
}

func TestTransactionLookupHistoryPruned(t *testing.T) {
	tx := newHistoryTestTx()
	backend := &txHistoryBackendMock{
		backendMock: newBackendMock(), // head=1100, retain=200 -> oldest available=901
		tx:          tx,
		blockHash:   common.HexToHash("0x1"),
		blockNumber: 900,
		index:       0,
	}
	api := NewTransactionAPI(backend, new(AddrLocker))

	_, err := api.GetTransactionByHash(context.Background(), tx.Hash())
	if err == nil {
		t.Fatalf("expected history pruned error")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrHistoryPruned {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrHistoryPruned)
	}
	if backend.headerByHashCalled {
		t.Fatalf("header lookup should not run for pruned transaction")
	}

	_, err = api.GetRawTransactionByHash(context.Background(), tx.Hash())
	if err == nil {
		t.Fatalf("expected history pruned error for raw transaction")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrHistoryPruned {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrHistoryPruned)
	}

	_, err = api.GetTransactionReceipt(context.Background(), tx.Hash())
	if err == nil {
		t.Fatalf("expected history pruned error for receipt")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrHistoryPruned {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrHistoryPruned)
	}
	if backend.receiptsCalled {
		t.Fatalf("receipt lookup should not run for pruned transaction")
	}
}
