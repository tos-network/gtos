package tosapi

import (
	"context"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/tos-network/gtos"
	"github.com/tos-network/gtos/accounts"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/consensus"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/bloombits"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/event"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/rpc"
	"github.com/tos-network/gtos/tosdb"
)

// TestSetFeeDefaults tests the logic for filling in default fee values works as expected.
func TestSetFeeDefaults(t *testing.T) {
	type test struct {
		name     string
		isLondon bool
		in       *TransactionArgs
		want     *TransactionArgs
		err      error
	}

	var (
		b        = newBackendMock()
		fortytwo = (*hexutil.Big)(big.NewInt(42))
		maxFee   = (*hexutil.Big)(big.NewInt(62))
		al       = &types.AccessList{types.AccessTuple{Address: common.Address{0xaa}, StorageKeys: []common.Hash{{0x01}}}}
	)

	tests := []test{
		{
			"legacy tx pre-London",
			false,
			&TransactionArgs{},
			&TransactionArgs{GasPrice: fortytwo},
			nil,
		},
		{
			"legacy tx post-London, explicit gas price",
			true,
			&TransactionArgs{GasPrice: fortytwo},
			&TransactionArgs{GasPrice: fortytwo},
			nil,
		},
		{
			"access list tx pre-London",
			false,
			&TransactionArgs{AccessList: al},
			&TransactionArgs{AccessList: al, GasPrice: fortytwo},
			nil,
		},
		{
			"access list tx post-London",
			true,
			&TransactionArgs{AccessList: al},
			&TransactionArgs{AccessList: al, GasPrice: fortytwo},
			nil,
		},
		{
			"dynamic fee tx pre-London, maxFee set",
			false,
			&TransactionArgs{MaxFeePerGas: maxFee},
			nil,
			fmt.Errorf("maxFeePerGas/maxPriorityFeePerGas are not supported in GTOS; use gasPrice"),
		},
		{
			"dynamic fee tx post-London, priorityFee set",
			true,
			&TransactionArgs{MaxPriorityFeePerGas: fortytwo},
			nil,
			fmt.Errorf("maxFeePerGas/maxPriorityFeePerGas are not supported in GTOS; use gasPrice"),
		},
		{
			"set all fee parameters",
			false,
			&TransactionArgs{GasPrice: fortytwo, MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
			fmt.Errorf("maxFeePerGas/maxPriorityFeePerGas are not supported in GTOS; use gasPrice"),
		},
	}

	ctx := context.Background()
	for i, test := range tests {
		if test.isLondon {
			b.activateLondon()
		} else {
			b.deactivateLondon()
		}
		got := test.in
		err := got.setFeeDefaults(ctx, b)
		if err != nil && err.Error() == test.err.Error() {
			// Test threw expected error.
			continue
		} else if err != nil {
			t.Fatalf("test %d (%s): unexpected error: %s", i, test.name, err)
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Fatalf("test %d (%s): did not fill defaults as expected: (got: %v, want: %v)", i, test.name, got, test.want)
		}
	}
}

type backendMock struct {
	current *types.Header
	config  *params.ChainConfig
}

func newBackendMock() *backendMock {
	config := &params.ChainConfig{
		ChainID:        big.NewInt(42),
		AIGenesisBlock: big.NewInt(1000),
	}
	return &backendMock{
		current: &types.Header{
			Difficulty: big.NewInt(10000000000),
			Number:     big.NewInt(1100),
			GasLimit:   8_000_000,
			GasUsed:    8_000_000,
			Time:       555,
			Extra:      make([]byte, 32),
			BaseFee:    big.NewInt(10),
		},
		config: config,
	}
}

func (b *backendMock) activateLondon() {
	b.current.Number = big.NewInt(1100)
}

func (b *backendMock) deactivateLondon() {
	b.current.Number = big.NewInt(900)
}
func (b *backendMock) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	return big.NewInt(42), nil
}
func (b *backendMock) CurrentHeader() *types.Header     { return b.current }
func (b *backendMock) ChainConfig() *params.ChainConfig { return b.config }

// Other methods needed to implement Backend interface.
func (b *backendMock) SyncProgress() gtos.SyncProgress { return gtos.SyncProgress{} }
func (b *backendMock) FeeHistory(ctx context.Context, blockCount int, lastBlock rpc.BlockNumber, rewardPercentiles []float64) (*big.Int, [][]*big.Int, []*big.Int, []float64, error) {
	return nil, nil, nil, nil, nil
}
func (b *backendMock) ChainDb() tosdb.Database           { return nil }
func (b *backendMock) AccountManager() *accounts.Manager { return nil }
func (b *backendMock) ExtRPCEnabled() bool               { return false }
func (b *backendMock) RPCGasCap() uint64                 { return 0 }
func (b *backendMock) RPCEVMTimeout() time.Duration      { return time.Second }
func (b *backendMock) RPCTxFeeCap() float64              { return 0 }
func (b *backendMock) UnprotectedAllowed() bool          { return false }
func (b *backendMock) SetHead(number uint64)             {}
func (b *backendMock) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	return nil, nil
}
func (b *backendMock) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return nil, nil
}
func (b *backendMock) HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	return nil, nil
}
func (b *backendMock) CurrentBlock() *types.Block { return nil }
func (b *backendMock) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	return nil, nil
}
func (b *backendMock) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return nil, nil
}
func (b *backendMock) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	return nil, nil
}
func (b *backendMock) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	return nil, nil, nil
}
func (b *backendMock) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	return nil, nil, nil
}
func (b *backendMock) PendingBlockAndReceipts() (*types.Block, types.Receipts) { return nil, nil }
func (b *backendMock) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	return nil, nil
}
func (b *backendMock) GetLogs(ctx context.Context, blockHash common.Hash, number uint64) ([][]*types.Log, error) {
	return nil, nil
}
func (b *backendMock) GetTd(ctx context.Context, hash common.Hash) *big.Int             { return nil }
func (b *backendMock) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription { return nil }
func (b *backendMock) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return nil
}
func (b *backendMock) SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription {
	return nil
}
func (b *backendMock) SendTx(ctx context.Context, signedTx *types.Transaction) error { return nil }
func (b *backendMock) GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	return nil, [32]byte{}, 0, 0, nil
}
func (b *backendMock) GetPoolTransactions() (types.Transactions, error)         { return nil, nil }
func (b *backendMock) GetPoolTransaction(txHash common.Hash) *types.Transaction { return nil }
func (b *backendMock) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return 0, nil
}
func (b *backendMock) Stats() (pending int, queued int) { return 0, 0 }
func (b *backendMock) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return nil, nil
}
func (b *backendMock) TxPoolContentFrom(addr common.Address) (types.Transactions, types.Transactions) {
	return nil, nil
}
func (b *backendMock) SubscribeNewTxsEvent(chan<- core.NewTxsEvent) event.Subscription      { return nil }
func (b *backendMock) BloomStatus() (uint64, uint64)                                        { return 0, 0 }
func (b *backendMock) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {}
func (b *backendMock) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription         { return nil }
func (b *backendMock) SubscribePendingLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return nil
}
func (b *backendMock) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return nil
}

func (b *backendMock) Engine() consensus.Engine { return nil }
