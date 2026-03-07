package tosapi

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tos-network/gtos"
	"github.com/tos-network/gtos/accounts"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/consensus"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/rawdb"
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
		b      = newBackendMock()
		maxFee = (*hexutil.Big)(big.NewInt(62))
		al     = &types.AccessList{types.AccessTuple{Address: common.Address{0xaa}, StorageKeys: []common.Hash{{0x01}}}}
	)

	tests := []test{
		{
			"legacy tx without base fee",
			false,
			&TransactionArgs{},
			&TransactionArgs{},
			nil,
		},
		{
			"legacy tx with base fee",
			true,
			&TransactionArgs{},
			&TransactionArgs{},
			nil,
		},
		{
			"access list tx without base fee",
			false,
			&TransactionArgs{AccessList: al},
			&TransactionArgs{AccessList: al},
			nil,
		},
		{
			"access list tx with base fee",
			true,
			&TransactionArgs{AccessList: al},
			&TransactionArgs{AccessList: al},
			nil,
		},
		{
			"dynamic fee tx without base fee, maxFee set",
			false,
			&TransactionArgs{MaxFeePerGas: maxFee},
			nil,
			fmt.Errorf("maxFeePerGas/maxPriorityFeePerGas are not supported in GTOS"),
		},
		{
			"dynamic fee tx with base fee, priorityFee set",
			true,
			&TransactionArgs{MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1))},
			nil,
			fmt.Errorf("maxFeePerGas/maxPriorityFeePerGas are not supported in GTOS"),
		},
		{
			"set all fee parameters",
			false,
			&TransactionArgs{MaxFeePerGas: maxFee, MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1))},
			nil,
			fmt.Errorf("maxFeePerGas/maxPriorityFeePerGas are not supported in GTOS"),
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

func TestEstimateStorageFirstGas(t *testing.T) {
	from := common.HexToAddress("0x85b1F044Bab6D30F3A19c1501563915E194D8CFBa1943570603f7606a3115508")

	toTransfer := common.HexToAddress("0x6ab1757c2549dcaafeF121277564105e977516c53be337314C7E53838967bDAC")
	transferGas, err := estimateStorageFirstGas(TransactionArgs{
		From: &from,
		To:   &toTransfer,
	})
	if err != nil {
		t.Fatalf("transfer gas estimate failed: %v", err)
	}
	if uint64(transferGas) != params.TxGas {
		t.Fatalf("unexpected transfer gas: have %d want %d", transferGas, params.TxGas)
	}

	systemPayload := hexutil.Bytes{0x01, 0x02}
	toSystem := params.SystemActionAddress
	systemGas, err := estimateStorageFirstGas(TransactionArgs{
		From:  &from,
		To:    &toSystem,
		Input: &systemPayload,
	})
	if err != nil {
		t.Fatalf("system action gas estimate failed: %v", err)
	}
	wantSystem, err := estimateSystemActionGas(systemPayload)
	if err != nil {
		t.Fatalf("system action intrinsic helper failed: %v", err)
	}
	if uint64(systemGas) != wantSystem {
		t.Fatalf("unexpected system action gas: have %d want %d", systemGas, wantSystem)
	}

	callData := hexutil.Bytes{0x60, 0x00}
	callGas, err := estimateStorageFirstGas(TransactionArgs{
		From:  &from,
		To:    &toTransfer,
		Input: &callData,
	})
	if err != nil {
		t.Fatalf("unexpected error for non-system calldata fallback estimate: %v", err)
	}
	if uint64(callGas) != params.TxGas {
		t.Fatalf("unexpected non-system calldata fallback gas: have %d want %d", callGas, params.TxGas)
	}

	// Contract creation (to=nil): standard CREATE gas = intrinsic + 200 gas/byte.
	luaCode := hexutil.Bytes{0x60, 0x00, 0x60, 0x01}
	createGas, err := estimateStorageFirstGas(TransactionArgs{
		From:  &from,
		To:    nil,
		Input: &luaCode,
	})
	if err != nil {
		t.Fatalf("create gas estimate failed: %v", err)
	}
	wantIntrinsic, err := core.IntrinsicGas(luaCode, nil, true, true, true)
	if err != nil {
		t.Fatalf("intrinsic gas failed: %v", err)
	}
	wantCreate := wantIntrinsic + uint64(len(luaCode))*200
	if uint64(createGas) != wantCreate {
		t.Fatalf("unexpected create gas: have %d want %d", createGas, wantCreate)
	}
}

func TestSetDefaultsUsesDoEstimateGasForContractCalldata(t *testing.T) {
	b := newBackendMock()
	marker := errors.New("estimate branch reached")
	b.blockByNumberOrHashErr = marker

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	calldata := hexutil.Bytes{0x60, 0x00}
	args := &TransactionArgs{
		From:  &from,
		To:    &to,
		Input: &calldata,
	}
	err := args.setDefaults(context.Background(), b)
	if !errors.Is(err, marker) {
		t.Fatalf("expected DoEstimateGas branch error %q, got %v", marker, err)
	}
	if strings.Contains(err.Error(), "cannot auto-estimate gas for calldata to non-system address") {
		t.Fatalf("setDefaults fell back to estimateStorageFirstGas branch, err=%v", err)
	}
}

func TestDoEstimateGasCapsByFundsBeforeBinarySearch(t *testing.T) {
	b := newBackendMock()
	from := common.HexToAddress("0x3333333333333333333333333333333333333333")
	to := common.HexToAddress("0x4444444444444444444444444444444444444444")

	allowance := params.TxGas - 1000 // deliberately below intrinsic transfer gas
	statedb := mustNewStateDB(t)
	statedb.AddBalance(from, new(big.Int).Mul(new(big.Int).SetUint64(allowance), params.TxPrice()))

	b.state = statedb
	b.current = &types.Header{
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		GasLimit:   1_000_000,
		Time:       1,
		BaseFee:    new(big.Int).Set(params.TxPrice()),
	}
	b.block = types.NewBlockWithHeader(b.current)

	_, err := DoEstimateGas(
		context.Background(),
		b,
		TransactionArgs{From: &from, To: &to},
		rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber),
		0,
	)
	if err == nil {
		t.Fatalf("expected allowance error, got nil")
	}
	want := fmt.Sprintf("gas required exceeds allowance (%d)", allowance)
	if err.Error() != want {
		t.Fatalf("unexpected error: have %q want %q", err.Error(), want)
	}
}

type backendMock struct {
	current *types.Header
	config  *params.ChainConfig
	engine  consensus.Engine

	block *types.Block
	state *state.StateDB

	blockByNumberOrHashErr          error
	stateAndHeaderByNumberOrHashErr error
}

func newBackendMock() *backendMock {
	config := &params.ChainConfig{
		ChainID: big.NewInt(42),
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
		engine: dpos.NewFaker(),
	}
}

func (b *backendMock) activateLondon() {
	b.current.Number = big.NewInt(1100)
}

func (b *backendMock) deactivateLondon() {
	b.current.Number = big.NewInt(900)
}
func (b *backendMock) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	return params.TxPrice(), nil
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
func (b *backendMock) CurrentFinalizedBlock() *types.Block { return nil }
func (b *backendMock) CurrentBlock() *types.Block {
	if b.block != nil {
		return b.block
	}
	return types.NewBlockWithHeader(b.current)
}
func (b *backendMock) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	return b.BlockByNumberOrHash(ctx, rpc.BlockNumberOrHashWithNumber(number))
}
func (b *backendMock) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	if b.block != nil && b.block.Hash() == hash {
		return b.block, nil
	}
	return nil, nil
}
func (b *backendMock) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	if b.blockByNumberOrHashErr != nil {
		return nil, b.blockByNumberOrHashErr
	}
	if b.block != nil {
		return b.block, nil
	}
	return types.NewBlockWithHeader(b.current), nil
}
func (b *backendMock) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	return b.StateAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithNumber(number))
}
func (b *backendMock) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	if b.stateAndHeaderByNumberOrHashErr != nil {
		return nil, nil, b.stateAndHeaderByNumberOrHashErr
	}
	if b.state == nil {
		return nil, b.current, nil
	}
	return b.state.Copy(), b.current, nil
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

func (b *backendMock) Engine() consensus.Engine                    { return b.engine }
func (b *backendMock) FinalizedValidatorSetHash() common.Hash      { return common.Hash{} }

func mustNewStateDB(t *testing.T) *state.StateDB {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	statedb, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
	if err != nil {
		t.Fatalf("create statedb: %v", err)
	}
	return statedb
}

func rpcBlockPtr(number rpc.BlockNumber) *rpc.BlockNumberOrHash {
	v := rpc.BlockNumberOrHashWithNumber(number)
	return &v
}
