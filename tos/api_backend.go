package tos

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/tos-network/gtos"
	"github.com/tos-network/gtos/accounts"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/bloombits"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/event"
	"github.com/tos-network/gtos/miner"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/rpc"
	"github.com/tos-network/gtos/tosdb"
)

// TOSAPIBackend implements tosapi.Backend for full nodes
type TOSAPIBackend struct {
	extRPCEnabled bool
	tos           *TOS
}

// ChainConfig returns the active chain configuration.
func (b *TOSAPIBackend) ChainConfig() *params.ChainConfig {
	return b.tos.blockchain.Config()
}

func (b *TOSAPIBackend) CurrentBlock() *types.Block {
	return b.tos.blockchain.CurrentBlock()
}

func (b *TOSAPIBackend) SetHead(number uint64) {
	b.tos.handler.downloader.Cancel()
	b.tos.blockchain.SetHead(number)
}

func (b *TOSAPIBackend) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	// Pending block is only known by the miner
	if number == rpc.PendingBlockNumber {
		block := b.tos.miner.PendingBlock()
		return block.Header(), nil
	}
	// Otherwise resolve and return the block
	if number == rpc.LatestBlockNumber {
		return b.tos.blockchain.CurrentBlock().Header(), nil
	}
	if number == rpc.FinalizedBlockNumber {
		block := b.tos.blockchain.CurrentFinalizedBlock()
		if block != nil {
			return block.Header(), nil
		}
		return nil, errors.New("finalized block not found")
	}
	if number == rpc.SafeBlockNumber {
		block := b.tos.blockchain.CurrentSafeBlock()
		if block != nil {
			return block.Header(), nil
		}
		return nil, errors.New("safe block not found")
	}
	return b.tos.blockchain.GetHeaderByNumber(uint64(number)), nil
}

func (b *TOSAPIBackend) HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.HeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header := b.tos.blockchain.GetHeaderByHash(hash)
		if header == nil {
			return nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.tos.blockchain.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		return header, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *TOSAPIBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return b.tos.blockchain.GetHeaderByHash(hash), nil
}

func (b *TOSAPIBackend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	// Pending block is only known by the miner
	if number == rpc.PendingBlockNumber {
		block := b.tos.miner.PendingBlock()
		return block, nil
	}
	// Otherwise resolve and return the block
	if number == rpc.LatestBlockNumber {
		return b.tos.blockchain.CurrentBlock(), nil
	}
	if number == rpc.FinalizedBlockNumber {
		return b.tos.blockchain.CurrentFinalizedBlock(), nil
	}
	if number == rpc.SafeBlockNumber {
		return b.tos.blockchain.CurrentSafeBlock(), nil
	}
	return b.tos.blockchain.GetBlockByNumber(uint64(number)), nil
}

func (b *TOSAPIBackend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return b.tos.blockchain.GetBlockByHash(hash), nil
}

func (b *TOSAPIBackend) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.BlockByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header := b.tos.blockchain.GetHeaderByHash(hash)
		if header == nil {
			return nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.tos.blockchain.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		block := b.tos.blockchain.GetBlock(hash, header.Number.Uint64())
		if block == nil {
			return nil, errors.New("header found, but block body is missing")
		}
		return block, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *TOSAPIBackend) PendingBlockAndReceipts() (*types.Block, types.Receipts) {
	return b.tos.miner.PendingBlockAndReceipts()
}

func (b *TOSAPIBackend) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	// Pending state is only known by the miner
	if number == rpc.PendingBlockNumber {
		block, state := b.tos.miner.Pending()
		return state, block.Header(), nil
	}
	// Otherwise resolve the block number and return its state
	header, err := b.HeaderByNumber(ctx, number)
	if err != nil {
		return nil, nil, err
	}
	if header == nil {
		return nil, nil, errors.New("header not found")
	}
	stateDb, err := b.tos.BlockChain().StateAt(header.Root)
	return stateDb, header, err
}

func (b *TOSAPIBackend) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.StateAndHeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header, err := b.HeaderByHash(ctx, hash)
		if err != nil {
			return nil, nil, err
		}
		if header == nil {
			return nil, nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.tos.blockchain.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, nil, errors.New("hash is not currently canonical")
		}
		stateDb, err := b.tos.BlockChain().StateAt(header.Root)
		return stateDb, header, err
	}
	return nil, nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *TOSAPIBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	return b.tos.blockchain.GetReceiptsByHash(hash), nil
}

func (b *TOSAPIBackend) GetLogs(ctx context.Context, hash common.Hash, number uint64) ([][]*types.Log, error) {
	return rawdb.ReadLogs(b.tos.chainDb, hash, number, b.ChainConfig()), nil
}

func (b *TOSAPIBackend) GetTd(ctx context.Context, hash common.Hash) *big.Int {
	if header := b.tos.blockchain.GetHeaderByHash(hash); header != nil {
		return b.tos.blockchain.GetTd(hash, header.Number.Uint64())
	}
	return nil
}

func (b *TOSAPIBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return b.tos.BlockChain().SubscribeRemovedLogsEvent(ch)
}

func (b *TOSAPIBackend) SubscribePendingLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.tos.miner.SubscribePendingLogs(ch)
}

func (b *TOSAPIBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return b.tos.BlockChain().SubscribeChainEvent(ch)
}

func (b *TOSAPIBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return b.tos.BlockChain().SubscribeChainHeadEvent(ch)
}

func (b *TOSAPIBackend) SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription {
	return b.tos.BlockChain().SubscribeChainSideEvent(ch)
}

func (b *TOSAPIBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.tos.BlockChain().SubscribeLogsEvent(ch)
}

func (b *TOSAPIBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	return b.tos.txPool.AddLocal(signedTx)
}

func (b *TOSAPIBackend) GetPoolTransactions() (types.Transactions, error) {
	pending := b.tos.txPool.Pending(false)
	var txs types.Transactions
	for _, batch := range pending {
		txs = append(txs, batch...)
	}
	return txs, nil
}

func (b *TOSAPIBackend) GetPoolTransaction(hash common.Hash) *types.Transaction {
	return b.tos.txPool.Get(hash)
}

func (b *TOSAPIBackend) GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	tx, blockHash, blockNumber, index := rawdb.ReadTransaction(b.tos.ChainDb(), txHash)
	return tx, blockHash, blockNumber, index, nil
}

func (b *TOSAPIBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return b.tos.txPool.Nonce(addr), nil
}

func (b *TOSAPIBackend) Stats() (pending int, queued int) {
	return b.tos.txPool.Stats()
}

func (b *TOSAPIBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return b.tos.TxPool().Content()
}

func (b *TOSAPIBackend) TxPoolContentFrom(addr common.Address) (types.Transactions, types.Transactions) {
	return b.tos.TxPool().ContentFrom(addr)
}

func (b *TOSAPIBackend) TxPool() *core.TxPool {
	return b.tos.TxPool()
}

func (b *TOSAPIBackend) SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription {
	return b.tos.TxPool().SubscribeNewTxsEvent(ch)
}

func (b *TOSAPIBackend) SyncProgress() gtos.SyncProgress {
	return b.tos.Downloader().Progress()
}

func (b *TOSAPIBackend) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	_ = ctx
	return params.GTOSPrice(), nil
}

func (b *TOSAPIBackend) FeeHistory(ctx context.Context, blockCount int, lastBlock rpc.BlockNumber, rewardPercentiles []float64) (firstBlock *big.Int, reward [][]*big.Int, baseFee []*big.Int, gasUsedRatio []float64, err error) {
	_ = ctx
	if blockCount < 0 {
		return nil, nil, nil, nil, fmt.Errorf("invalid blockCount: %d", blockCount)
	}
	if blockCount == 0 {
		blockCount = 1
	}
	fixed := params.GTOSPrice()
	if lastBlock >= 0 {
		firstBlock = big.NewInt(int64(lastBlock))
	} else {
		firstBlock = new(big.Int).SetUint64(b.tos.blockchain.CurrentBlock().NumberU64())
	}
	reward = make([][]*big.Int, blockCount)
	for i := range reward {
		reward[i] = make([]*big.Int, len(rewardPercentiles))
		for j := range reward[i] {
			reward[i][j] = new(big.Int).Set(fixed)
		}
	}
	baseFee = make([]*big.Int, blockCount+1)
	for i := range baseFee {
		baseFee[i] = new(big.Int)
	}
	gasUsedRatio = make([]float64, blockCount)
	return firstBlock, reward, baseFee, gasUsedRatio, nil
}

func (b *TOSAPIBackend) ChainDb() tosdb.Database {
	return b.tos.ChainDb()
}

func (b *TOSAPIBackend) EventMux() *event.TypeMux {
	return b.tos.EventMux()
}

func (b *TOSAPIBackend) AccountManager() *accounts.Manager {
	return b.tos.AccountManager()
}

func (b *TOSAPIBackend) ExtRPCEnabled() bool {
	return b.extRPCEnabled
}

func (b *TOSAPIBackend) RPCGasCap() uint64 {
	return b.tos.config.RPCGasCap
}

func (b *TOSAPIBackend) RPCEVMTimeout() time.Duration {
	return b.tos.config.RPCEVMTimeout
}

func (b *TOSAPIBackend) RPCTxFeeCap() float64 {
	return b.tos.config.RPCTxFeeCap
}

func (b *TOSAPIBackend) BloomStatus() (uint64, uint64) {
	sections, _, _ := b.tos.bloomIndexer.Sections()
	return params.BloomBitsBlocks, sections
}

func (b *TOSAPIBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	for i := 0; i < bloomFilterThreads; i++ {
		go session.Multiplex(bloomRetrievalBatch, bloomRetrievalWait, b.tos.bloomRequests)
	}
}

func (b *TOSAPIBackend) Engine() consensus.Engine {
	return b.tos.engine
}

func (b *TOSAPIBackend) CurrentHeader() *types.Header {
	return b.tos.blockchain.CurrentHeader()
}

func (b *TOSAPIBackend) Miner() *miner.Miner {
	return b.tos.Miner()
}

func (b *TOSAPIBackend) StartMining(threads int) error {
	return b.tos.StartMining(threads)
}

func (b *TOSAPIBackend) StateAtBlock(ctx context.Context, block *types.Block, reexec uint64, base *state.StateDB, checkLive, preferDisk bool) (*state.StateDB, error) {
	return b.tos.StateAtBlock(block, reexec, base, checkLive, preferDisk)
}

func (b *TOSAPIBackend) StateAtTransaction(ctx context.Context, block *types.Block, txIndex int, reexec uint64) (core.Message, *state.StateDB, error) {
	return b.tos.stateAtTransaction(block, txIndex, reexec)
}
