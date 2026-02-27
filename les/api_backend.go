// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package les

import (
	"context"
	"errors"
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
	"github.com/tos-network/gtos/tosdb"
	"github.com/tos-network/gtos/event"
	"github.com/tos-network/gtos/light"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/rpc"
)

type LesApiBackend struct {
	extRPCEnabled       bool
	allowUnprotectedTxs bool
	les                 *LightEthereum
}

func (b *LesApiBackend) ChainConfig() *params.ChainConfig {
	return b.les.chainConfig
}

func (b *LesApiBackend) CurrentBlock() *types.Block {
	return types.NewBlockWithHeader(b.les.BlockChain().CurrentHeader())
}

func (b *LesApiBackend) SetHead(number uint64) {
	b.les.handler.downloader.Cancel()
	b.les.blockchain.SetHead(number)
}

func (b *LesApiBackend) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	// Return the latest current as the pending one since there
	// is no pending notion in the light client. TODO(rjl493456442)
	// unify the behavior of `HeaderByNumber` and `PendingBlockAndReceipts`.
	if number == rpc.PendingBlockNumber {
		return b.les.blockchain.CurrentHeader(), nil
	}
	if number == rpc.LatestBlockNumber {
		return b.les.blockchain.CurrentHeader(), nil
	}
	return b.les.blockchain.GetHeaderByNumberOdr(ctx, uint64(number))
}

func (b *LesApiBackend) HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.HeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header, err := b.HeaderByHash(ctx, hash)
		if err != nil {
			return nil, err
		}
		if header == nil {
			return nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.les.blockchain.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		return header, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *LesApiBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return b.les.blockchain.GetHeaderByHash(hash), nil
}

func (b *LesApiBackend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	header, err := b.HeaderByNumber(ctx, number)
	if header == nil || err != nil {
		return nil, err
	}
	return b.BlockByHash(ctx, header.Hash())
}

func (b *LesApiBackend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return b.les.blockchain.GetBlockByHash(ctx, hash)
}

func (b *LesApiBackend) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.BlockByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		block, err := b.BlockByHash(ctx, hash)
		if err != nil {
			return nil, err
		}
		if block == nil {
			return nil, errors.New("header found, but block body is missing")
		}
		if blockNrOrHash.RequireCanonical && b.les.blockchain.GetCanonicalHash(block.NumberU64()) != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		return block, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *LesApiBackend) PendingBlockAndReceipts() (*types.Block, types.Receipts) {
	return nil, nil
}

func (b *LesApiBackend) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	header, err := b.HeaderByNumber(ctx, number)
	if err != nil {
		return nil, nil, err
	}
	if header == nil {
		return nil, nil, errors.New("header not found")
	}
	return light.NewState(ctx, header, b.les.odr), header, nil
}

func (b *LesApiBackend) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.StateAndHeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header := b.les.blockchain.GetHeaderByHash(hash)
		if header == nil {
			return nil, nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.les.blockchain.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, nil, errors.New("hash is not currently canonical")
		}
		return light.NewState(ctx, header, b.les.odr), header, nil
	}
	return nil, nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *LesApiBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	if number := rawdb.ReadHeaderNumber(b.les.chainDb, hash); number != nil {
		return light.GetBlockReceipts(ctx, b.les.odr, hash, *number)
	}
	return nil, nil
}

func (b *LesApiBackend) GetLogs(ctx context.Context, hash common.Hash, number uint64) ([][]*types.Log, error) {
	return light.GetBlockLogs(ctx, b.les.odr, hash, number)
}

func (b *LesApiBackend) GetTd(ctx context.Context, hash common.Hash) *big.Int {
	if number := rawdb.ReadHeaderNumber(b.les.chainDb, hash); number != nil {
		return b.les.blockchain.GetTdOdr(ctx, hash, *number)
	}
	return nil
}

func (b *LesApiBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	return b.les.txPool.Add(ctx, signedTx)
}

func (b *LesApiBackend) RemoveTx(txHash common.Hash) {
	b.les.txPool.RemoveTx(txHash)
}

func (b *LesApiBackend) GetPoolTransactions() (types.Transactions, error) {
	return b.les.txPool.GetTransactions()
}

func (b *LesApiBackend) GetPoolTransaction(txHash common.Hash) *types.Transaction {
	return b.les.txPool.GetTransaction(txHash)
}

func (b *LesApiBackend) GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	return light.GetTransaction(ctx, b.les.odr, txHash)
}

func (b *LesApiBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return b.les.txPool.GetNonce(ctx, addr)
}

func (b *LesApiBackend) Stats() (pending int, queued int) {
	return b.les.txPool.Stats(), 0
}

func (b *LesApiBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return b.les.txPool.Content()
}

func (b *LesApiBackend) TxPoolContentFrom(addr common.Address) (types.Transactions, types.Transactions) {
	return b.les.txPool.ContentFrom(addr)
}

func (b *LesApiBackend) SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription {
	return b.les.txPool.SubscribeNewTxsEvent(ch)
}

func (b *LesApiBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return b.les.blockchain.SubscribeChainEvent(ch)
}

func (b *LesApiBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return b.les.blockchain.SubscribeChainHeadEvent(ch)
}

func (b *LesApiBackend) SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription {
	return b.les.blockchain.SubscribeChainSideEvent(ch)
}

func (b *LesApiBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.les.blockchain.SubscribeLogsEvent(ch)
}

func (b *LesApiBackend) SubscribePendingLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return event.NewSubscription(func(quit <-chan struct{}) error {
		<-quit
		return nil
	})
}

func (b *LesApiBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return b.les.blockchain.SubscribeRemovedLogsEvent(ch)
}

func (b *LesApiBackend) SyncProgress() gtos.SyncProgress {
	return b.les.Downloader().Progress()
}

func (b *LesApiBackend) ProtocolVersion() int {
	return b.les.LesVersion() + 10000
}

func (b *LesApiBackend) SuggestGasTipCap(_ context.Context) (*big.Int, error) {
	return params.GTOSPrice(), nil
}

func (b *LesApiBackend) FeeHistory(_ context.Context, blockCount int, lastBlock rpc.BlockNumber, rewardPercentiles []float64) (firstBlock *big.Int, reward [][]*big.Int, baseFee []*big.Int, gasUsedRatio []float64, err error) {
	if blockCount < 0 {
		return nil, nil, nil, nil, errors.New("invalid blockCount")
	}
	if blockCount == 0 {
		blockCount = 1
	}
	fixed := params.GTOSPrice()
	if lastBlock >= 0 {
		firstBlock = big.NewInt(int64(lastBlock))
	} else {
		firstBlock = new(big.Int).SetUint64(b.les.blockchain.CurrentHeader().Number.Uint64())
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

func (b *LesApiBackend) ChainDb() tosdb.Database {
	return b.les.chainDb
}

func (b *LesApiBackend) AccountManager() *accounts.Manager {
	return b.les.accountManager
}

func (b *LesApiBackend) ExtRPCEnabled() bool {
	return b.extRPCEnabled
}

func (b *LesApiBackend) UnprotectedAllowed() bool {
	return b.allowUnprotectedTxs
}

func (b *LesApiBackend) RPCGasCap() uint64 {
	return b.les.config.RPCGasCap
}

func (b *LesApiBackend) RPCEVMTimeout() time.Duration {
	return b.les.config.RPCEVMTimeout
}

func (b *LesApiBackend) RPCTxFeeCap() float64 {
	return b.les.config.RPCTxFeeCap
}

func (b *LesApiBackend) BloomStatus() (uint64, uint64) {
	if b.les.bloomIndexer == nil {
		return 0, 0
	}
	sections, _, _ := b.les.bloomIndexer.Sections()
	return params.BloomBitsBlocksClient, sections
}

func (b *LesApiBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	for i := 0; i < bloomFilterThreads; i++ {
		go session.Multiplex(bloomRetrievalBatch, bloomRetrievalWait, b.les.bloomRequests)
	}
}

func (b *LesApiBackend) Engine() consensus.Engine {
	return b.les.engine
}

func (b *LesApiBackend) CurrentHeader() *types.Header {
	return b.les.blockchain.CurrentHeader()
}

func (b *LesApiBackend) StateAtBlock(ctx context.Context, block *types.Block, reexec uint64, base *state.StateDB, checkLive bool, preferDisk bool) (*state.StateDB, error) {
	return b.les.stateAtBlock(ctx, block, reexec)
}

func (b *LesApiBackend) StateAtTransaction(ctx context.Context, block *types.Block, txIndex int, reexec uint64) (core.Message, *state.StateDB, error) {
	return b.les.stateAtTransaction(ctx, block, txIndex, reexec)
}
