// Copyright 2014 The go-ethereum Authors
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

// Package eth implements the Ethereum protocol.
package tos

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tos-network/gtos/accounts"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/consensus"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/bloombits"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state/pruner"
	"github.com/tos-network/gtos/core/types"
	engineclient "github.com/tos-network/gtos/engineapi/client"
	enginepayloadtosv1 "github.com/tos-network/gtos/engineapi/payload/tosv1"
	"github.com/tos-network/gtos/event"
	"github.com/tos-network/gtos/internal/shutdowncheck"
	"github.com/tos-network/gtos/internal/tosapi"
	"github.com/tos-network/gtos/log"
	"github.com/tos-network/gtos/miner"
	"github.com/tos-network/gtos/node"
	"github.com/tos-network/gtos/p2p"
	"github.com/tos-network/gtos/p2p/dnsdisc"
	"github.com/tos-network/gtos/p2p/enode"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/rlp"
	"github.com/tos-network/gtos/rpc"
	"github.com/tos-network/gtos/tos/downloader"
	"github.com/tos-network/gtos/tos/gasprice"
	"github.com/tos-network/gtos/tos/protocols/snap"
	"github.com/tos-network/gtos/tos/protocols/tos"
	"github.com/tos-network/gtos/tos/tosconfig"
	"github.com/tos-network/gtos/tosdb"
	_ "github.com/tos-network/gtos/validator" // registers VALIDATOR_* handlers via init()
)

// Config contains the configuration options of the ETH protocol.
// Deprecated: use tosconfig.Config instead.
type Config = tosconfig.Config

// Ethereum implements the Ethereum full node service.
type TOS struct {
	config *tosconfig.Config

	// Handlers
	txPool             *core.TxPool
	blockchain         *core.BlockChain
	handler            *handler
	tosDialCandidates  enode.Iterator
	snapDialCandidates enode.Iterator
	merger             *consensus.Merger

	// DB interfaces
	chainDb tosdb.Database // Block chain database

	eventMux       *event.TypeMux
	engine         consensus.Engine
	accountManager *accounts.Manager
	engineHeadSub  event.Subscription

	bloomRequests     chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer      *core.ChainIndexer             // Bloom indexer operating during block imports
	closeBloomHandler chan struct{}

	APIBackend *TOSAPIBackend

	miner     *miner.Miner
	gasPrice  *big.Int
	etherbase common.Address

	networkID     uint64
	netRPCService *tosapi.NetAPI

	p2pServer *p2p.Server

	lock sync.RWMutex // Protects the variadic fields (e.g. gas price and etherbase)

	shutdownTracker *shutdowncheck.ShutdownTracker // Tracks if and when the node has shutdown ungracefully

	// External execution layer bridge (phase-1 scaffold).
	engineAPIConfig     engineclient.Config
	engineAPIClient     engineclient.Client
	lastForkchoiceState *engineclient.ForkchoiceState
}

// New creates a new Ethereum object (including the
// initialisation of the common Ethereum object)
func New(stack *node.Node, config *tosconfig.Config) (*TOS, error) {
	// Ensure configuration values are compatible and sane
	if config.SyncMode == downloader.LightSync {
		return nil, errors.New("can't run tos.TOS in light sync mode, use les.LightEthereum")
	}
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	if config.Miner.GasPrice == nil || config.Miner.GasPrice.Cmp(common.Big0) <= 0 {
		log.Warn("Sanitizing invalid miner gas price", "provided", config.Miner.GasPrice, "updated", tosconfig.Defaults.Miner.GasPrice)
		config.Miner.GasPrice = new(big.Int).Set(tosconfig.Defaults.Miner.GasPrice)
	}
	if config.NoPruning && config.TrieDirtyCache > 0 {
		if config.SnapshotCache > 0 {
			config.TrieCleanCache += config.TrieDirtyCache * 3 / 5
			config.SnapshotCache += config.TrieDirtyCache * 2 / 5
		} else {
			config.TrieCleanCache += config.TrieDirtyCache
		}
		config.TrieDirtyCache = 0
	}
	log.Info("Allocated trie memory caches", "clean", common.StorageSize(config.TrieCleanCache)*1024*1024, "dirty", common.StorageSize(config.TrieDirtyCache)*1024*1024)

	// Assemble the Ethereum object
	chainDb, err := stack.OpenDatabaseWithFreezer("chaindata", config.DatabaseCache, config.DatabaseHandles, config.DatabaseFreezer, "tos/db/chaindata/", false)
	if err != nil {
		return nil, err
	}
	chainConfig, genesisHash, genesisErr := core.SetupGenesisBlockWithOverride(chainDb, config.Genesis, config.OverrideTerminalTotalDifficulty, config.OverrideTerminalTotalDifficultyPassed)
	if _, ok := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !ok {
		return nil, genesisErr
	}
	log.Info("")
	log.Info(strings.Repeat("-", 153))
	for _, line := range strings.Split(chainConfig.String(), "\n") {
		log.Info(line)
	}
	log.Info(strings.Repeat("-", 153))
	log.Info("")

	if err := pruner.RecoverPruning(stack.ResolvePath(""), chainDb, stack.ResolvePath(config.TrieCleanCacheJournal)); err != nil {
		log.Error("Failed to recover state", "error", err)
	}
	merger := consensus.NewMerger(chainDb)
	tosNode := &TOS{
		config:         config,
		merger:         merger,
		chainDb:        chainDb,
		eventMux:       stack.EventMux(),
		accountManager: stack.AccountManager(),
		engine: func() consensus.Engine {
			if config.Engine != nil {
				return config.Engine
			}
			return tosconfig.CreateConsensusEngine(stack, chainConfig, chainDb)
		}(),
		closeBloomHandler: make(chan struct{}),
		networkID:         config.NetworkId,
		gasPrice:          config.Miner.GasPrice,
		etherbase:         config.Miner.Etherbase,
		bloomRequests:     make(chan chan *bloombits.Retrieval),
		bloomIndexer:      core.NewBloomIndexer(chainDb, params.BloomBitsBlocks, params.BloomConfirms),
		p2pServer:         stack.Server(),
		shutdownTracker:   shutdowncheck.NewShutdownTracker(chainDb),
	}

	bcVersion := rawdb.ReadDatabaseVersion(chainDb)
	var dbVer = "<nil>"
	if bcVersion != nil {
		dbVer = fmt.Sprintf("%d", *bcVersion)
	}
	log.Info("Initialising Ethereum protocol", "network", config.NetworkId, "dbversion", dbVer)

	if !config.SkipBcVersionCheck {
		if bcVersion != nil && *bcVersion > core.BlockChainVersion {
			return nil, fmt.Errorf("database version is v%d, Geth %s only supports v%d", *bcVersion, params.VersionWithMeta, core.BlockChainVersion)
		} else if bcVersion == nil || *bcVersion < core.BlockChainVersion {
			if bcVersion != nil { // only print warning on upgrade, not on init
				log.Warn("Upgrade blockchain database version", "from", dbVer, "to", core.BlockChainVersion)
			}
			rawdb.WriteDatabaseVersion(chainDb, core.BlockChainVersion)
		}
	}
	var (
		cacheConfig = &core.CacheConfig{
			TrieCleanLimit:      config.TrieCleanCache,
			TrieCleanJournal:    stack.ResolvePath(config.TrieCleanCacheJournal),
			TrieCleanRejournal:  config.TrieCleanCacheRejournal,
			TrieCleanNoPrefetch: config.NoPrefetch,
			TrieDirtyLimit:      config.TrieDirtyCache,
			TrieDirtyDisabled:   config.NoPruning,
			TrieTimeLimit:       config.TrieTimeout,
			SnapshotLimit:       config.SnapshotCache,
			Preimages:           config.Preimages,
		}
	)
	tosNode.blockchain, err = core.NewBlockChain(chainDb, cacheConfig, chainConfig, tosNode.engine, tosNode.shouldPreserve, &config.TxLookupLimit)
	if err != nil {
		return nil, err
	}
	// Rewind the chain in case of an incompatible config upgrade.
	if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		tosNode.blockchain.SetHead(compat.RewindTo)
		rawdb.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}
	tosNode.bloomIndexer.Start(tosNode.blockchain)

	if config.TxPool.Journal != "" {
		config.TxPool.Journal = stack.ResolvePath(config.TxPool.Journal)
	}
	tosNode.txPool = core.NewTxPool(config.TxPool, chainConfig, tosNode.blockchain)

	// Permit the downloader to use the trie cache allowance during fast sync
	cacheLimit := cacheConfig.TrieCleanLimit + cacheConfig.TrieDirtyLimit + cacheConfig.SnapshotLimit
	checkpoint := config.Checkpoint
	if checkpoint == nil {
		checkpoint = params.TrustedCheckpoints[genesisHash]
	}
	if tosNode.handler, err = newHandler(&handlerConfig{
		Database:       chainDb,
		Chain:          tosNode.blockchain,
		TxPool:         tosNode.txPool,
		Merger:         merger,
		BlockValidator: tosNode.validateImportedBlockWithEngine,
		OnQCFinalized:  tosNode.onQCFinalized,
		Network:        config.NetworkId,
		Sync:           config.SyncMode,
		BloomCache:     uint64(cacheLimit),
		EventMux:       tosNode.eventMux,
		Checkpoint:     checkpoint,
		RequiredBlocks: config.RequiredBlocks,
	}); err != nil {
		return nil, err
	}

	tosNode.miner = miner.New(tosNode, &config.Miner, chainConfig, tosNode.EventMux(), tosNode.engine, tosNode.isLocalBlock)
	tosNode.miner.SetExtra(makeExtraData(config.Miner.ExtraData))

	tosNode.APIBackend = &TOSAPIBackend{stack.Config().ExtRPCEnabled(), stack.Config().AllowUnprotectedTxs, tosNode, nil}
	if tosNode.APIBackend.allowUnprotectedTxs {
		log.Info("Unprotected transactions allowed")
	}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.Miner.GasPrice
	}
	tosNode.APIBackend.gpo = gasprice.NewOracle(tosNode.APIBackend, gpoParams)

	// Setup DNS discovery iterators.
	dnsclient := dnsdisc.NewClient(dnsdisc.Config{})
	tosNode.tosDialCandidates, err = dnsclient.NewIterator(tosNode.config.TosDiscoveryURLs...)
	if err != nil {
		return nil, err
	}
	tosNode.snapDialCandidates, err = dnsclient.NewIterator(tosNode.config.SnapDiscoveryURLs...)
	if err != nil {
		return nil, err
	}

	// Start the RPC service
	tosNode.netRPCService = tosapi.NewNetAPI(tosNode.p2pServer, config.NetworkId)

	// Register the backend on the node
	stack.RegisterAPIs(tosNode.APIs())
	stack.RegisterProtocols(tosNode.Protocols())
	stack.RegisterLifecycle(tosNode)

	// Successful startup; push a marker and check previous unclean shutdowns.
	tosNode.shutdownTracker.MarkStartup()

	return tosNode, nil
}

func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(params.VersionMajor<<16 | params.VersionMinor<<8 | params.VersionPatch),
			"gtos",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

// APIs return the collection of RPC services the ethereum package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *TOS) APIs() []rpc.API {
	apis := tosapi.GetAPIs(s.APIBackend)

	// Append any APIs exposed explicitly by the consensus engine
	apis = append(apis, s.engine.APIs(s.BlockChain())...)

	// Append all the local APIs and return
	return append(apis, []rpc.API{
		{
			Namespace: "tos",
			Service:   NewTOSAPI(s),
		}, {
			Namespace: "miner",
			Service:   NewMinerAPI(s),
		}, {
			Namespace: "tos",
			Service:   downloader.NewDownloaderAPI(s.handler.downloader, s.eventMux),
		}, {
			Namespace: "admin",
			Service:   NewAdminAPI(s),
		}, {
			Namespace: "debug",
			Service:   NewDebugAPI(s),
		}, {
			Namespace: "net",
			Service:   s.netRPCService,
		},
	}...)
}

func (s *TOS) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *TOS) Etherbase() (eb common.Address, err error) {
	s.lock.RLock()
	etherbase := s.etherbase
	s.lock.RUnlock()

	if etherbase != (common.Address{}) {
		return etherbase, nil
	}
	if wallets := s.AccountManager().Wallets(); len(wallets) > 0 {
		if accounts := wallets[0].Accounts(); len(accounts) > 0 {
			etherbase := accounts[0].Address

			s.lock.Lock()
			s.etherbase = etherbase
			s.lock.Unlock()

			log.Info("Etherbase automatically configured", "address", etherbase)
			return etherbase, nil
		}
	}
	return common.Address{}, fmt.Errorf("etherbase must be explicitly specified")
}

// isLocalBlock checks whether the specified block is mined
// by local miner accounts.
//
// We regard two types of accounts as local miner account: etherbase
// and accounts specified via `txpool.locals` flag.
func (s *TOS) isLocalBlock(header *types.Header) bool {
	author, err := s.engine.Author(header)
	if err != nil {
		log.Warn("Failed to retrieve block author", "number", header.Number.Uint64(), "hash", header.Hash(), "err", err)
		return false
	}
	// Check whether the given address is etherbase.
	s.lock.RLock()
	etherbase := s.etherbase
	s.lock.RUnlock()
	if author == etherbase {
		return true
	}
	// Check whether the given address is specified by `txpool.local`
	// CLI flag.
	for _, account := range s.config.TxPool.Locals {
		if account == author {
			return true
		}
	}
	return false
}

// shouldPreserve checks whether we should preserve the given block
// during the chain reorg depending on whether the author of block
// is a local account.
func (s *TOS) shouldPreserve(header *types.Header) bool {
	// The reason we need to disable the self-reorg preserving for clique
	// is it can be probable to introduce a deadlock.
	//
	// e.g. If there are 7 available signers (kept for historical context)
	//
	// r1   A
	// r2     B
	// r3       C
	// r4         D
	// r5   A      [X] F G
	// r6    [X]
	//
	// In the round5, the inturn signer E is offline, so the worst case
	// is A, F and G sign the block of round5 and reject the block of opponents
	// and in the round6, the last available signer B is offline, the whole
	// network is stuck.
	return s.isLocalBlock(header)
}

// SetEtherbase sets the mining reward address.
func (s *TOS) SetEtherbase(etherbase common.Address) {
	s.lock.Lock()
	s.etherbase = etherbase
	s.lock.Unlock()

	s.miner.SetEtherbase(etherbase)
}

// StartMining starts the miner with the given number of CPU threads. If mining
// is already running, this method adjust the number of threads allowed to use
// and updates the minimum price required by the transaction pool.
func (s *TOS) StartMining(threads int) error {
	// Update the thread count within the consensus engine
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := s.engine.(threaded); ok {
		log.Info("Updated mining threads", "threads", threads)
		if threads == 0 {
			threads = -1 // Disable the miner from within
		}
		th.SetThreads(threads)
	}
	// If the miner was not running, initialize it
	if !s.IsMining() {
		// Propagate the initial price point to the transaction pool
		s.lock.RLock()
		price := s.gasPrice
		s.lock.RUnlock()
		s.txPool.SetGasPrice(price)

		// Configure the local mining address
		eb, err := s.Etherbase()
		if err != nil {
			log.Error("Cannot start mining without etherbase", "err", err)
			return fmt.Errorf("etherbase missing: %v", err)
		}
		if d, ok := s.engine.(*dpos.DPoS); ok {
			wallet, err := s.accountManager.Find(accounts.Account{Address: eb})
			if wallet == nil || err != nil {
				log.Error("Etherbase account unavailable locally", "err", err)
				return fmt.Errorf("signer missing: %v", err)
			}
			d.Authorize(eb, wallet.SignData)
		}
		// If mining is started, we can disable the transaction rejection mechanism
		// introduced to speed sync times.
		atomic.StoreUint32(&s.handler.acceptTxs, 1)

		go s.miner.Start(eb)
	}
	return nil
}

// StopMining terminates the miner, both at the consensus engine level as well as
// at the block creation level.
func (s *TOS) StopMining() {
	// Update the thread count within the consensus engine
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := s.engine.(threaded); ok {
		th.SetThreads(-1)
	}
	// Stop the block creating itself
	s.miner.Stop()
}

func (s *TOS) IsMining() bool      { return s.miner.Mining() }
func (s *TOS) Miner() *miner.Miner { return s.miner }

func (s *TOS) AccountManager() *accounts.Manager  { return s.accountManager }
func (s *TOS) BlockChain() *core.BlockChain       { return s.blockchain }
func (s *TOS) TxPool() *core.TxPool               { return s.txPool }
func (s *TOS) EventMux() *event.TypeMux           { return s.eventMux }
func (s *TOS) Engine() consensus.Engine           { return s.engine }
func (s *TOS) ChainDb() tosdb.Database            { return s.chainDb }
func (s *TOS) IsListening() bool                  { return true } // Always listening
func (s *TOS) Downloader() *downloader.Downloader { return s.handler.downloader }
func (s *TOS) Synced() bool                       { return atomic.LoadUint32(&s.handler.acceptTxs) == 1 }
func (s *TOS) SetSynced()                         { atomic.StoreUint32(&s.handler.acceptTxs, 1) }
func (s *TOS) ArchiveMode() bool                  { return s.config.NoPruning }
func (s *TOS) BloomIndexer() *core.ChainIndexer   { return s.bloomIndexer }
func (s *TOS) Merger() *consensus.Merger          { return s.merger }
func (s *TOS) SyncMode() downloader.SyncMode {
	mode, _ := s.handler.chainSync.modeAndLocalHead()
	return mode
}

// Protocols returns all the currently configured
// network protocols to start.
func (s *TOS) Protocols() []p2p.Protocol {
	protos := tos.MakeProtocols((*tosHandler)(s.handler), s.networkID, s.tosDialCandidates)
	if s.config.SnapshotCache > 0 {
		protos = append(protos, snap.MakeProtocols((*snapHandler)(s.handler), s.snapDialCandidates)...)
	}
	return protos
}

// Start implements node.Lifecycle, starting all internal goroutines needed by the
// Ethereum protocol implementation.
func (s *TOS) Start() error {
	tos.StartENRUpdater(s.blockchain, s.p2pServer.LocalNode())

	// Start the bloom bits servicing goroutines
	s.startBloomHandlers(params.BloomBitsBlocks)

	// Regularly update shutdown marker
	s.shutdownTracker.Start()

	// Figure out a max peers count based on the server limits
	maxPeers := s.p2pServer.MaxPeers
	if s.config.LightServ > 0 {
		if s.config.LightPeers >= s.p2pServer.MaxPeers {
			return fmt.Errorf("invalid peer config: light peer count (%d) >= total peer count (%d)", s.config.LightPeers, s.p2pServer.MaxPeers)
		}
		maxPeers -= s.config.LightPeers
	}
	// Start the networking layer and the light server if requested
	s.handler.Start(maxPeers)
	headCh := make(chan core.ChainHeadEvent, 16)
	s.engineHeadSub = s.blockchain.SubscribeChainHeadEvent(headCh)
	go s.engineHeadLoop(s.engineHeadSub, headCh)
	if head := s.blockchain.CurrentBlock(); head != nil {
		s.onChainHead(head)
	}
	return nil
}

// Stop implements node.Lifecycle, terminating all internal goroutines used by the
// Ethereum protocol.
func (s *TOS) Stop() error {
	// Stop all the peer-related stuff first.
	s.tosDialCandidates.Close()
	s.snapDialCandidates.Close()
	s.handler.Stop()
	if s.engineHeadSub != nil {
		s.engineHeadSub.Unsubscribe()
		s.engineHeadSub = nil
	}

	// Then stop everything else.
	s.bloomIndexer.Close()
	close(s.closeBloomHandler)
	s.txPool.Stop()
	s.miner.Close()
	s.blockchain.Stop()
	s.engine.Close()

	// Clean shutdown marker as the last thing before closing db
	s.shutdownTracker.Stop()

	s.chainDb.Close()
	s.eventMux.Stop()

	return nil
}

// ConfigureEngineAPI configures the local engine API bridge client.
// In phase-1 this wires the client object only; integration into proposal/vote
// flow will be added incrementally.
func (s *TOS) ConfigureEngineAPI(cfg engineclient.Config) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.engineAPIConfig = cfg
	s.lastForkchoiceState = nil
	if !cfg.Enabled {
		s.engineAPIClient = nil
		log.Info("Engine API bridge disabled")
		return
	}
	s.engineAPIClient = engineclient.NewRPCClient(cfg)
	log.Info("Engine API bridge configured", "endpoint", cfg.Endpoint, "timeout", cfg.RequestTimeout, "allowTxPoolFallback", cfg.AllowTxPoolFallback)
}

// EngineAPIClient returns the configured engine API bridge client.
func (s *TOS) EngineAPIClient() engineclient.Client {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.engineAPIClient
}

// EngineAPIAllowTxPoolFallback reports whether local txpool fallback is allowed
// when engine payload retrieval fails.
func (s *TOS) EngineAPIAllowTxPoolFallback() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.engineAPIConfig.AllowTxPoolFallback
}

func (s *TOS) validateImportedBlockWithEngine(block *types.Block) error {
	s.lock.RLock()
	client := s.engineAPIClient
	cfg := s.engineAPIConfig
	s.lock.RUnlock()
	if client == nil {
		return nil
	}
	txBlobs := make([][]byte, 0, len(block.Transactions()))
	for i, tx := range block.Transactions() {
		raw, err := tx.MarshalBinary()
		if err != nil {
			return fmt.Errorf("encode engine tx[%d] for block %s: %w", i, block.Hash(), err)
		}
		txBlobs = append(txBlobs, raw)
	}
	payload, err := enginepayloadtosv1.Encode(txBlobs)
	if err != nil {
		return fmt.Errorf("encode engine payload for block %s: %w", block.Hash(), err)
	}
	timeout := cfg.RequestTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resp, err := client.NewPayload(ctx, &engineclient.NewPayloadRequest{
		Payload:    payload,
		ParentHash: block.ParentHash().Hex(),
	})
	if err != nil {
		if errors.Is(err, engineclient.ErrNotImplemented) {
			return nil
		}
		log.Warn("Engine NewPayload failed, allowing local import fallback", "hash", block.Hash(), "err", err)
		return nil
	}
	if resp != nil && !resp.Valid {
		return fmt.Errorf("engine rejected block %s (state=%s)", block.Hash(), resp.StateHash)
	}
	if resp != nil && resp.StateHash != "" {
		var engineStateHash common.Hash
		if err := engineStateHash.UnmarshalText([]byte(resp.StateHash)); err != nil {
			return fmt.Errorf("engine returned invalid state hash %q for block %s: %w", resp.StateHash, block.Hash(), err)
		}
		if engineStateHash != block.Root() {
			return fmt.Errorf("engine state hash mismatch for block %s (engine=%s, block=%s)", block.Hash(), engineStateHash.Hex(), block.Root().Hex())
		}
	}
	return nil
}

func (s *TOS) engineHeadLoop(sub event.Subscription, headCh <-chan core.ChainHeadEvent) {
	for {
		select {
		case ev := <-headCh:
			if ev.Block != nil {
				s.onChainHead(ev.Block)
			}
		case <-sub.Err():
			return
		}
	}
}

func (s *TOS) onChainHead(head *types.Block) {
	if head == nil {
		return
	}
	if s.handler != nil {
		if err := s.handler.proposeVoteForBlock(head); err != nil {
			log.Warn("Failed to propose BFT vote for head", "hash", head.Hash(), "err", err)
		}
	}
	s.notifyForkchoiceUpdated(head)
}

func (s *TOS) notifyForkchoiceUpdated(head *types.Block) {
	s.lock.RLock()
	client := s.engineAPIClient
	cfg := s.engineAPIConfig
	prev := cloneForkchoiceState(s.lastForkchoiceState)
	s.lock.RUnlock()
	if client == nil || head == nil {
		return
	}
	state := resolveForkchoiceState(head, s.blockchain.CurrentSafeBlock(), s.blockchain.CurrentFinalizedBlock())
	if state == nil || sameForkchoiceState(state, prev) {
		return
	}
	timeout := cfg.RequestTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := client.ForkchoiceUpdated(ctx, state); err != nil && !errors.Is(err, engineclient.ErrNotImplemented) {
		log.Warn("Engine ForkchoiceUpdated failed", "head", head.Hash(), "err", err)
		return
	}
	s.lock.Lock()
	s.lastForkchoiceState = cloneForkchoiceState(state)
	s.lock.Unlock()
}

func (s *TOS) onQCFinalized(finalized *types.Block) {
	if finalized == nil || s.blockchain == nil {
		return
	}
	if head := s.blockchain.CurrentBlock(); head != nil {
		s.notifyForkchoiceUpdated(head)
	}
}

func resolveForkchoiceState(head, safe, finalized *types.Block) *engineclient.ForkchoiceState {
	if head == nil {
		return nil
	}
	if safe == nil {
		safe = head
	}
	if finalized == nil {
		finalized = safe
	}
	return &engineclient.ForkchoiceState{
		HeadHash:      head.Hash().Hex(),
		SafeHash:      safe.Hash().Hex(),
		FinalizedHash: finalized.Hash().Hex(),
	}
}

func sameForkchoiceState(a, b *engineclient.ForkchoiceState) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.HeadHash == b.HeadHash &&
		a.SafeHash == b.SafeHash &&
		a.FinalizedHash == b.FinalizedHash
}

func cloneForkchoiceState(state *engineclient.ForkchoiceState) *engineclient.ForkchoiceState {
	if state == nil {
		return nil
	}
	return &engineclient.ForkchoiceState{
		HeadHash:      state.HeadHash,
		SafeHash:      state.SafeHash,
		FinalizedHash: state.FinalizedHash,
	}
}
