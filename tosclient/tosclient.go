// Package tosclient provides a client for the TOS RPC API.
package tosclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/tos-network/gtos"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/rpc"
)

// Client defines typed wrappers for the TOS RPC API.
type Client struct {
	c *rpc.Client
}

// ChainProfile describes chain identity and retention profile.
type ChainProfile struct {
	ChainID               *big.Int
	NetworkID             *big.Int
	TargetBlockIntervalMs uint64
	RetainBlocks          uint64
	SnapshotInterval      uint64
}

// RetentionPolicy describes current retention window and watermark.
type RetentionPolicy struct {
	RetainBlocks         uint64
	SnapshotInterval     uint64
	HeadBlock            uint64
	OldestAvailableBlock uint64
}

// PruneWatermark reports queryable history watermark.
type PruneWatermark struct {
	HeadBlock            uint64
	OldestAvailableBlock uint64
	RetainBlocks         uint64
}

// SignerDescriptor describes the effective signer identity for an account.
type SignerDescriptor struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Defaulted bool   `json:"defaulted"`
}

// AccountProfile contains account state and signer at a specific block.
type AccountProfile struct {
	Address     common.Address
	Nonce       uint64
	Balance     *big.Int
	Signer      SignerDescriptor
	BlockNumber uint64
}

// SignerProfile contains signer view at a specific block.
type SignerProfile struct {
	Address     common.Address
	Signer      SignerDescriptor
	BlockNumber uint64
}

// SetSignerArgs is the argument object for tos_setSigner.
type SetSignerArgs struct {
	From        common.Address  `json:"from"`
	SignerType  string          `json:"signerType"`
	SignerValue string          `json:"signerValue"`
	Nonce       *hexutil.Uint64 `json:"nonce,omitempty"`
	Gas         *hexutil.Uint64 `json:"gas,omitempty"`
	GasPrice    *hexutil.Big    `json:"gasPrice,omitempty"`
}

// BuildSetSignerTxResult is the result object for tos_buildSetSignerTx.
type BuildSetSignerTxResult struct {
	Tx  map[string]interface{} `json:"tx"`
	Raw hexutil.Bytes          `json:"raw"`
}

// SetCodeArgs is the argument object for tos_setCode.
type SetCodeArgs struct {
	From     common.Address  `json:"from"`
	Nonce    *hexutil.Uint64 `json:"nonce,omitempty"`
	Gas      *hexutil.Uint64 `json:"gas,omitempty"`
	GasPrice *hexutil.Big    `json:"gasPrice,omitempty"`
	Code     hexutil.Bytes   `json:"code"`
	TTL      hexutil.Uint64  `json:"ttl"`
}

// CodeObject describes a code record and ttl metadata.
type CodeObject struct {
	CodeHash  common.Hash
	Code      []byte
	CreatedAt uint64
	ExpireAt  uint64
	Expired   bool
}

// CodeObjectMeta describes code metadata without payload.
type CodeObjectMeta struct {
	CodeHash  common.Hash
	CreatedAt uint64
	ExpireAt  uint64
	Expired   bool
}

// PutKVTTLArgs is the argument object for tos_putKVTTL.
type PutKVTTLArgs struct {
	From      common.Address  `json:"from"`
	Nonce     *hexutil.Uint64 `json:"nonce,omitempty"`
	Gas       *hexutil.Uint64 `json:"gas,omitempty"`
	GasPrice  *hexutil.Big    `json:"gasPrice,omitempty"`
	Namespace string          `json:"namespace"`
	Key       hexutil.Bytes   `json:"key"`
	Value     hexutil.Bytes   `json:"value"`
	TTL       hexutil.Uint64  `json:"ttl"`
}

// KVResult is an active KV read result.
type KVResult struct {
	Namespace string
	Key       []byte
	Value     []byte
}

// KVMetaResult is KV metadata result.
type KVMetaResult struct {
	Namespace string
	Key       []byte
	CreatedAt uint64
	ExpireAt  uint64
	Expired   bool
}

// DPoSValidatorInfo is validator status at a specific block.
type DPoSValidatorInfo struct {
	Address            common.Address
	Active             bool
	Index              *uint
	SnapshotBlock      uint64
	SnapshotHash       common.Hash
	RecentSignedBlocks []uint64
}

// DPoSEpochInfo is epoch context at a specific block.
type DPoSEpochInfo struct {
	BlockNumber        uint64
	EpochLength        uint64
	EpochIndex         uint64
	EpochStart         uint64
	NextEpochStart     uint64
	BlocksUntilEpoch   uint64
	TargetBlockPeriodS uint64
	MaxValidators      uint64
	ValidatorCount     uint64
	SnapshotHash       common.Hash
}

// Dial connects a client to the given URL.
func Dial(rawurl string) (*Client, error) {
	return DialContext(context.Background(), rawurl)
}

func DialContext(ctx context.Context, rawurl string) (*Client, error) {
	c, err := rpc.DialContext(ctx, rawurl)
	if err != nil {
		return nil, err
	}
	return NewClient(c), nil
}

// NewClient creates a client that uses the given RPC client.
func NewClient(c *rpc.Client) *Client {
	return &Client{c}
}

func (ec *Client) Close() {
	ec.c.Close()
}

// Blockchain Access

// ChainID retrieves the current chain ID for transaction replay protection.
func (ec *Client) ChainID(ctx context.Context) (*big.Int, error) {
	var result hexutil.Big
	err := ec.c.CallContext(ctx, &result, "tos_chainId")
	if err != nil {
		return nil, err
	}
	return (*big.Int)(&result), err
}

// GetChainProfile returns chain identity and retention profile.
func (ec *Client) GetChainProfile(ctx context.Context) (*ChainProfile, error) {
	var raw struct {
		ChainID               *hexutil.Big   `json:"chainId"`
		NetworkID             *hexutil.Big   `json:"networkId"`
		TargetBlockIntervalMs hexutil.Uint64 `json:"targetBlockIntervalMs"`
		RetainBlocks          hexutil.Uint64 `json:"retainBlocks"`
		SnapshotInterval      hexutil.Uint64 `json:"snapshotInterval"`
	}
	if err := ec.c.CallContext(ctx, &raw, "tos_getChainProfile"); err != nil {
		return nil, err
	}
	return &ChainProfile{
		ChainID:               bigFromHex(raw.ChainID),
		NetworkID:             bigFromHex(raw.NetworkID),
		TargetBlockIntervalMs: uint64(raw.TargetBlockIntervalMs),
		RetainBlocks:          uint64(raw.RetainBlocks),
		SnapshotInterval:      uint64(raw.SnapshotInterval),
	}, nil
}

// GetRetentionPolicy returns retention settings and current history watermark.
func (ec *Client) GetRetentionPolicy(ctx context.Context) (*RetentionPolicy, error) {
	var raw struct {
		RetainBlocks         hexutil.Uint64 `json:"retainBlocks"`
		SnapshotInterval     hexutil.Uint64 `json:"snapshotInterval"`
		HeadBlock            hexutil.Uint64 `json:"headBlock"`
		OldestAvailableBlock hexutil.Uint64 `json:"oldestAvailableBlock"`
	}
	if err := ec.c.CallContext(ctx, &raw, "tos_getRetentionPolicy"); err != nil {
		return nil, err
	}
	return &RetentionPolicy{
		RetainBlocks:         uint64(raw.RetainBlocks),
		SnapshotInterval:     uint64(raw.SnapshotInterval),
		HeadBlock:            uint64(raw.HeadBlock),
		OldestAvailableBlock: uint64(raw.OldestAvailableBlock),
	}, nil
}

// GetPruneWatermark returns the current pruning watermark.
func (ec *Client) GetPruneWatermark(ctx context.Context) (*PruneWatermark, error) {
	var raw struct {
		HeadBlock            hexutil.Uint64 `json:"headBlock"`
		OldestAvailableBlock hexutil.Uint64 `json:"oldestAvailableBlock"`
		RetainBlocks         hexutil.Uint64 `json:"retainBlocks"`
	}
	if err := ec.c.CallContext(ctx, &raw, "tos_getPruneWatermark"); err != nil {
		return nil, err
	}
	return &PruneWatermark{
		HeadBlock:            uint64(raw.HeadBlock),
		OldestAvailableBlock: uint64(raw.OldestAvailableBlock),
		RetainBlocks:         uint64(raw.RetainBlocks),
	}, nil
}

// GetAccount returns account profile for a block (latest when blockNumber is nil).
func (ec *Client) GetAccount(ctx context.Context, address common.Address, blockNumber *big.Int) (*AccountProfile, error) {
	var raw struct {
		Address     common.Address   `json:"address"`
		Nonce       hexutil.Uint64   `json:"nonce"`
		Balance     *hexutil.Big     `json:"balance"`
		Signer      SignerDescriptor `json:"signer"`
		BlockNumber hexutil.Uint64   `json:"blockNumber"`
	}
	if err := ec.c.CallContext(ctx, &raw, "tos_getAccount", address, toBlockNumArg(blockNumber)); err != nil {
		return nil, err
	}
	return &AccountProfile{
		Address:     raw.Address,
		Nonce:       uint64(raw.Nonce),
		Balance:     bigFromHex(raw.Balance),
		Signer:      raw.Signer,
		BlockNumber: uint64(raw.BlockNumber),
	}, nil
}

// GetSigner returns signer profile for a block (latest when blockNumber is nil).
func (ec *Client) GetSigner(ctx context.Context, address common.Address, blockNumber *big.Int) (*SignerProfile, error) {
	var raw struct {
		Address     common.Address   `json:"address"`
		Signer      SignerDescriptor `json:"signer"`
		BlockNumber hexutil.Uint64   `json:"blockNumber"`
	}
	if err := ec.c.CallContext(ctx, &raw, "tos_getSigner", address, toBlockNumArg(blockNumber)); err != nil {
		return nil, err
	}
	return &SignerProfile{
		Address:     raw.Address,
		Signer:      raw.Signer,
		BlockNumber: uint64(raw.BlockNumber),
	}, nil
}

// SetSigner submits a signer-change operation transaction.
func (ec *Client) SetSigner(ctx context.Context, args SetSignerArgs) (common.Hash, error) {
	var txHash common.Hash
	err := ec.c.CallContext(ctx, &txHash, "tos_setSigner", args)
	return txHash, err
}

// BuildSetSignerTx builds an unsigned signer-change transaction payload.
func (ec *Client) BuildSetSignerTx(ctx context.Context, args SetSignerArgs) (*BuildSetSignerTxResult, error) {
	var out BuildSetSignerTxResult
	if err := ec.c.CallContext(ctx, &out, "tos_buildSetSignerTx", args); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetCode submits a code-storage write with ttl.
func (ec *Client) SetCode(ctx context.Context, args SetCodeArgs) (common.Hash, error) {
	var txHash common.Hash
	err := ec.c.CallContext(ctx, &txHash, "tos_setCode", args)
	return txHash, err
}

// EstimateSetCodeGas returns deterministic gas for tos_setCode payload.
func (ec *Client) EstimateSetCodeGas(ctx context.Context, code []byte, ttl uint64) (uint64, error) {
	var gas hexutil.Uint64
	if err := ec.c.CallContext(ctx, &gas, "tos_estimateSetCodeGas", hexutil.Bytes(code), hexutil.Uint64(ttl)); err != nil {
		return 0, err
	}
	return uint64(gas), nil
}

// GetCodeObject returns a code object by hash.
func (ec *Client) GetCodeObject(ctx context.Context, codeHash common.Hash, blockNumber *big.Int) (*CodeObject, error) {
	var raw struct {
		CodeHash  common.Hash    `json:"codeHash"`
		Code      hexutil.Bytes  `json:"code"`
		CreatedAt hexutil.Uint64 `json:"createdAt"`
		ExpireAt  hexutil.Uint64 `json:"expireAt"`
		Expired   bool           `json:"expired"`
	}
	if err := ec.c.CallContext(ctx, &raw, "tos_getCodeObject", codeHash, toBlockNumArg(blockNumber)); err != nil {
		return nil, err
	}
	return &CodeObject{
		CodeHash:  raw.CodeHash,
		Code:      []byte(raw.Code),
		CreatedAt: uint64(raw.CreatedAt),
		ExpireAt:  uint64(raw.ExpireAt),
		Expired:   raw.Expired,
	}, nil
}

// GetCodeObjectMeta returns metadata for a code object.
func (ec *Client) GetCodeObjectMeta(ctx context.Context, codeHash common.Hash, blockNumber *big.Int) (*CodeObjectMeta, error) {
	var raw struct {
		CodeHash  common.Hash    `json:"codeHash"`
		CreatedAt hexutil.Uint64 `json:"createdAt"`
		ExpireAt  hexutil.Uint64 `json:"expireAt"`
		Expired   bool           `json:"expired"`
	}
	if err := ec.c.CallContext(ctx, &raw, "tos_getCodeObjectMeta", codeHash, toBlockNumArg(blockNumber)); err != nil {
		return nil, err
	}
	return &CodeObjectMeta{
		CodeHash:  raw.CodeHash,
		CreatedAt: uint64(raw.CreatedAt),
		ExpireAt:  uint64(raw.ExpireAt),
		Expired:   raw.Expired,
	}, nil
}

// PutKVTTL submits a KV upsert with ttl.
func (ec *Client) PutKVTTL(ctx context.Context, args PutKVTTLArgs) (common.Hash, error) {
	var txHash common.Hash
	err := ec.c.CallContext(ctx, &txHash, "tos_putKVTTL", args)
	return txHash, err
}

// GetKV reads an active KV value.
func (ec *Client) GetKV(ctx context.Context, namespace string, key []byte, blockNumber *big.Int) (*KVResult, error) {
	var raw struct {
		Namespace string        `json:"namespace"`
		Key       hexutil.Bytes `json:"key"`
		Value     hexutil.Bytes `json:"value"`
	}
	if err := ec.c.CallContext(ctx, &raw, "tos_getKV", namespace, hexutil.Bytes(key), toBlockNumArg(blockNumber)); err != nil {
		return nil, err
	}
	return &KVResult{
		Namespace: raw.Namespace,
		Key:       []byte(raw.Key),
		Value:     []byte(raw.Value),
	}, nil
}

// GetKVMeta reads KV metadata.
func (ec *Client) GetKVMeta(ctx context.Context, namespace string, key []byte, blockNumber *big.Int) (*KVMetaResult, error) {
	var raw struct {
		Namespace string         `json:"namespace"`
		Key       hexutil.Bytes  `json:"key"`
		CreatedAt hexutil.Uint64 `json:"createdAt"`
		ExpireAt  hexutil.Uint64 `json:"expireAt"`
		Expired   bool           `json:"expired"`
	}
	if err := ec.c.CallContext(ctx, &raw, "tos_getKVMeta", namespace, hexutil.Bytes(key), toBlockNumArg(blockNumber)); err != nil {
		return nil, err
	}
	return &KVMetaResult{
		Namespace: raw.Namespace,
		Key:       []byte(raw.Key),
		CreatedAt: uint64(raw.CreatedAt),
		ExpireAt:  uint64(raw.ExpireAt),
		Expired:   raw.Expired,
	}, nil
}

// DPoSGetValidators returns active validators at the requested block.
func (ec *Client) DPoSGetValidators(ctx context.Context, blockNumber *big.Int) ([]common.Address, error) {
	var out []common.Address
	if err := ec.c.CallContext(ctx, &out, "dpos_getValidators", toBlockNumArg(blockNumber)); err != nil {
		return nil, err
	}
	return out, nil
}

// DPoSGetValidator returns validator status at the requested block.
func (ec *Client) DPoSGetValidator(ctx context.Context, address common.Address, blockNumber *big.Int) (*DPoSValidatorInfo, error) {
	var raw struct {
		Address            common.Address   `json:"address"`
		Active             bool             `json:"active"`
		Index              *hexutil.Uint    `json:"index"`
		SnapshotBlock      hexutil.Uint64   `json:"snapshotBlock"`
		SnapshotHash       common.Hash      `json:"snapshotHash"`
		RecentSignedBlocks []hexutil.Uint64 `json:"recentSignedBlocks"`
	}
	if err := ec.c.CallContext(ctx, &raw, "dpos_getValidator", address, toBlockNumArg(blockNumber)); err != nil {
		return nil, err
	}
	var idx *uint
	if raw.Index != nil {
		v := uint(*raw.Index)
		idx = &v
	}
	recent := make([]uint64, len(raw.RecentSignedBlocks))
	for i := range raw.RecentSignedBlocks {
		recent[i] = uint64(raw.RecentSignedBlocks[i])
	}
	return &DPoSValidatorInfo{
		Address:            raw.Address,
		Active:             raw.Active,
		Index:              idx,
		SnapshotBlock:      uint64(raw.SnapshotBlock),
		SnapshotHash:       raw.SnapshotHash,
		RecentSignedBlocks: recent,
	}, nil
}

// DPoSGetEpochInfo returns epoch context at the requested block.
func (ec *Client) DPoSGetEpochInfo(ctx context.Context, blockNumber *big.Int) (*DPoSEpochInfo, error) {
	var raw struct {
		BlockNumber        hexutil.Uint64 `json:"blockNumber"`
		EpochLength        hexutil.Uint64 `json:"epochLength"`
		EpochIndex         hexutil.Uint64 `json:"epochIndex"`
		EpochStart         hexutil.Uint64 `json:"epochStart"`
		NextEpochStart     hexutil.Uint64 `json:"nextEpochStart"`
		BlocksUntilEpoch   hexutil.Uint64 `json:"blocksUntilEpoch"`
		TargetBlockPeriodS hexutil.Uint64 `json:"targetBlockPeriodS"`
		MaxValidators      hexutil.Uint64 `json:"maxValidators"`
		ValidatorCount     hexutil.Uint64 `json:"validatorCount"`
		SnapshotHash       common.Hash    `json:"snapshotHash"`
	}
	if err := ec.c.CallContext(ctx, &raw, "dpos_getEpochInfo", toBlockNumArg(blockNumber)); err != nil {
		return nil, err
	}
	return &DPoSEpochInfo{
		BlockNumber:        uint64(raw.BlockNumber),
		EpochLength:        uint64(raw.EpochLength),
		EpochIndex:         uint64(raw.EpochIndex),
		EpochStart:         uint64(raw.EpochStart),
		NextEpochStart:     uint64(raw.NextEpochStart),
		BlocksUntilEpoch:   uint64(raw.BlocksUntilEpoch),
		TargetBlockPeriodS: uint64(raw.TargetBlockPeriodS),
		MaxValidators:      uint64(raw.MaxValidators),
		ValidatorCount:     uint64(raw.ValidatorCount),
		SnapshotHash:       raw.SnapshotHash,
	}, nil
}

// BlockByHash returns the given full block.
//
// Note that loading full blocks requires two requests. Use HeaderByHash
// if you don't need all transactions or uncle headers.
func (ec *Client) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return ec.getBlock(ctx, "tos_getBlockByHash", hash, true)
}

// BlockByNumber returns a block from the current canonical chain. If number is nil, the
// latest known block is returned.
//
// Note that loading full blocks requires two requests. Use HeaderByNumber
// if you don't need all transactions or uncle headers.
func (ec *Client) BlockByNumber(ctx context.Context, number *big.Int) (*types.Block, error) {
	return ec.getBlock(ctx, "tos_getBlockByNumber", toBlockNumArg(number), true)
}

// BlockNumber returns the most recent block number
func (ec *Client) BlockNumber(ctx context.Context) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "tos_blockNumber")
	return uint64(result), err
}

// PeerCount returns the number of p2p peers as reported by the net_peerCount method.
func (ec *Client) PeerCount(ctx context.Context) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "net_peerCount")
	return uint64(result), err
}

type rpcBlock struct {
	Hash         common.Hash      `json:"hash"`
	Transactions []rpcTransaction `json:"transactions"`
	UncleHashes  []common.Hash    `json:"uncles"`
}

func (ec *Client) getBlock(ctx context.Context, method string, args ...interface{}) (*types.Block, error) {
	var raw json.RawMessage
	err := ec.c.CallContext(ctx, &raw, method, args...)
	if err != nil {
		return nil, err
	} else if len(raw) == 0 {
		return nil, gtos.NotFound
	}
	// Decode header and transactions.
	var head *types.Header
	var body rpcBlock
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	// Quick-verify transaction and uncle lists. This mostly helps with debugging the server.
	if head.UncleHash == types.EmptyUncleHash && len(body.UncleHashes) > 0 {
		return nil, fmt.Errorf("server returned non-empty uncle list but block header indicates no uncles")
	}
	if head.UncleHash != types.EmptyUncleHash && len(body.UncleHashes) == 0 {
		return nil, fmt.Errorf("server returned empty uncle list but block header indicates uncles")
	}
	if head.TxHash == types.EmptyRootHash && len(body.Transactions) > 0 {
		return nil, fmt.Errorf("server returned non-empty transaction list but block header indicates no transactions")
	}
	if head.TxHash != types.EmptyRootHash && len(body.Transactions) == 0 {
		return nil, fmt.Errorf("server returned empty transaction list but block header indicates transactions")
	}
	// Load uncles because they are not included in the block response.
	var uncles []*types.Header
	if len(body.UncleHashes) > 0 {
		uncles = make([]*types.Header, len(body.UncleHashes))
		reqs := make([]rpc.BatchElem, len(body.UncleHashes))
		for i := range reqs {
			reqs[i] = rpc.BatchElem{
				Method: "tos_getUncleByBlockHashAndIndex",
				Args:   []interface{}{body.Hash, hexutil.EncodeUint64(uint64(i))},
				Result: &uncles[i],
			}
		}
		if err := ec.c.BatchCallContext(ctx, reqs); err != nil {
			return nil, err
		}
		for i := range reqs {
			if reqs[i].Error != nil {
				return nil, reqs[i].Error
			}
			if uncles[i] == nil {
				return nil, fmt.Errorf("got null header for uncle %d of block %x", i, body.Hash[:])
			}
		}
	}
	// Fill the sender cache of transactions in the block.
	txs := make([]*types.Transaction, len(body.Transactions))
	for i, tx := range body.Transactions {
		if tx.From != nil {
			setSenderFromServer(tx.tx, *tx.From, body.Hash)
		}
		txs[i] = tx.tx
	}
	return types.NewBlockWithHeader(head).WithBody(txs, uncles), nil
}

// HeaderByHash returns the block header with the given hash.
func (ec *Client) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	var head *types.Header
	err := ec.c.CallContext(ctx, &head, "tos_getBlockByHash", hash, false)
	if err == nil && head == nil {
		err = gtos.NotFound
	}
	return head, err
}

// HeaderByNumber returns a block header from the current canonical chain. If number is
// nil, the latest known header is returned.
func (ec *Client) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	var head *types.Header
	err := ec.c.CallContext(ctx, &head, "tos_getBlockByNumber", toBlockNumArg(number), false)
	if err == nil && head == nil {
		err = gtos.NotFound
	}
	return head, err
}

type rpcTransaction struct {
	tx *types.Transaction
	txExtraInfo
}

type txExtraInfo struct {
	BlockNumber *string         `json:"blockNumber,omitempty"`
	BlockHash   *common.Hash    `json:"blockHash,omitempty"`
	From        *common.Address `json:"from,omitempty"`
}

func (tx *rpcTransaction) UnmarshalJSON(msg []byte) error {
	if err := json.Unmarshal(msg, &tx.tx); err != nil {
		return err
	}
	return json.Unmarshal(msg, &tx.txExtraInfo)
}

// TransactionByHash returns the transaction with the given hash.
func (ec *Client) TransactionByHash(ctx context.Context, hash common.Hash) (tx *types.Transaction, isPending bool, err error) {
	var json *rpcTransaction
	err = ec.c.CallContext(ctx, &json, "tos_getTransactionByHash", hash)
	if err != nil {
		return nil, false, err
	} else if json == nil {
		return nil, false, gtos.NotFound
	} else if _, r, _ := json.tx.RawSignatureValues(); r == nil {
		return nil, false, fmt.Errorf("server returned transaction without signature")
	}
	if json.From != nil && json.BlockHash != nil {
		setSenderFromServer(json.tx, *json.From, *json.BlockHash)
	}
	return json.tx, json.BlockNumber == nil, nil
}

// TransactionSender returns the sender address of the given transaction. The transaction
// must be known to the remote node and included in the blockchain at the given block and
// index. The sender is the one derived by the protocol at the time of inclusion.
//
// There is a fast-path for transactions retrieved by TransactionByHash and
// TransactionInBlock. Getting their sender address can be done without an RPC interaction.
func (ec *Client) TransactionSender(ctx context.Context, tx *types.Transaction, block common.Hash, index uint) (common.Address, error) {
	// Try to load the address from the cache.
	sender, err := types.Sender(&senderFromServer{blockhash: block}, tx)
	if err == nil {
		return sender, nil
	}

	// It was not found in cache, ask the server.
	var meta struct {
		Hash common.Hash
		From common.Address
	}
	if err = ec.c.CallContext(ctx, &meta, "tos_getTransactionByBlockHashAndIndex", block, hexutil.Uint64(index)); err != nil {
		return common.Address{}, err
	}
	if meta.Hash == (common.Hash{}) || meta.Hash != tx.Hash() {
		return common.Address{}, errors.New("wrong inclusion block/index")
	}
	return meta.From, nil
}

// TransactionCount returns the total number of transactions in the given block.
func (ec *Client) TransactionCount(ctx context.Context, blockHash common.Hash) (uint, error) {
	var num hexutil.Uint
	err := ec.c.CallContext(ctx, &num, "tos_getBlockTransactionCountByHash", blockHash)
	return uint(num), err
}

// TransactionInBlock returns a single transaction at index in the given block.
func (ec *Client) TransactionInBlock(ctx context.Context, blockHash common.Hash, index uint) (*types.Transaction, error) {
	var json *rpcTransaction
	err := ec.c.CallContext(ctx, &json, "tos_getTransactionByBlockHashAndIndex", blockHash, hexutil.Uint64(index))
	if err != nil {
		return nil, err
	}
	if json == nil {
		return nil, gtos.NotFound
	} else if _, r, _ := json.tx.RawSignatureValues(); r == nil {
		return nil, fmt.Errorf("server returned transaction without signature")
	}
	if json.From != nil && json.BlockHash != nil {
		setSenderFromServer(json.tx, *json.From, *json.BlockHash)
	}
	return json.tx, err
}

// TransactionReceipt returns the receipt of a transaction by transaction hash.
// Note that the receipt is not available for pending transactions.
func (ec *Client) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	var r *types.Receipt
	err := ec.c.CallContext(ctx, &r, "tos_getTransactionReceipt", txHash)
	if err == nil {
		if r == nil {
			return nil, gtos.NotFound
		}
	}
	return r, err
}

// SyncProgress retrieves the current progress of the sync algorithm. If there's
// no sync currently running, it returns nil.
func (ec *Client) SyncProgress(ctx context.Context) (*gtos.SyncProgress, error) {
	var raw json.RawMessage
	if err := ec.c.CallContext(ctx, &raw, "tos_syncing"); err != nil {
		return nil, err
	}
	// Handle the possible response types
	var syncing bool
	if err := json.Unmarshal(raw, &syncing); err == nil {
		return nil, nil // Not syncing (always false)
	}
	var p *rpcProgress
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return p.toSyncProgress(), nil
}

// SubscribeNewHead subscribes to notifications about the current blockchain head
// on the given channel.
func (ec *Client) SubscribeNewHead(ctx context.Context, ch chan<- *types.Header) (gtos.Subscription, error) {
	return ec.c.TOSSubscribe(ctx, ch, "newHeads")
}

// State Access

// NetworkID returns the network ID (also known as the chain ID) for this chain.
func (ec *Client) NetworkID(ctx context.Context) (*big.Int, error) {
	version := new(big.Int)
	var ver string
	if err := ec.c.CallContext(ctx, &ver, "net_version"); err != nil {
		return nil, err
	}
	if _, ok := version.SetString(ver, 10); !ok {
		return nil, fmt.Errorf("invalid net_version result %q", ver)
	}
	return version, nil
}

// BalanceAt returns the wei balance of the given account.
// The block number can be nil, in which case the balance is taken from the latest known block.
func (ec *Client) BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error) {
	var result hexutil.Big
	err := ec.c.CallContext(ctx, &result, "tos_getBalance", account, toBlockNumArg(blockNumber))
	return (*big.Int)(&result), err
}

// StorageAt returns the value of key in the contract storage of the given account.
// The block number can be nil, in which case the value is taken from the latest known block.
func (ec *Client) StorageAt(ctx context.Context, account common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "tos_getStorageAt", account, key, toBlockNumArg(blockNumber))
	return result, err
}

// CodeAt returns the contract code of the given account.
// The block number can be nil, in which case the code is taken from the latest known block.
func (ec *Client) CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "tos_getCode", account, toBlockNumArg(blockNumber))
	return result, err
}

// NonceAt returns the account nonce of the given account.
// The block number can be nil, in which case the nonce is taken from the latest known block.
func (ec *Client) NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "tos_getTransactionCount", account, toBlockNumArg(blockNumber))
	return uint64(result), err
}

// Filters

// FilterLogs executes a filter query.
func (ec *Client) FilterLogs(ctx context.Context, q gtos.FilterQuery) ([]types.Log, error) {
	var result []types.Log
	arg, err := toFilterArg(q)
	if err != nil {
		return nil, err
	}
	err = ec.c.CallContext(ctx, &result, "tos_getLogs", arg)
	return result, err
}

// SubscribeFilterLogs subscribes to the results of a streaming filter query.
func (ec *Client) SubscribeFilterLogs(ctx context.Context, q gtos.FilterQuery, ch chan<- types.Log) (gtos.Subscription, error) {
	arg, err := toFilterArg(q)
	if err != nil {
		return nil, err
	}
	return ec.c.TOSSubscribe(ctx, ch, "logs", arg)
}

func toFilterArg(q gtos.FilterQuery) (interface{}, error) {
	arg := map[string]interface{}{
		"address": q.Addresses,
		"topics":  q.Topics,
	}
	if q.BlockHash != nil {
		arg["blockHash"] = *q.BlockHash
		if q.FromBlock != nil || q.ToBlock != nil {
			return nil, fmt.Errorf("cannot specify both BlockHash and FromBlock/ToBlock")
		}
	} else {
		if q.FromBlock == nil {
			arg["fromBlock"] = "0x0"
		} else {
			arg["fromBlock"] = toBlockNumArg(q.FromBlock)
		}
		arg["toBlock"] = toBlockNumArg(q.ToBlock)
	}
	return arg, nil
}

// Pending State

// PendingBalanceAt returns the wei balance of the given account in the pending state.
func (ec *Client) PendingBalanceAt(ctx context.Context, account common.Address) (*big.Int, error) {
	var result hexutil.Big
	err := ec.c.CallContext(ctx, &result, "tos_getBalance", account, "pending")
	return (*big.Int)(&result), err
}

// PendingStorageAt returns the value of key in the contract storage of the given account in the pending state.
func (ec *Client) PendingStorageAt(ctx context.Context, account common.Address, key common.Hash) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "tos_getStorageAt", account, key, "pending")
	return result, err
}

// PendingCodeAt returns the contract code of the given account in the pending state.
func (ec *Client) PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "tos_getCode", account, "pending")
	return result, err
}

// PendingNonceAt returns the account nonce of the given account in the pending state.
// This is the nonce that should be used for the next transaction.
func (ec *Client) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "tos_getTransactionCount", account, "pending")
	return uint64(result), err
}

// PendingTransactionCount returns the total number of transactions in the pending state.
func (ec *Client) PendingTransactionCount(ctx context.Context) (uint, error) {
	var num hexutil.Uint
	err := ec.c.CallContext(ctx, &num, "tos_getBlockTransactionCountByNumber", "pending")
	return uint(num), err
}

// Contract Calling

// CallContract executes a message call transaction, which is directly executed in the VM
// of the node, but never mined into the blockchain.
//
// blockNumber selects the block height at which the call runs. It can be nil, in which
// case the code is taken from the latest known block. Note that state from very old
// blocks might not be available.
func (ec *Client) CallContract(ctx context.Context, msg gtos.CallMsg, blockNumber *big.Int) ([]byte, error) {
	var hex hexutil.Bytes
	err := ec.c.CallContext(ctx, &hex, "tos_call", toCallArg(msg), toBlockNumArg(blockNumber))
	if err != nil {
		return nil, err
	}
	return hex, nil
}

// CallContractAtHash is almost the same as CallContract except that it selects
// the block by block hash instead of block height.
func (ec *Client) CallContractAtHash(ctx context.Context, msg gtos.CallMsg, blockHash common.Hash) ([]byte, error) {
	var hex hexutil.Bytes
	err := ec.c.CallContext(ctx, &hex, "tos_call", toCallArg(msg), rpc.BlockNumberOrHashWithHash(blockHash, false))
	if err != nil {
		return nil, err
	}
	return hex, nil
}

// PendingCallContract executes a message call transaction using the TVM.
// The state seen by the contract call is the pending state.
func (ec *Client) PendingCallContract(ctx context.Context, msg gtos.CallMsg) ([]byte, error) {
	var hex hexutil.Bytes
	err := ec.c.CallContext(ctx, &hex, "tos_call", toCallArg(msg), "pending")
	if err != nil {
		return nil, err
	}
	return hex, nil
}

// SuggestGasPrice retrieves the currently suggested gas price to allow a timely
// execution of a transaction.
func (ec *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := ec.c.CallContext(ctx, &hex, "tos_gasPrice"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

// SuggestGasTipCap retrieves the currently suggested gas tip cap after 1559 to
// allow a timely execution of a transaction.
func (ec *Client) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := ec.c.CallContext(ctx, &hex, "tos_maxPriorityFeePerGas"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

type feeHistoryResultMarshaling struct {
	OldestBlock  *hexutil.Big     `json:"oldestBlock"`
	Reward       [][]*hexutil.Big `json:"reward,omitempty"`
	BaseFee      []*hexutil.Big   `json:"baseFeePerGas,omitempty"`
	GasUsedRatio []float64        `json:"gasUsedRatio"`
}

// FeeHistory retrieves the fee market history.
func (ec *Client) FeeHistory(ctx context.Context, blockCount uint64, lastBlock *big.Int, rewardPercentiles []float64) (*gtos.FeeHistory, error) {
	var res feeHistoryResultMarshaling
	if err := ec.c.CallContext(ctx, &res, "tos_feeHistory", hexutil.Uint(blockCount), toBlockNumArg(lastBlock), rewardPercentiles); err != nil {
		return nil, err
	}
	reward := make([][]*big.Int, len(res.Reward))
	for i, r := range res.Reward {
		reward[i] = make([]*big.Int, len(r))
		for j, r := range r {
			reward[i][j] = (*big.Int)(r)
		}
	}
	baseFee := make([]*big.Int, len(res.BaseFee))
	for i, b := range res.BaseFee {
		baseFee[i] = (*big.Int)(b)
	}
	return &gtos.FeeHistory{
		OldestBlock:  (*big.Int)(res.OldestBlock),
		Reward:       reward,
		BaseFee:      baseFee,
		GasUsedRatio: res.GasUsedRatio,
	}, nil
}

// EstimateGas tries to estimate the gas needed to execute a specific transaction based on
// the current pending state of the backend blockchain. There is no guarantee that this is
// the true gas limit requirement as other transactions may be added or removed by miners,
// but it should provide a basis for setting a reasonable default.
func (ec *Client) EstimateGas(ctx context.Context, msg gtos.CallMsg) (uint64, error) {
	var hex hexutil.Uint64
	err := ec.c.CallContext(ctx, &hex, "tos_estimateGas", toCallArg(msg))
	if err != nil {
		return 0, err
	}
	return uint64(hex), nil
}

// SendTransaction injects a signed transaction into the pending pool for execution.
//
// If the transaction was a contract creation use the TransactionReceipt method to get the
// contract address after the transaction has been mined.
func (ec *Client) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	data, err := tx.MarshalBinary()
	if err != nil {
		return err
	}
	return ec.c.CallContext(ctx, nil, "tos_sendRawTransaction", hexutil.Encode(data))
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	pending := big.NewInt(-1)
	if number.Cmp(pending) == 0 {
		return "pending"
	}
	return hexutil.EncodeBig(number)
}

func bigFromHex(value *hexutil.Big) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set((*big.Int)(value))
}

func toCallArg(msg gtos.CallMsg) interface{} {
	arg := map[string]interface{}{
		"from": msg.From,
		"to":   msg.To,
	}
	if len(msg.Data) > 0 {
		arg["data"] = hexutil.Bytes(msg.Data)
	}
	if msg.Value != nil {
		arg["value"] = (*hexutil.Big)(msg.Value)
	}
	if msg.Gas != 0 {
		arg["gas"] = hexutil.Uint64(msg.Gas)
	}
	if msg.GasPrice != nil {
		arg["gasPrice"] = (*hexutil.Big)(msg.GasPrice)
	}
	return arg
}

// rpcProgress is a copy of SyncProgress with hex-encoded fields.
type rpcProgress struct {
	StartingBlock hexutil.Uint64
	CurrentBlock  hexutil.Uint64
	HighestBlock  hexutil.Uint64

	PulledStates hexutil.Uint64
	KnownStates  hexutil.Uint64

	SyncedAccounts      hexutil.Uint64
	SyncedAccountBytes  hexutil.Uint64
	SyncedBytecodes     hexutil.Uint64
	SyncedBytecodeBytes hexutil.Uint64
	SyncedStorage       hexutil.Uint64
	SyncedStorageBytes  hexutil.Uint64
	HealedTrienodes     hexutil.Uint64
	HealedTrienodeBytes hexutil.Uint64
	HealedBytecodes     hexutil.Uint64
	HealedBytecodeBytes hexutil.Uint64
	HealingTrienodes    hexutil.Uint64
	HealingBytecode     hexutil.Uint64
}

func (p *rpcProgress) toSyncProgress() *gtos.SyncProgress {
	if p == nil {
		return nil
	}
	return &gtos.SyncProgress{
		StartingBlock:       uint64(p.StartingBlock),
		CurrentBlock:        uint64(p.CurrentBlock),
		HighestBlock:        uint64(p.HighestBlock),
		PulledStates:        uint64(p.PulledStates),
		KnownStates:         uint64(p.KnownStates),
		SyncedAccounts:      uint64(p.SyncedAccounts),
		SyncedAccountBytes:  uint64(p.SyncedAccountBytes),
		SyncedBytecodes:     uint64(p.SyncedBytecodes),
		SyncedBytecodeBytes: uint64(p.SyncedBytecodeBytes),
		SyncedStorage:       uint64(p.SyncedStorage),
		SyncedStorageBytes:  uint64(p.SyncedStorageBytes),
		HealedTrienodes:     uint64(p.HealedTrienodes),
		HealedTrienodeBytes: uint64(p.HealedTrienodeBytes),
		HealedBytecodes:     uint64(p.HealedBytecodes),
		HealedBytecodeBytes: uint64(p.HealedBytecodeBytes),
		HealingTrienodes:    uint64(p.HealingTrienodes),
		HealingBytecode:     uint64(p.HealingBytecode),
	}
}
