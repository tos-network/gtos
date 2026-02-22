package tosapi

import (
	"context"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/rpc"
)

const (
	v2DefaultRetainBlocks     = uint64(200)
	v2DefaultSnapshotInterval = uint64(1000)

	v2ErrNotSupported         = -38000
	v2ErrNotImplemented       = -38001
	v2ErrInvalidTTL           = -38002
	v2ErrExpired              = -38003
	v2ErrNotFound             = -38004
	v2ErrHistoryPruned        = -38005
	v2ErrPermissionDenied     = -38006
	v2ErrInvalidSigner        = -38007
	v2ErrRetentionUnavailable = -38008
)

// v2APIError is a JSON-RPC error with stable application code and optional data payload.
type v2APIError struct {
	code    int
	message string
	data    interface{}
}

func (e *v2APIError) Error() string          { return e.message }
func (e *v2APIError) ErrorCode() int         { return e.code }
func (e *v2APIError) ErrorData() interface{} { return e.data }

func newV2NotImplementedError(method string) error {
	return &v2APIError{
		code:    v2ErrNotImplemented,
		message: "not implemented",
		data: map[string]interface{}{
			"reason": method + " is not implemented yet",
		},
	}
}

type V2ChainProfile struct {
	ChainID               *hexutil.Big   `json:"chainId"`
	NetworkID             *hexutil.Big   `json:"networkId"`
	TargetBlockIntervalMs hexutil.Uint64 `json:"targetBlockIntervalMs"`
	RetainBlocks          hexutil.Uint64 `json:"retainBlocks"`
	SnapshotInterval      hexutil.Uint64 `json:"snapshotInterval"`
}

type V2RetentionPolicy struct {
	RetainBlocks         hexutil.Uint64 `json:"retainBlocks"`
	SnapshotInterval     hexutil.Uint64 `json:"snapshotInterval"`
	HeadBlock            hexutil.Uint64 `json:"headBlock"`
	OldestAvailableBlock hexutil.Uint64 `json:"oldestAvailableBlock"`
}

type V2PruneWatermark struct {
	HeadBlock            hexutil.Uint64 `json:"headBlock"`
	OldestAvailableBlock hexutil.Uint64 `json:"oldestAvailableBlock"`
	RetainBlocks         hexutil.Uint64 `json:"retainBlocks"`
}

type V2SignerDescriptor struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Defaulted bool   `json:"defaulted"`
}

type V2GetAccountArgs struct {
	Address common.Address         `json:"address"`
	Block   *rpc.BlockNumberOrHash `json:"block,omitempty"`
}

type V2AccountResult struct {
	Address     common.Address     `json:"address"`
	Nonce       hexutil.Uint64     `json:"nonce"`
	Balance     *hexutil.Big       `json:"balance"`
	Signer      V2SignerDescriptor `json:"signer"`
	BlockNumber hexutil.Uint64     `json:"blockNumber"`
}

type V2GetSignerArgs struct {
	Address common.Address         `json:"address"`
	Block   *rpc.BlockNumberOrHash `json:"block,omitempty"`
}

type V2SignerResult struct {
	Address     common.Address     `json:"address"`
	Signer      V2SignerDescriptor `json:"signer"`
	BlockNumber hexutil.Uint64     `json:"blockNumber"`
}

type V2TxCommonArgs struct {
	From     common.Address  `json:"from"`
	Nonce    *hexutil.Uint64 `json:"nonce,omitempty"`
	Gas      *hexutil.Uint64 `json:"gas,omitempty"`
	GasPrice *hexutil.Big    `json:"gasPrice,omitempty"`
}

type V2SetSignerArgs struct {
	V2TxCommonArgs
	SignerType  string `json:"signerType"`
	SignerValue string `json:"signerValue"`
}

type V2BuildTxResult struct {
	Tx  map[string]interface{} `json:"tx"`
	Raw hexutil.Bytes          `json:"raw"`
}

type V2PutCodeTTLArgs struct {
	V2TxCommonArgs
	Code hexutil.Bytes  `json:"code"`
	TTL  hexutil.Uint64 `json:"ttl"`
}

type V2GetCodeObjectArgs struct {
	CodeHash common.Hash            `json:"codeHash"`
	Block    *rpc.BlockNumberOrHash `json:"block,omitempty"`
}

type V2CodeObject struct {
	CodeHash  common.Hash    `json:"codeHash"`
	Code      hexutil.Bytes  `json:"code"`
	CreatedAt hexutil.Uint64 `json:"createdAt"`
	ExpireAt  hexutil.Uint64 `json:"expireAt"`
	Expired   bool           `json:"expired"`
}

type V2CodeObjectMeta struct {
	CodeHash  common.Hash    `json:"codeHash"`
	CreatedAt hexutil.Uint64 `json:"createdAt"`
	ExpireAt  hexutil.Uint64 `json:"expireAt"`
	Expired   bool           `json:"expired"`
}

type V2PutKVTTLArgs struct {
	V2TxCommonArgs
	Namespace string         `json:"namespace"`
	Key       hexutil.Bytes  `json:"key"`
	Value     hexutil.Bytes  `json:"value"`
	TTL       hexutil.Uint64 `json:"ttl"`
}

type V2GetKVArgs struct {
	Namespace string                 `json:"namespace"`
	Key       hexutil.Bytes          `json:"key"`
	Block     *rpc.BlockNumberOrHash `json:"block,omitempty"`
}

type V2KVResult struct {
	Namespace string        `json:"namespace"`
	Key       hexutil.Bytes `json:"key"`
	Value     hexutil.Bytes `json:"value"`
}

type V2KVMetaResult struct {
	Namespace string         `json:"namespace"`
	Key       hexutil.Bytes  `json:"key"`
	CreatedAt hexutil.Uint64 `json:"createdAt"`
	ExpireAt  hexutil.Uint64 `json:"expireAt"`
	Expired   bool           `json:"expired"`
}

type V2ListKVArgs struct {
	Namespace string                 `json:"namespace"`
	Cursor    *string                `json:"cursor,omitempty"`
	Limit     *hexutil.Uint64        `json:"limit,omitempty"`
	Block     *rpc.BlockNumberOrHash `json:"block,omitempty"`
}

type V2ListKVItem struct {
	Namespace string        `json:"namespace"`
	Key       hexutil.Bytes `json:"key"`
	Value     hexutil.Bytes `json:"value"`
}

type V2ListKVResult struct {
	Items      []V2ListKVItem `json:"items"`
	NextCursor *string        `json:"nextCursor"`
}

func (s *TOSAPI) retainBlocks() uint64 { return v2DefaultRetainBlocks }

func (s *TOSAPI) snapshotInterval() uint64 { return v2DefaultSnapshotInterval }

func (s *TOSAPI) targetBlockIntervalMs() uint64 {
	if cfg := s.b.ChainConfig(); cfg != nil && cfg.DPoS != nil && cfg.DPoS.Period > 0 {
		return cfg.DPoS.Period * 1000
	}
	return 1000
}

func (s *TOSAPI) currentHead() uint64 {
	header := s.b.CurrentHeader()
	if header == nil || header.Number == nil {
		return 0
	}
	return header.Number.Uint64()
}

func oldestAvailableBlock(head, retain uint64) uint64 {
	if retain == 0 || head+1 <= retain {
		return 0
	}
	return head - retain + 1
}

func resolveBlockArg(block *rpc.BlockNumberOrHash) rpc.BlockNumberOrHash {
	if block == nil {
		return rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	}
	return *block
}

// GetChainProfile returns chain identity and storage/retention profile.
func (s *TOSAPI) GetChainProfile() *V2ChainProfile {
	chainID := new(big.Int)
	if cfg := s.b.ChainConfig(); cfg != nil && cfg.ChainID != nil {
		chainID.Set(cfg.ChainID)
	}
	return &V2ChainProfile{
		ChainID:               (*hexutil.Big)(new(big.Int).Set(chainID)),
		NetworkID:             (*hexutil.Big)(new(big.Int).Set(chainID)),
		TargetBlockIntervalMs: hexutil.Uint64(s.targetBlockIntervalMs()),
		RetainBlocks:          hexutil.Uint64(s.retainBlocks()),
		SnapshotInterval:      hexutil.Uint64(s.snapshotInterval()),
	}
}

// GetRetentionPolicy returns the configured retention/snapshot values and current watermark.
func (s *TOSAPI) GetRetentionPolicy() *V2RetentionPolicy {
	head := s.currentHead()
	retain := s.retainBlocks()
	return &V2RetentionPolicy{
		RetainBlocks:         hexutil.Uint64(retain),
		SnapshotInterval:     hexutil.Uint64(s.snapshotInterval()),
		HeadBlock:            hexutil.Uint64(head),
		OldestAvailableBlock: hexutil.Uint64(oldestAvailableBlock(head, retain)),
	}
}

// GetPruneWatermark returns the oldest block still expected to be queryable by non-archive nodes.
func (s *TOSAPI) GetPruneWatermark() *V2PruneWatermark {
	head := s.currentHead()
	retain := s.retainBlocks()
	return &V2PruneWatermark{
		HeadBlock:            hexutil.Uint64(head),
		OldestAvailableBlock: hexutil.Uint64(oldestAvailableBlock(head, retain)),
		RetainBlocks:         hexutil.Uint64(retain),
	}
}

// GetAccount returns nonce/balance and signer view (fallback signer for now).
func (s *TOSAPI) GetAccount(ctx context.Context, args V2GetAccountArgs) (*V2AccountResult, error) {
	state, header, err := s.b.StateAndHeaderByNumberOrHash(ctx, resolveBlockArg(args.Block))
	if err != nil {
		return nil, err
	}
	if state == nil || header == nil {
		return nil, &v2APIError{code: v2ErrNotFound, message: "account state not found"}
	}
	return &V2AccountResult{
		Address: args.Address,
		Nonce:   hexutil.Uint64(state.GetNonce(args.Address)),
		Balance: (*hexutil.Big)(new(big.Int).Set(state.GetBalance(args.Address))),
		Signer: V2SignerDescriptor{
			Type:      "address",
			Value:     args.Address.Hex(),
			Defaulted: true,
		},
		BlockNumber: hexutil.Uint64(header.Number.Uint64()),
	}, nil
}

// GetSigner returns signer info; if signer is unset, fallback is account address.
func (s *TOSAPI) GetSigner(ctx context.Context, args V2GetSignerArgs) (*V2SignerResult, error) {
	acc, err := s.GetAccount(ctx, V2GetAccountArgs{
		Address: args.Address,
		Block:   args.Block,
	})
	if err != nil {
		return nil, err
	}
	return &V2SignerResult{
		Address:     args.Address,
		Signer:      acc.Signer,
		BlockNumber: acc.BlockNumber,
	}, nil
}

func (s *TOSAPI) SetSigner(ctx context.Context, args V2SetSignerArgs) (common.Hash, error) {
	_ = ctx
	_ = args
	return common.Hash{}, newV2NotImplementedError("tos_setSigner")
}

func (s *TOSAPI) BuildSetSignerTx(ctx context.Context, args V2SetSignerArgs) (*V2BuildTxResult, error) {
	_ = ctx
	_ = args
	return nil, newV2NotImplementedError("tos_buildSetSignerTx")
}

func (s *TOSAPI) PutCodeTTL(ctx context.Context, args V2PutCodeTTLArgs) (common.Hash, error) {
	_ = ctx
	_ = args
	return common.Hash{}, newV2NotImplementedError("tos_putCodeTTL")
}

func (s *TOSAPI) GetCodeObject(ctx context.Context, args V2GetCodeObjectArgs) (*V2CodeObject, error) {
	_ = ctx
	_ = args
	return nil, newV2NotImplementedError("tos_getCodeObject")
}

func (s *TOSAPI) GetCodeObjectMeta(ctx context.Context, args V2GetCodeObjectArgs) (*V2CodeObjectMeta, error) {
	_ = ctx
	_ = args
	return nil, newV2NotImplementedError("tos_getCodeObjectMeta")
}

func (s *TOSAPI) PutKVTTL(ctx context.Context, args V2PutKVTTLArgs) (common.Hash, error) {
	_ = ctx
	_ = args
	return common.Hash{}, newV2NotImplementedError("tos_putKVTTL")
}

func (s *TOSAPI) GetKV(ctx context.Context, args V2GetKVArgs) (*V2KVResult, error) {
	_ = ctx
	_ = args
	return nil, newV2NotImplementedError("tos_getKV")
}

func (s *TOSAPI) GetKVMeta(ctx context.Context, args V2GetKVArgs) (*V2KVMetaResult, error) {
	_ = ctx
	_ = args
	return nil, newV2NotImplementedError("tos_getKVMeta")
}

func (s *TOSAPI) ListKV(ctx context.Context, args V2ListKVArgs) (*V2ListKVResult, error) {
	_ = ctx
	_ = args
	return nil, newV2NotImplementedError("tos_listKV")
}
