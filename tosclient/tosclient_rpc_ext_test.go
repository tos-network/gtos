package tosclient

import (
	"context"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/rpc"
)

type rpcExtTestError struct {
	msg  string
	code int
	data interface{}
}

func (e rpcExtTestError) Error() string          { return e.msg }
func (e rpcExtTestError) ErrorCode() int         { return e.code }
func (e rpcExtTestError) ErrorData() interface{} { return e.data }

type rpcExtTestService struct {
	lastGetAccountAddress common.Address
	lastGetAccountBlock   string

	lastGetSignerAddress common.Address
	lastGetSignerBlock   string

	lastGetCodeHash  common.Hash
	lastGetCodeBlock string

	lastGetKVNamespace string
	lastGetKVKey       hexutil.Bytes
	lastGetKVBlock     string

	lastEstimateSetCodeGasCode hexutil.Bytes
	lastEstimateSetCodeGasTTL  hexutil.Uint64

	lastSetSignerArgs    SetSignerArgs
	lastBuildSignerArgs  SetSignerArgs
	lastSetCodeArgs      SetCodeArgs
	lastPutKVTTLArgs     PutKVTTLArgs
	lastDPoSQueryAddress common.Address
	lastDPoSQueryBlock   string
}

func (s *rpcExtTestService) GetChainProfile() interface{} {
	return struct {
		ChainID               *hexutil.Big   `json:"chainId"`
		NetworkID             *hexutil.Big   `json:"networkId"`
		TargetBlockIntervalMs hexutil.Uint64 `json:"targetBlockIntervalMs"`
		RetainBlocks          hexutil.Uint64 `json:"retainBlocks"`
		SnapshotInterval      hexutil.Uint64 `json:"snapshotInterval"`
	}{
		ChainID:               (*hexutil.Big)(big.NewInt(1666)),
		NetworkID:             (*hexutil.Big)(big.NewInt(1666)),
		TargetBlockIntervalMs: hexutil.Uint64(1000),
		RetainBlocks:          hexutil.Uint64(200),
		SnapshotInterval:      hexutil.Uint64(1000),
	}
}

func (s *rpcExtTestService) GetRetentionPolicy() interface{} {
	return struct {
		RetainBlocks         hexutil.Uint64 `json:"retainBlocks"`
		SnapshotInterval     hexutil.Uint64 `json:"snapshotInterval"`
		HeadBlock            hexutil.Uint64 `json:"headBlock"`
		OldestAvailableBlock hexutil.Uint64 `json:"oldestAvailableBlock"`
	}{
		RetainBlocks:         hexutil.Uint64(200),
		SnapshotInterval:     hexutil.Uint64(1000),
		HeadBlock:            hexutil.Uint64(1234),
		OldestAvailableBlock: hexutil.Uint64(1035),
	}
}

func (s *rpcExtTestService) GetPruneWatermark() interface{} {
	return struct {
		HeadBlock            hexutil.Uint64 `json:"headBlock"`
		OldestAvailableBlock hexutil.Uint64 `json:"oldestAvailableBlock"`
		RetainBlocks         hexutil.Uint64 `json:"retainBlocks"`
	}{
		HeadBlock:            hexutil.Uint64(1234),
		OldestAvailableBlock: hexutil.Uint64(1035),
		RetainBlocks:         hexutil.Uint64(200),
	}
}

func (s *rpcExtTestService) GetAccount(address common.Address, block string) interface{} {
	s.lastGetAccountAddress = address
	s.lastGetAccountBlock = block
	return struct {
		Address     common.Address   `json:"address"`
		Nonce       hexutil.Uint64   `json:"nonce"`
		Balance     *hexutil.Big     `json:"balance"`
		Signer      SignerDescriptor `json:"signer"`
		BlockNumber hexutil.Uint64   `json:"blockNumber"`
	}{
		Address:     address,
		Nonce:       hexutil.Uint64(7),
		Balance:     (*hexutil.Big)(big.NewInt(999)),
		Signer:      SignerDescriptor{Type: "address", Value: address.Hex(), Defaulted: true},
		BlockNumber: hexutil.Uint64(42),
	}
}

func (s *rpcExtTestService) GetSigner(address common.Address, block string) interface{} {
	s.lastGetSignerAddress = address
	s.lastGetSignerBlock = block
	return struct {
		Address     common.Address   `json:"address"`
		Signer      SignerDescriptor `json:"signer"`
		BlockNumber hexutil.Uint64   `json:"blockNumber"`
	}{
		Address:     address,
		Signer:      SignerDescriptor{Type: "secp256k1", Value: "0xabcdef", Defaulted: false},
		BlockNumber: hexutil.Uint64(43),
	}
}

func (s *rpcExtTestService) SetSigner(args SetSignerArgs) common.Hash {
	s.lastSetSignerArgs = args
	return common.HexToHash("0x1")
}

func (s *rpcExtTestService) BuildSetSignerTx(args SetSignerArgs) interface{} {
	s.lastBuildSignerArgs = args
	return BuildSetSignerTxResult{
		Tx:  map[string]interface{}{"from": args.From.Hex()},
		Raw: hexutil.Bytes{0xaa, 0xbb},
	}
}

func (s *rpcExtTestService) SetCode(args SetCodeArgs) common.Hash {
	s.lastSetCodeArgs = args
	return common.HexToHash("0x2")
}

func (s *rpcExtTestService) EstimateSetCodeGas(code hexutil.Bytes, ttl hexutil.Uint64) hexutil.Uint64 {
	s.lastEstimateSetCodeGasCode = code
	s.lastEstimateSetCodeGasTTL = ttl
	return hexutil.Uint64(77777)
}

func (s *rpcExtTestService) GetCodeObject(codeHash common.Hash, block string) interface{} {
	s.lastGetCodeHash = codeHash
	s.lastGetCodeBlock = block
	return struct {
		CodeHash  common.Hash    `json:"codeHash"`
		Code      hexutil.Bytes  `json:"code"`
		CreatedAt hexutil.Uint64 `json:"createdAt"`
		ExpireAt  hexutil.Uint64 `json:"expireAt"`
		Expired   bool           `json:"expired"`
	}{
		CodeHash:  codeHash,
		Code:      hexutil.Bytes{0xde, 0xad},
		CreatedAt: hexutil.Uint64(10),
		ExpireAt:  hexutil.Uint64(110),
		Expired:   false,
	}
}

func (s *rpcExtTestService) GetCodeObjectMeta(codeHash common.Hash, block string) interface{} {
	return struct {
		CodeHash  common.Hash    `json:"codeHash"`
		CreatedAt hexutil.Uint64 `json:"createdAt"`
		ExpireAt  hexutil.Uint64 `json:"expireAt"`
		Expired   bool           `json:"expired"`
	}{
		CodeHash:  codeHash,
		CreatedAt: hexutil.Uint64(10),
		ExpireAt:  hexutil.Uint64(110),
		Expired:   false,
	}
}

func (s *rpcExtTestService) PutKVTTL(args PutKVTTLArgs) common.Hash {
	s.lastPutKVTTLArgs = args
	return common.HexToHash("0x3")
}

func (s *rpcExtTestService) GetKV(namespace string, key hexutil.Bytes, block string) interface{} {
	s.lastGetKVNamespace = namespace
	s.lastGetKVKey = key
	s.lastGetKVBlock = block
	return struct {
		Namespace string        `json:"namespace"`
		Key       hexutil.Bytes `json:"key"`
		Value     hexutil.Bytes `json:"value"`
	}{
		Namespace: namespace,
		Key:       key,
		Value:     hexutil.Bytes("value"),
	}
}

func (s *rpcExtTestService) GetKVMeta(namespace string, key hexutil.Bytes, block string) interface{} {
	return struct {
		Namespace string         `json:"namespace"`
		Key       hexutil.Bytes  `json:"key"`
		CreatedAt hexutil.Uint64 `json:"createdAt"`
		ExpireAt  hexutil.Uint64 `json:"expireAt"`
		Expired   bool           `json:"expired"`
	}{
		Namespace: namespace,
		Key:       key,
		CreatedAt: hexutil.Uint64(11),
		ExpireAt:  hexutil.Uint64(111),
		Expired:   false,
	}
}

func (s *rpcExtTestService) GetValidators(block string) []common.Address {
	s.lastDPoSQueryBlock = block
	return []common.Address{
		common.HexToAddress("0x0000000000000000000000000000000000000001"),
		common.HexToAddress("0x0000000000000000000000000000000000000002"),
	}
}

func (s *rpcExtTestService) GetValidator(address common.Address, block string) interface{} {
	s.lastDPoSQueryAddress = address
	s.lastDPoSQueryBlock = block
	index := hexutil.Uint(3)
	return struct {
		Address            common.Address   `json:"address"`
		Active             bool             `json:"active"`
		Index              *hexutil.Uint    `json:"index"`
		SnapshotBlock      hexutil.Uint64   `json:"snapshotBlock"`
		SnapshotHash       common.Hash      `json:"snapshotHash"`
		RecentSignedBlocks []hexutil.Uint64 `json:"recentSignedBlocks"`
	}{
		Address:            address,
		Active:             true,
		Index:              &index,
		SnapshotBlock:      hexutil.Uint64(120),
		SnapshotHash:       common.HexToHash("0x1234"),
		RecentSignedBlocks: []hexutil.Uint64{1, 2, 3},
	}
}

func (s *rpcExtTestService) GetEpochInfo(block string) interface{} {
	s.lastDPoSQueryBlock = block
	return struct {
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
	}{
		BlockNumber:        hexutil.Uint64(99),
		EpochLength:        hexutil.Uint64(50),
		EpochIndex:         hexutil.Uint64(1),
		EpochStart:         hexutil.Uint64(50),
		NextEpochStart:     hexutil.Uint64(100),
		BlocksUntilEpoch:   hexutil.Uint64(1),
		TargetBlockPeriodS: hexutil.Uint64(1),
		MaxValidators:      hexutil.Uint64(21),
		ValidatorCount:     hexutil.Uint64(7),
		SnapshotHash:       common.HexToHash("0x99"),
	}
}

func newRPCExtTestClient(t *testing.T) (*Client, *rpcExtTestService, func()) {
	t.Helper()
	server := rpc.NewServer()
	service := &rpcExtTestService{}
	if err := server.RegisterName("tos", service); err != nil {
		t.Fatalf("failed to register tos service: %v", err)
	}
	if err := server.RegisterName("dpos", service); err != nil {
		t.Fatalf("failed to register dpos service: %v", err)
	}
	raw := rpc.DialInProc(server)
	client := NewClient(raw)
	return client, service, func() {
		raw.Close()
		server.Stop()
	}
}

func TestRPCExtChainAndRetention(t *testing.T) {
	client, _, cleanup := newRPCExtTestClient(t)
	defer cleanup()

	ctx := context.Background()

	chain, err := client.GetChainProfile(ctx)
	if err != nil {
		t.Fatalf("GetChainProfile error: %v", err)
	}
	if chain.ChainID == nil || chain.ChainID.Cmp(big.NewInt(1666)) != 0 {
		t.Fatalf("unexpected chain id: %v", chain.ChainID)
	}
	if chain.NetworkID == nil || chain.NetworkID.Cmp(big.NewInt(1666)) != 0 {
		t.Fatalf("unexpected network id: %v", chain.NetworkID)
	}
	if chain.TargetBlockIntervalMs != 1000 || chain.RetainBlocks != 200 || chain.SnapshotInterval != 1000 {
		t.Fatalf("unexpected chain profile: %+v", chain)
	}

	retention, err := client.GetRetentionPolicy(ctx)
	if err != nil {
		t.Fatalf("GetRetentionPolicy error: %v", err)
	}
	if retention.HeadBlock != 1234 || retention.OldestAvailableBlock != 1035 {
		t.Fatalf("unexpected retention policy: %+v", retention)
	}

	watermark, err := client.GetPruneWatermark(ctx)
	if err != nil {
		t.Fatalf("GetPruneWatermark error: %v", err)
	}
	if watermark.HeadBlock != 1234 || watermark.RetainBlocks != 200 {
		t.Fatalf("unexpected prune watermark: %+v", watermark)
	}
}

func TestRPCExtStorageAndSignerMethods(t *testing.T) {
	client, svc, cleanup := newRPCExtTestClient(t)
	defer cleanup()

	ctx := context.Background()
	address := common.HexToAddress("0x00000000000000000000000000000000000000aa")

	account, err := client.GetAccount(ctx, address, nil)
	if err != nil {
		t.Fatalf("GetAccount error: %v", err)
	}
	if svc.lastGetAccountBlock != "latest" {
		t.Fatalf("GetAccount block arg = %q, want latest", svc.lastGetAccountBlock)
	}
	if account.Balance == nil || account.Balance.Cmp(big.NewInt(999)) != 0 {
		t.Fatalf("unexpected account balance: %v", account.Balance)
	}

	signer, err := client.GetSigner(ctx, address, big.NewInt(15))
	if err != nil {
		t.Fatalf("GetSigner error: %v", err)
	}
	if svc.lastGetSignerBlock != "0xf" {
		t.Fatalf("GetSigner block arg = %q, want 0xf", svc.lastGetSignerBlock)
	}
	if signer.Signer.Type != "secp256k1" || signer.Signer.Value != "0xabcdef" {
		t.Fatalf("unexpected signer profile: %+v", signer)
	}

	codeHash := common.HexToHash("0x1234")
	code, err := client.GetCodeObject(ctx, codeHash, big.NewInt(-1))
	if err != nil {
		t.Fatalf("GetCodeObject error: %v", err)
	}
	if svc.lastGetCodeBlock != "pending" {
		t.Fatalf("GetCodeObject block arg = %q, want pending", svc.lastGetCodeBlock)
	}
	if len(code.Code) != 2 || code.Code[0] != 0xde || code.Code[1] != 0xad {
		t.Fatalf("unexpected code object: %+v", code)
	}

	meta, err := client.GetCodeObjectMeta(ctx, codeHash, big.NewInt(8))
	if err != nil {
		t.Fatalf("GetCodeObjectMeta error: %v", err)
	}
	if meta.ExpireAt != 110 {
		t.Fatalf("unexpected code meta: %+v", meta)
	}

	kv, err := client.GetKV(ctx, "ns", []byte("k"), big.NewInt(20))
	if err != nil {
		t.Fatalf("GetKV error: %v", err)
	}
	if svc.lastGetKVBlock != "0x14" {
		t.Fatalf("GetKV block arg = %q, want 0x14", svc.lastGetKVBlock)
	}
	if kv.Namespace != "ns" || string(kv.Key) != "k" || string(kv.Value) != "value" {
		t.Fatalf("unexpected kv result: %+v", kv)
	}

	kvMeta, err := client.GetKVMeta(ctx, "ns", []byte("k"), nil)
	if err != nil {
		t.Fatalf("GetKVMeta error: %v", err)
	}
	if kvMeta.CreatedAt != 11 || kvMeta.ExpireAt != 111 || kvMeta.Expired {
		t.Fatalf("unexpected kv meta: %+v", kvMeta)
	}
}

func TestRPCExtWriteAndDPoSMethods(t *testing.T) {
	client, svc, cleanup := newRPCExtTestClient(t)
	defer cleanup()

	ctx := context.Background()
	from := common.HexToAddress("0x00000000000000000000000000000000000000bb")

	setSignerArgs := SetSignerArgs{
		From:        from,
		SignerType:  "ed25519",
		SignerValue: "z6Mkj...",
	}
	hash, err := client.SetSigner(ctx, setSignerArgs)
	if err != nil {
		t.Fatalf("SetSigner error: %v", err)
	}
	if hash != common.HexToHash("0x1") {
		t.Fatalf("unexpected setSigner hash: %s", hash.Hex())
	}
	if svc.lastSetSignerArgs.SignerType != "ed25519" {
		t.Fatalf("setSigner args were not forwarded")
	}

	tx, err := client.BuildSetSignerTx(ctx, setSignerArgs)
	if err != nil {
		t.Fatalf("BuildSetSignerTx error: %v", err)
	}
	if tx == nil || len(tx.Raw) != 2 || tx.Raw[0] != 0xaa {
		t.Fatalf("unexpected buildSetSignerTx result: %+v", tx)
	}

	codeHash, err := client.SetCode(ctx, SetCodeArgs{
		From: from,
		Code: hexutil.Bytes{0x60, 0x00},
		TTL:  hexutil.Uint64(600),
	})
	if err != nil {
		t.Fatalf("SetCode error: %v", err)
	}
	if codeHash != common.HexToHash("0x2") {
		t.Fatalf("unexpected setCode hash: %s", codeHash.Hex())
	}
	if svc.lastSetCodeArgs.From != from || svc.lastSetCodeArgs.TTL != hexutil.Uint64(600) {
		t.Fatalf("setCode args were not forwarded: %+v", svc.lastSetCodeArgs)
	}
	estimateGas, err := client.EstimateSetCodeGas(ctx, []byte{0x60, 0x00}, 600)
	if err != nil {
		t.Fatalf("EstimateSetCodeGas error: %v", err)
	}
	if estimateGas != 77777 {
		t.Fatalf("unexpected estimateSetCodeGas result: %d", estimateGas)
	}
	if string(svc.lastEstimateSetCodeGasCode) != string([]byte{0x60, 0x00}) || svc.lastEstimateSetCodeGasTTL != hexutil.Uint64(600) {
		t.Fatalf("estimateSetCodeGas args were not forwarded: code=%x ttl=%d", []byte(svc.lastEstimateSetCodeGasCode), svc.lastEstimateSetCodeGasTTL)
	}

	kvHash, err := client.PutKVTTL(ctx, PutKVTTLArgs{
		From:      from,
		Namespace: "ns",
		Key:       hexutil.Bytes("k"),
		Value:     hexutil.Bytes("v"),
		TTL:       hexutil.Uint64(300),
	})
	if err != nil {
		t.Fatalf("PutKVTTL error: %v", err)
	}
	if kvHash != common.HexToHash("0x3") {
		t.Fatalf("unexpected putKVTTL hash: %s", kvHash.Hex())
	}

	validators, err := client.DPoSGetValidators(ctx, nil)
	if err != nil {
		t.Fatalf("DPoSGetValidators error: %v", err)
	}
	if svc.lastDPoSQueryBlock != "latest" || len(validators) != 2 {
		t.Fatalf("unexpected validators response: block=%q validators=%v", svc.lastDPoSQueryBlock, validators)
	}

	validator, err := client.DPoSGetValidator(ctx, validators[0], big.NewInt(9))
	if err != nil {
		t.Fatalf("DPoSGetValidator error: %v", err)
	}
	if svc.lastDPoSQueryBlock != "0x9" {
		t.Fatalf("DPoSGetValidator block arg = %q, want 0x9", svc.lastDPoSQueryBlock)
	}
	if validator.Index == nil || *validator.Index != 3 {
		t.Fatalf("unexpected validator index: %+v", validator)
	}
	if len(validator.RecentSignedBlocks) != 3 || validator.RecentSignedBlocks[2] != 3 {
		t.Fatalf("unexpected recent signed blocks: %+v", validator.RecentSignedBlocks)
	}

	epoch, err := client.DPoSGetEpochInfo(ctx, big.NewInt(-1))
	if err != nil {
		t.Fatalf("DPoSGetEpochInfo error: %v", err)
	}
	if svc.lastDPoSQueryBlock != "pending" {
		t.Fatalf("DPoSGetEpochInfo block arg = %q, want pending", svc.lastDPoSQueryBlock)
	}
	if epoch.TargetBlockPeriodS != 1 || epoch.ValidatorCount != 7 {
		t.Fatalf("unexpected epoch info: %+v", epoch)
	}
}

type rpcExtErrorService struct{}

func (s *rpcExtErrorService) GetChainProfile() (interface{}, error) {
	return nil, rpcExtTestError{
		msg:  "chain profile unavailable",
		code: -38008,
		data: map[string]interface{}{"reason": "retention unavailable"},
	}
}

func (s *rpcExtErrorService) SetSigner(args SetSignerArgs) (common.Hash, error) {
	_ = args
	return common.Hash{}, rpcExtTestError{
		msg:  "invalid signer payload",
		code: -38007,
		data: map[string]interface{}{"reason": "unsupported signer type"},
	}
}

func TestRPCExtErrorPropagation(t *testing.T) {
	server := rpc.NewServer()
	if err := server.RegisterName("tos", &rpcExtErrorService{}); err != nil {
		t.Fatalf("failed to register tos service: %v", err)
	}
	raw := rpc.DialInProc(server)
	client := NewClient(raw)
	defer raw.Close()
	defer server.Stop()

	_, err := client.GetChainProfile(context.Background())
	if err == nil {
		t.Fatalf("GetChainProfile expected error")
	}
	rpcErr, ok := err.(rpc.Error)
	if !ok {
		t.Fatalf("GetChainProfile error type = %T, want rpc.Error", err)
	}
	if rpcErr.ErrorCode() != -38008 {
		t.Fatalf("GetChainProfile error code = %d, want -38008", rpcErr.ErrorCode())
	}
	dataErr, ok := err.(rpc.DataError)
	if !ok || dataErr.ErrorData() == nil {
		t.Fatalf("GetChainProfile missing rpc.DataError payload")
	}

	_, err = client.SetSigner(context.Background(), SetSignerArgs{
		From:        common.HexToAddress("0x0000000000000000000000000000000000000011"),
		SignerType:  "invalid",
		SignerValue: "x",
	})
	if err == nil {
		t.Fatalf("SetSigner expected error")
	}
	rpcErr, ok = err.(rpc.Error)
	if !ok {
		t.Fatalf("SetSigner error type = %T, want rpc.Error", err)
	}
	if rpcErr.ErrorCode() != -38007 {
		t.Fatalf("SetSigner error code = %d, want -38007", rpcErr.ErrorCode())
	}

	_, err = client.DPoSGetEpochInfo(context.Background(), nil)
	if err == nil {
		t.Fatalf("DPoSGetEpochInfo expected method-not-found error")
	}
	rpcErr, ok = err.(rpc.Error)
	if !ok {
		t.Fatalf("DPoSGetEpochInfo error type = %T, want rpc.Error", err)
	}
	if rpcErr.ErrorCode() != -32601 {
		t.Fatalf("DPoSGetEpochInfo error code = %d, want -32601", rpcErr.ErrorCode())
	}
}
