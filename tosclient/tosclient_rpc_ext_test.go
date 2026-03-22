package tosclient

import (
	"context"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/agentdiscovery"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/rpc"
	tolmeta "github.com/tos-network/tolang/metadata"
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

	lastGetSponsorNonceAddress common.Address
	lastGetSponsorNonceBlock   string

	lastGetLeaseAddress common.Address
	lastGetLeaseBlock   string

	lastGetContractMetadataAddress common.Address
	lastGetContractMetadataBlock   string

	lastGetCapabilityName        string
	lastGetDelegationPrincipal   string
	lastGetDelegationDelegate    string
	lastGetDelegationScope       string
	lastGetPackageName           string
	lastGetPackageVersion        string
	lastGetPackageByHash         string
	lastGetLatestPackageName     string
	lastGetLatestPackageChannel  string
	lastGetPublisherID           string
	lastGetPublisherNamespace    string
	lastGetNamespaceClaim        string
	lastGetVerifierName          string
	lastGetVerificationSubject   string
	lastGetVerificationProofType string
	lastGetSettlementPolicyOwner string
	lastGetSettlementPolicyAsset string
	lastGetAgentIdentityAddress  string

	lastGetCodeHash  common.Hash
	lastGetCodeBlock string

	lastAgentDiscoveryPublishArgs          AgentDiscoveryPublishArgs
	lastAgentDiscoveryPublishSuggestedArgs AgentDiscoveryPublishSuggestedArgs
	lastAgentDiscoverySuggestedCardArgs    AgentDiscoverySuggestedCardArgs
	lastAgentDiscoverySearchCapability     string
	lastAgentDiscoverySearchLimit          *int
	lastAgentDiscoveryGetCardNodeRecord    string
	lastAgentDiscoveryDirectoryNodeRecord  string
	lastAgentDiscoveryDirectoryCapability  string
	lastAgentDiscoveryDirectoryLimit       *int

	lastLeaseDeployArgs      LeaseDeployArgs
	lastLeaseDeployBuildArgs LeaseDeployArgs
	lastLeaseRenewArgs       LeaseRenewArgs
	lastLeaseRenewBuildArgs  LeaseRenewArgs
	lastLeaseCloseArgs       LeaseCloseArgs
	lastLeaseCloseBuildArgs  LeaseCloseArgs
	lastSetSignerArgs        SetSignerArgs
	lastBuildSignerArgs      SetSignerArgs
	lastMaintenanceArgs      ValidatorMaintenanceArgs
	lastMaintenanceBuildArgs ValidatorMaintenanceArgs
	lastMaintenanceMethod    string
	lastEvidenceSubmitArgs   SubmitMaliciousVoteEvidenceArgs
	lastEvidenceBuildArgs    SubmitMaliciousVoteEvidenceArgs
	lastDPoSQueryAddress     common.Address
	lastDPoSQueryBlock       string
}

func commonAddressPtr(addr common.Address) *common.Address {
	return &addr
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

func (s *rpcExtTestService) GetSponsorNonce(address common.Address, block string) interface{} {
	s.lastGetSponsorNonceAddress = address
	s.lastGetSponsorNonceBlock = block
	return hexutil.Uint64(23)
}

func (s *rpcExtTestService) GetLease(address common.Address, block string) interface{} {
	s.lastGetLeaseAddress = address
	s.lastGetLeaseBlock = block
	return struct {
		Address             common.Address `json:"address"`
		LeaseOwner          common.Address `json:"leaseOwner"`
		CreatedAtBlock      hexutil.Uint64 `json:"createdAtBlock"`
		ExpireAtBlock       hexutil.Uint64 `json:"expireAtBlock"`
		GraceUntilBlock     hexutil.Uint64 `json:"graceUntilBlock"`
		CodeBytes           hexutil.Uint64 `json:"codeBytes"`
		DepositWei          *hexutil.Big   `json:"depositWei"`
		ScheduledPruneEpoch hexutil.Uint64 `json:"scheduledPruneEpoch"`
		ScheduledPruneSeq   hexutil.Uint64 `json:"scheduledPruneSeq"`
		Status              string         `json:"status"`
		Tombstoned          bool           `json:"tombstoned"`
		TombstoneCodeHash   common.Hash    `json:"tombstoneCodeHash"`
		TombstoneExpiredAt  hexutil.Uint64 `json:"tombstoneExpiredAt"`
		BlockNumber         hexutil.Uint64 `json:"blockNumber"`
	}{
		Address:             address,
		LeaseOwner:          common.HexToAddress("0x1234"),
		CreatedAtBlock:      hexutil.Uint64(10),
		ExpireAtBlock:       hexutil.Uint64(110),
		GraceUntilBlock:     hexutil.Uint64(120),
		CodeBytes:           hexutil.Uint64(256),
		DepositWei:          (*hexutil.Big)(big.NewInt(9999)),
		ScheduledPruneEpoch: hexutil.Uint64(2),
		ScheduledPruneSeq:   hexutil.Uint64(7),
		Status:              "active",
		Tombstoned:          false,
		TombstoneCodeHash:   common.Hash{},
		TombstoneExpiredAt:  hexutil.Uint64(0),
		BlockNumber:         hexutil.Uint64(88),
	}
}

func (s *rpcExtTestService) GetContractMetadata(address common.Address, block string) interface{} {
	s.lastGetContractMetadataAddress = address
	s.lastGetContractMetadataBlock = block
	return DeployedCodeInfo{
		Address:  address,
		CodeHash: common.HexToHash("0xcafe"),
		CodeKind: "tor",
		Package: &TOLPackageInfo{
			Name:         "privacy",
			Package:      "tolang.openlib.privacy",
			Version:      "1.0.0",
			MainContract: "ConfidentialEscrow",
			Profile: &tolmeta.AgentBundleProfile{
				SchemaVersion: tolmeta.AgentBundleProfileSchemaVersion,
			},
			Published: &PackageInfo{
				Name:        "tolang.openlib.privacy",
				Namespace:   "tolang.openlib",
				Version:     "1.0.0",
				PackageHash: common.HexToHash("0xbeef").Hex(),
				PublisherID: common.HexToAddress("0x7777").Hex(),
				Channel:     "stable",
				Status:      "active",
				Trusted:     true,
			},
			Publisher: &PublisherInfo{
				PublisherID: common.HexToAddress("0x7777").Hex(),
				Controller:  common.HexToAddress("0x9999").Hex(),
				Namespace:   "tolang.openlib",
				Status:      "active",
			},
			SuggestedCard: &agentdiscovery.PublishedCard{
				Version:        1,
				AgentID:        "privacy-agent",
				AgentAddress:   common.HexToAddress("0x1234").Hex(),
				PackageName:    "tolang.openlib.privacy",
				PackageVersion: "1.0.0",
				ProfileRef:     "openlib/releases/privacy/privacy.bundle.profile.json",
			},
		},
	}
}

func (s *rpcExtTestService) TolGetCapability(name string) interface{} {
	s.lastGetCapabilityName = name
	return &CapabilityInfo{
		Name:     name,
		BitIndex: 7,
		Status:   "active",
	}
}

func (s *rpcExtTestService) TolGetDelegation(principalHex, delegateHex, scopeHex string) interface{} {
	s.lastGetDelegationPrincipal = principalHex
	s.lastGetDelegationDelegate = delegateHex
	s.lastGetDelegationScope = scopeHex
	return &DelegationInfo{
		Principal:       principalHex,
		Delegate:        delegateHex,
		ScopeRef:        scopeHex,
		Status:          "active",
		EffectiveStatus: "active",
	}
}

func (s *rpcExtTestService) TolGetPackage(name, version string) interface{} {
	s.lastGetPackageName = name
	s.lastGetPackageVersion = version
	return &PackageInfo{
		Name:            name,
		Version:         version,
		PackageHash:     common.HexToHash("0x1111").Hex(),
		PublisherID:     common.HexToHash("0x2222").Hex(),
		Channel:         "stable",
		Status:          "active",
		EffectiveStatus: "active",
		NamespaceStatus: "clear",
		Trusted:         true,
	}
}

func (s *rpcExtTestService) TolGetPackageByHash(packageHash string) interface{} {
	s.lastGetPackageByHash = packageHash
	return &PackageInfo{
		Name:            "tolang.openlib.privacy",
		Version:         "1.0.0",
		PackageHash:     packageHash,
		PublisherID:     common.HexToHash("0x2222").Hex(),
		Channel:         "stable",
		Status:          "active",
		EffectiveStatus: "active",
		NamespaceStatus: "clear",
		Trusted:         true,
	}
}

func (s *rpcExtTestService) TolGetLatestPackage(name, channel string) interface{} {
	s.lastGetLatestPackageName = name
	s.lastGetLatestPackageChannel = channel
	return &PackageInfo{
		Name:            name,
		Version:         "1.2.3",
		PackageHash:     common.HexToHash("0x3333").Hex(),
		PublisherID:     common.HexToHash("0x2222").Hex(),
		Channel:         channel,
		Status:          "active",
		EffectiveStatus: "active",
		NamespaceStatus: "clear",
		Trusted:         true,
	}
}

func (s *rpcExtTestService) TolGetPublisher(publisherID string) interface{} {
	s.lastGetPublisherID = publisherID
	return &PublisherInfo{
		PublisherID:     publisherID,
		Controller:      common.HexToAddress("0x4444").Hex(),
		Namespace:       "tolang.openlib",
		Status:          "active",
		EffectiveStatus: "active",
		NamespaceStatus: "clear",
	}
}

func (s *rpcExtTestService) TolGetPublisherByNamespace(namespace string) interface{} {
	s.lastGetPublisherNamespace = namespace
	return &PublisherInfo{
		PublisherID:     common.HexToHash("0x2222").Hex(),
		Controller:      common.HexToAddress("0x4444").Hex(),
		Namespace:       namespace,
		Status:          "active",
		EffectiveStatus: "active",
		NamespaceStatus: "clear",
	}
}

func (s *rpcExtTestService) TolGetNamespaceClaim(namespace string) interface{} {
	s.lastGetNamespaceClaim = namespace
	return &NamespaceGovernanceInfo{
		Namespace:   namespace,
		PublisherID: common.HexToHash("0x2222").Hex(),
		Status:      "disputed",
		EvidenceRef: common.HexToHash("0x9999").Hex(),
	}
}

func (s *rpcExtTestService) TolGetVerifier(name string) interface{} {
	s.lastGetVerifierName = name
	return &VerifierInfo{
		Name:         name,
		VerifierType: 1,
		VerifierAddr: common.HexToAddress("0x5555").Hex(),
		Status:       "active",
	}
}

func (s *rpcExtTestService) TolGetVerification(subjectHex, proofType string) interface{} {
	s.lastGetVerificationSubject = subjectHex
	s.lastGetVerificationProofType = proofType
	return &VerificationClaimInfo{
		Subject:         subjectHex,
		ProofType:       proofType,
		Status:          "active",
		EffectiveStatus: "active",
	}
}

func (s *rpcExtTestService) TolGetSettlementPolicy(ownerHex, asset string) interface{} {
	s.lastGetSettlementPolicyOwner = ownerHex
	s.lastGetSettlementPolicyAsset = asset
	return &SettlementPolicyInfo{
		PolicyID:  common.HexToHash("0x6666").Hex(),
		Owner:     ownerHex,
		Asset:     asset,
		MaxAmount: "1000",
		Status:    "active",
	}
}

func (s *rpcExtTestService) TolGetAgentIdentity(agentHex string) interface{} {
	s.lastGetAgentIdentityAddress = agentHex
	return &AgentIdentityInfo{
		AgentAddress: agentHex,
		Registered:   true,
		Status:       1,
		Stake:        "42",
	}
}

func (s *rpcExtTestService) AgentDiscoveryInfo() interface{} {
	return agentdiscovery.Info{
		Enabled:          true,
		ProfileVersion:   agentdiscovery.ProfileVersion,
		TalkProtocol:     agentdiscovery.TalkProtocol,
		NodeID:           "node-1",
		NodeRecord:       "enr:-test",
		PrimaryIdentity:  common.HexToAddress("0x1234").Hex(),
		CardSequence:     9,
		ConnectionModes:  agentdiscovery.ConnectionModeTalkReq,
		Capabilities:     []string{"settlement.execute"},
		HasPublishedCard: true,
	}
}

func (s *rpcExtTestService) AgentDiscoveryPublish(args AgentDiscoveryPublishArgs) interface{} {
	s.lastAgentDiscoveryPublishArgs = args
	return agentdiscovery.Info{
		Enabled:          true,
		ProfileVersion:   agentdiscovery.ProfileVersion,
		TalkProtocol:     agentdiscovery.TalkProtocol,
		PrimaryIdentity:  args.PrimaryIdentity.Hex(),
		CardSequence:     args.CardSequence,
		ConnectionModes:  agentdiscovery.ConnectionModeTalkReq,
		Capabilities:     args.Capabilities,
		HasPublishedCard: true,
	}
}

func (s *rpcExtTestService) AgentDiscoveryPublishSuggested(args AgentDiscoveryPublishSuggestedArgs) interface{} {
	s.lastAgentDiscoveryPublishSuggestedArgs = args
	return agentdiscovery.Info{
		Enabled:          true,
		ProfileVersion:   agentdiscovery.ProfileVersion,
		TalkProtocol:     agentdiscovery.TalkProtocol,
		PrimaryIdentity:  args.PrimaryIdentity.Hex(),
		CardSequence:     args.CardSequence,
		ConnectionModes:  agentdiscovery.ConnectionModeTalkReq,
		Capabilities:     []string{"settlement.execute"},
		HasPublishedCard: true,
	}
}

func (s *rpcExtTestService) AgentDiscoveryGetSuggestedCard(args AgentDiscoverySuggestedCardArgs) interface{} {
	s.lastAgentDiscoverySuggestedCardArgs = args
	return agentdiscovery.PublishedCard{
		Version:        1,
		AgentID:        "settlement-agent",
		AgentAddress:   common.HexToAddress("0x1234").Hex(),
		PackageName:    "tolang.openlib.settlement",
		PackageVersion: "1.0.0",
		ProfileRef:     "openlib/releases/settlement/TaskSettlement.profile.json",
		Capabilities: []agentdiscovery.PublishedCapability{
			{Name: "settlement.execute", Mode: "managed"},
		},
	}
}

func (s *rpcExtTestService) AgentDiscoveryClear() interface{} {
	return agentdiscovery.Info{
		Enabled:          true,
		ProfileVersion:   agentdiscovery.ProfileVersion,
		TalkProtocol:     agentdiscovery.TalkProtocol,
		HasPublishedCard: false,
	}
}

func (s *rpcExtTestService) AgentDiscoverySearch(capability string, limit *int) interface{} {
	s.lastAgentDiscoverySearchCapability = capability
	s.lastAgentDiscoverySearchLimit = limit
	return []agentdiscovery.SearchResult{{
		NodeID:          "node-1",
		NodeRecord:      "enr:-test",
		PrimaryIdentity: common.HexToAddress("0x1234").Hex(),
		Capabilities:    []string{capability},
	}}
}

func (s *rpcExtTestService) AgentDiscoveryGetCard(nodeRecord string) interface{} {
	s.lastAgentDiscoveryGetCardNodeRecord = nodeRecord
	return agentdiscovery.CardResponse{
		NodeID:     "node-1",
		NodeRecord: nodeRecord,
		CardJSON:   `{"agent_id":"settlement-agent"}`,
		ParsedCard: &agentdiscovery.PublishedCard{AgentID: "settlement-agent"},
	}
}

func (s *rpcExtTestService) AgentDiscoveryDirectorySearch(nodeRecord string, capability string, limit *int) interface{} {
	s.lastAgentDiscoveryDirectoryNodeRecord = nodeRecord
	s.lastAgentDiscoveryDirectoryCapability = capability
	s.lastAgentDiscoveryDirectoryLimit = limit
	return []agentdiscovery.SearchResult{{
		NodeID:          "node-2",
		NodeRecord:      "enr:-dir",
		PrimaryIdentity: common.HexToAddress("0x5678").Hex(),
		Capabilities:    []string{capability},
	}}
}

func (s *rpcExtTestService) LeaseDeploy(args LeaseDeployArgs) interface{} {
	s.lastLeaseDeployArgs = args
	return LeaseDeployResult{
		TxHash:          common.HexToHash("0x10"),
		ContractAddress: common.HexToAddress("0x1010"),
	}
}

func (s *rpcExtTestService) BuildLeaseDeployTx(args LeaseDeployArgs) interface{} {
	s.lastLeaseDeployBuildArgs = args
	return BuildSetSignerTxResult{
		Tx:              map[string]interface{}{"from": args.From.Hex()},
		Raw:             hexutil.Bytes{0x31, 0x32},
		ContractAddress: commonAddressPtr(common.HexToAddress("0x1010")),
	}
}

func (s *rpcExtTestService) LeaseRenew(args LeaseRenewArgs) common.Hash {
	s.lastLeaseRenewArgs = args
	return common.HexToHash("0x11")
}

func (s *rpcExtTestService) BuildLeaseRenewTx(args LeaseRenewArgs) interface{} {
	s.lastLeaseRenewBuildArgs = args
	return BuildSetSignerTxResult{
		Tx:  map[string]interface{}{"from": args.From.Hex()},
		Raw: hexutil.Bytes{0x33, 0x34},
	}
}

func (s *rpcExtTestService) LeaseClose(args LeaseCloseArgs) common.Hash {
	s.lastLeaseCloseArgs = args
	return common.HexToHash("0x12")
}

func (s *rpcExtTestService) BuildLeaseCloseTx(args LeaseCloseArgs) interface{} {
	s.lastLeaseCloseBuildArgs = args
	return BuildSetSignerTxResult{
		Tx:  map[string]interface{}{"from": args.From.Hex()},
		Raw: hexutil.Bytes{0x35, 0x36},
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

func (s *rpcExtTestService) EnterMaintenance(args ValidatorMaintenanceArgs) common.Hash {
	s.lastMaintenanceArgs = args
	s.lastMaintenanceMethod = "enter"
	return common.HexToHash("0x2")
}

func (s *rpcExtTestService) BuildEnterMaintenanceTx(args ValidatorMaintenanceArgs) interface{} {
	s.lastMaintenanceBuildArgs = args
	s.lastMaintenanceMethod = "build-enter"
	return BuildSetSignerTxResult{
		Tx:  map[string]interface{}{"from": args.From.Hex()},
		Raw: hexutil.Bytes{0xcc, 0xdd},
	}
}

func (s *rpcExtTestService) ExitMaintenance(args ValidatorMaintenanceArgs) common.Hash {
	s.lastMaintenanceArgs = args
	s.lastMaintenanceMethod = "exit"
	return common.HexToHash("0x3")
}

func (s *rpcExtTestService) BuildExitMaintenanceTx(args ValidatorMaintenanceArgs) interface{} {
	s.lastMaintenanceBuildArgs = args
	s.lastMaintenanceMethod = "build-exit"
	return BuildSetSignerTxResult{
		Tx:  map[string]interface{}{"from": args.From.Hex()},
		Raw: hexutil.Bytes{0xee, 0xff},
	}
}

func (s *rpcExtTestService) SubmitMaliciousVoteEvidence(args SubmitMaliciousVoteEvidenceArgs) common.Hash {
	s.lastEvidenceSubmitArgs = args
	return common.HexToHash("0x4")
}

func (s *rpcExtTestService) BuildSubmitMaliciousVoteEvidenceTx(args SubmitMaliciousVoteEvidenceArgs) interface{} {
	s.lastEvidenceBuildArgs = args
	return BuildSetSignerTxResult{
		Tx:  map[string]interface{}{"from": args.From.Hex()},
		Raw: hexutil.Bytes{0x11, 0x22},
	}
}

func (s *rpcExtTestService) GetMaliciousVoteEvidence(hash common.Hash, block string) interface{} {
	s.lastGetCodeHash = hash
	s.lastGetCodeBlock = block
	return struct {
		EvidenceHash common.Hash    `json:"evidenceHash"`
		OffenseKey   common.Hash    `json:"offenseKey"`
		Number       hexutil.Uint64 `json:"number"`
		Signer       common.Address `json:"signer"`
		SubmittedBy  common.Address `json:"submittedBy"`
		SubmittedAt  hexutil.Uint64 `json:"submittedAt"`
		Status       string         `json:"status"`
	}{
		EvidenceHash: hash,
		OffenseKey:   common.HexToHash("0xf1"),
		Number:       hexutil.Uint64(64),
		Signer:       common.HexToAddress("0x100"),
		SubmittedBy:  common.HexToAddress("0x200"),
		SubmittedAt:  hexutil.Uint64(77),
		Status:       "submitted",
	}
}

func (s *rpcExtTestService) ListMaliciousVoteEvidence(limit hexutil.Uint64, block string) interface{} {
	s.lastGetCodeBlock = block
	return []struct {
		EvidenceHash common.Hash    `json:"evidenceHash"`
		OffenseKey   common.Hash    `json:"offenseKey"`
		Number       hexutil.Uint64 `json:"number"`
		Signer       common.Address `json:"signer"`
		SubmittedBy  common.Address `json:"submittedBy"`
		SubmittedAt  hexutil.Uint64 `json:"submittedAt"`
		Status       string         `json:"status"`
	}{
		{
			EvidenceHash: common.HexToHash("0xa1"),
			OffenseKey:   common.HexToHash("0xf1"),
			Number:       hexutil.Uint64(limit),
			Signer:       common.HexToAddress("0x100"),
			SubmittedBy:  common.HexToAddress("0x200"),
			SubmittedAt:  hexutil.Uint64(77),
			Status:       "submitted",
		},
	}
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

func (s *rpcExtTestService) GetValidators(block string) []common.Address {
	s.lastDPoSQueryBlock = block
	return []common.Address{
		common.HexToAddress("0x969b0a11b8a56bacf1ac18f219e7e376e7c213b7e7e7e46cc70a5dd086daff2a"),
		common.HexToAddress("0x85b1f044bab6d30f3a19c1501563915e194d8cfba1943570603f7606a3115508"),
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
		BlockNumber         hexutil.Uint64 `json:"blockNumber"`
		EpochLength         hexutil.Uint64 `json:"epochLength"`
		EpochIndex          hexutil.Uint64 `json:"epochIndex"`
		EpochStart          hexutil.Uint64 `json:"epochStart"`
		NextEpochStart      hexutil.Uint64 `json:"nextEpochStart"`
		BlocksUntilEpoch    hexutil.Uint64 `json:"blocksUntilEpoch"`
		TargetBlockPeriodMs hexutil.Uint64 `json:"targetBlockPeriodMs"`
		TurnLength          hexutil.Uint64 `json:"turnLength"`
		TurnGroupDurationMs hexutil.Uint64 `json:"turnGroupDurationMs"`
		RecentSignerWindow  hexutil.Uint64 `json:"recentSignerWindow"`
		MaxValidators       hexutil.Uint64 `json:"maxValidators"`
		ValidatorCount      hexutil.Uint64 `json:"validatorCount"`
		SnapshotHash        common.Hash    `json:"snapshotHash"`
	}{
		BlockNumber:         hexutil.Uint64(99),
		EpochLength:         hexutil.Uint64(50),
		EpochIndex:          hexutil.Uint64(1),
		EpochStart:          hexutil.Uint64(50),
		NextEpochStart:      hexutil.Uint64(100),
		BlocksUntilEpoch:    hexutil.Uint64(1),
		TargetBlockPeriodMs: hexutil.Uint64(1000),
		TurnLength:          hexutil.Uint64(16),
		TurnGroupDurationMs: hexutil.Uint64(16000),
		RecentSignerWindow:  hexutil.Uint64(31),
		MaxValidators:       hexutil.Uint64(21),
		ValidatorCount:      hexutil.Uint64(7),
		SnapshotHash:        common.HexToHash("0x99"),
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
	address := common.HexToAddress("0xf81c536380b2dd5ef5c4ae95e1fae9b4fab2f5726677ecfa912d96b0b683e6a9")

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

	sponsorNonce, err := client.GetSponsorNonce(ctx, address, big.NewInt(16))
	if err != nil {
		t.Fatalf("GetSponsorNonce error: %v", err)
	}
	if svc.lastGetSponsorNonceBlock != "0x10" {
		t.Fatalf("GetSponsorNonce block arg = %q, want 0x10", svc.lastGetSponsorNonceBlock)
	}
	if sponsorNonce != 23 {
		t.Fatalf("unexpected sponsor nonce: %d", sponsorNonce)
	}

	leaseRec, err := client.GetLease(ctx, address, big.NewInt(6))
	if err != nil {
		t.Fatalf("GetLease error: %v", err)
	}
	if svc.lastGetLeaseBlock != "0x6" {
		t.Fatalf("GetLease block arg = %q, want 0x6", svc.lastGetLeaseBlock)
	}
	if leaseRec == nil || leaseRec.Status != "active" || leaseRec.BlockNumber != 88 {
		t.Fatalf("unexpected lease record: %+v", leaseRec)
	}

	codeInfo, err := client.GetContractMetadata(ctx, address, big.NewInt(5))
	if err != nil {
		t.Fatalf("GetContractMetadata error: %v", err)
	}
	if svc.lastGetContractMetadataBlock != "0x5" {
		t.Fatalf("GetContractMetadata block arg = %q, want 0x5", svc.lastGetContractMetadataBlock)
	}
	if codeInfo.Package == nil || codeInfo.Package.SuggestedCard == nil || codeInfo.Package.SuggestedCard.AgentID != "privacy-agent" {
		t.Fatalf("unexpected contract metadata: %+v", codeInfo)
	}
	if codeInfo.Package.Published == nil || !codeInfo.Package.Published.Trusted {
		t.Fatalf("expected published package trust info, got %+v", codeInfo.Package)
	}

	capabilityInfo, err := client.GetCapability(ctx, "settlement.execute")
	if err != nil {
		t.Fatalf("GetCapability error: %v", err)
	}
	if svc.lastGetCapabilityName != "settlement.execute" || capabilityInfo == nil || capabilityInfo.BitIndex != 7 {
		t.Fatalf("unexpected capability info: arg=%q out=%+v", svc.lastGetCapabilityName, capabilityInfo)
	}

	scopeRef := common.HexToHash("0x7777")
	delegationInfo, err := client.GetDelegation(ctx, address, common.HexToAddress("0x9999"), scopeRef)
	if err != nil {
		t.Fatalf("GetDelegation error: %v", err)
	}
	if svc.lastGetDelegationScope != scopeRef.Hex() || delegationInfo == nil || delegationInfo.ScopeRef != scopeRef.Hex() {
		t.Fatalf("unexpected delegation info: scope=%q out=%+v", svc.lastGetDelegationScope, delegationInfo)
	}

	pkgInfo, err := client.GetPackage(ctx, "tolang.openlib.privacy", "1.0.0")
	if err != nil {
		t.Fatalf("GetPackage error: %v", err)
	}
	if svc.lastGetPackageName != "tolang.openlib.privacy" || pkgInfo == nil || !pkgInfo.Trusted {
		t.Fatalf("unexpected package info: name=%q out=%+v", svc.lastGetPackageName, pkgInfo)
	}

	pkgByHash, err := client.GetPackageByHash(ctx, common.HexToHash("0xabcd"))
	if err != nil {
		t.Fatalf("GetPackageByHash error: %v", err)
	}
	if svc.lastGetPackageByHash != common.HexToHash("0xabcd").Hex() || pkgByHash == nil || pkgByHash.PackageHash != common.HexToHash("0xabcd").Hex() {
		t.Fatalf("unexpected package-by-hash info: hash=%q out=%+v", svc.lastGetPackageByHash, pkgByHash)
	}

	latestPkg, err := client.GetLatestPackage(ctx, "tolang.openlib.privacy", "stable")
	if err != nil {
		t.Fatalf("GetLatestPackage error: %v", err)
	}
	if svc.lastGetLatestPackageChannel != "stable" || latestPkg == nil || latestPkg.Version != "1.2.3" {
		t.Fatalf("unexpected latest package info: channel=%q out=%+v", svc.lastGetLatestPackageChannel, latestPkg)
	}

	publisherInfo, err := client.GetPublisher(ctx, common.HexToHash("0x2222"))
	if err != nil {
		t.Fatalf("GetPublisher error: %v", err)
	}
	if svc.lastGetPublisherID != common.HexToHash("0x2222").Hex() || publisherInfo == nil || publisherInfo.Namespace != "tolang.openlib" {
		t.Fatalf("unexpected publisher info: id=%q out=%+v", svc.lastGetPublisherID, publisherInfo)
	}

	publisherByNS, err := client.GetPublisherByNamespace(ctx, "tolang.openlib")
	if err != nil {
		t.Fatalf("GetPublisherByNamespace error: %v", err)
	}
	if svc.lastGetPublisherNamespace != "tolang.openlib" || publisherByNS == nil || publisherByNS.Namespace != "tolang.openlib" {
		t.Fatalf("unexpected publisher-by-namespace info: namespace=%q out=%+v", svc.lastGetPublisherNamespace, publisherByNS)
	}

	namespaceClaim, err := client.GetNamespaceClaim(ctx, "tolang.openlib")
	if err != nil {
		t.Fatalf("GetNamespaceClaim error: %v", err)
	}
	if svc.lastGetNamespaceClaim != "tolang.openlib" || namespaceClaim == nil || namespaceClaim.Status != "disputed" {
		t.Fatalf("unexpected namespace claim: namespace=%q out=%+v", svc.lastGetNamespaceClaim, namespaceClaim)
	}

	verifierInfo, err := client.GetVerifier(ctx, "zk-settlement")
	if err != nil {
		t.Fatalf("GetVerifier error: %v", err)
	}
	if svc.lastGetVerifierName != "zk-settlement" || verifierInfo == nil || verifierInfo.VerifierType != 1 {
		t.Fatalf("unexpected verifier info: name=%q out=%+v", svc.lastGetVerifierName, verifierInfo)
	}

	verificationInfo, err := client.GetVerification(ctx, address, "zktls")
	if err != nil {
		t.Fatalf("GetVerification error: %v", err)
	}
	if svc.lastGetVerificationProofType != "zktls" || verificationInfo == nil || verificationInfo.ProofType != "zktls" {
		t.Fatalf("unexpected verification info: proofType=%q out=%+v", svc.lastGetVerificationProofType, verificationInfo)
	}

	settlementPolicyInfo, err := client.GetSettlementPolicy(ctx, address, "UNO")
	if err != nil {
		t.Fatalf("GetSettlementPolicy error: %v", err)
	}
	if svc.lastGetSettlementPolicyAsset != "UNO" || settlementPolicyInfo == nil || settlementPolicyInfo.MaxAmount != "1000" {
		t.Fatalf("unexpected settlement policy info: asset=%q out=%+v", svc.lastGetSettlementPolicyAsset, settlementPolicyInfo)
	}

	agentIdentityInfo, err := client.GetAgentIdentity(ctx, address)
	if err != nil {
		t.Fatalf("GetAgentIdentity error: %v", err)
	}
	if svc.lastGetAgentIdentityAddress != address.Hex() || agentIdentityInfo == nil || !agentIdentityInfo.Registered {
		t.Fatalf("unexpected agent identity info: address=%q out=%+v", svc.lastGetAgentIdentityAddress, agentIdentityInfo)
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

}

func TestRPCExtAgentDiscoveryMethods(t *testing.T) {
	client, svc, cleanup := newRPCExtTestClient(t)
	defer cleanup()

	ctx := context.Background()
	info, err := client.AgentDiscoveryInfo(ctx)
	if err != nil {
		t.Fatalf("AgentDiscoveryInfo error: %v", err)
	}
	if !info.Enabled || !info.HasPublishedCard || info.CardSequence != 9 {
		t.Fatalf("unexpected discovery info: %+v", info)
	}

	publishInfo, err := client.AgentDiscoveryPublish(ctx, AgentDiscoveryPublishArgs{
		PrimaryIdentity: common.HexToAddress("0x1234"),
		Capabilities:    []string{"settlement.execute"},
		ConnectionModes: []string{"talkreq"},
		CardJSON:        `{"agent_id":"settlement-agent"}`,
		CardSequence:    11,
	})
	if err != nil {
		t.Fatalf("AgentDiscoveryPublish error: %v", err)
	}
	if svc.lastAgentDiscoveryPublishArgs.CardSequence != 11 || publishInfo.CardSequence != 11 {
		t.Fatalf("unexpected publish result: args=%+v out=%+v", svc.lastAgentDiscoveryPublishArgs, publishInfo)
	}

	suggested, err := client.AgentDiscoveryGetSuggestedCard(ctx, common.HexToAddress("0x9999"), big.NewInt(7))
	if err != nil {
		t.Fatalf("AgentDiscoveryGetSuggestedCard error: %v", err)
	}
	if svc.lastAgentDiscoverySuggestedCardArgs.Block != "0x7" {
		t.Fatalf("suggested card block arg = %q, want 0x7", svc.lastAgentDiscoverySuggestedCardArgs.Block)
	}
	if suggested.AgentID != "settlement-agent" || len(suggested.Capabilities) != 1 {
		t.Fatalf("unexpected suggested card: %+v", suggested)
	}

	suggestedInfo, err := client.AgentDiscoveryPublishSuggested(ctx, AgentDiscoveryPublishSuggestedArgs{
		Address:         common.HexToAddress("0x8888"),
		PrimaryIdentity: common.HexToAddress("0x1234"),
		ConnectionModes: []string{"talkreq", "https"},
		CardSequence:    12,
	}, big.NewInt(8))
	if err != nil {
		t.Fatalf("AgentDiscoveryPublishSuggested error: %v", err)
	}
	if svc.lastAgentDiscoveryPublishSuggestedArgs.Block != "0x8" {
		t.Fatalf("publish suggested block arg = %q, want 0x8", svc.lastAgentDiscoveryPublishSuggestedArgs.Block)
	}
	if !suggestedInfo.HasPublishedCard || suggestedInfo.CardSequence != 12 {
		t.Fatalf("unexpected publish suggested result: %+v", suggestedInfo)
	}

	results, err := client.AgentDiscoverySearch(ctx, "settlement.execute", nil)
	if err != nil {
		t.Fatalf("AgentDiscoverySearch error: %v", err)
	}
	if svc.lastAgentDiscoverySearchCapability != "settlement.execute" || len(results) != 1 {
		t.Fatalf("unexpected search result: capability=%q results=%+v", svc.lastAgentDiscoverySearchCapability, results)
	}

	card, err := client.AgentDiscoveryGetCard(ctx, "enr:-test")
	if err != nil {
		t.Fatalf("AgentDiscoveryGetCard error: %v", err)
	}
	if svc.lastAgentDiscoveryGetCardNodeRecord != "enr:-test" || card.ParsedCard == nil || card.ParsedCard.AgentID != "settlement-agent" {
		t.Fatalf("unexpected card response: node=%q resp=%+v", svc.lastAgentDiscoveryGetCardNodeRecord, card)
	}

	limit := 3
	dirResults, err := client.AgentDiscoveryDirectorySearch(ctx, "enr:-directory", "settlement.execute", &limit)
	if err != nil {
		t.Fatalf("AgentDiscoveryDirectorySearch error: %v", err)
	}
	if svc.lastAgentDiscoveryDirectoryNodeRecord != "enr:-directory" || svc.lastAgentDiscoveryDirectoryCapability != "settlement.execute" || len(dirResults) != 1 {
		t.Fatalf("unexpected directory search: node=%q capability=%q results=%+v", svc.lastAgentDiscoveryDirectoryNodeRecord, svc.lastAgentDiscoveryDirectoryCapability, dirResults)
	}

	cleared, err := client.AgentDiscoveryClear(ctx)
	if err != nil {
		t.Fatalf("AgentDiscoveryClear error: %v", err)
	}
	if cleared.HasPublishedCard {
		t.Fatalf("expected cleared discovery info, got %+v", cleared)
	}
}

func TestRPCExtWriteAndDPoSMethods(t *testing.T) {
	client, svc, cleanup := newRPCExtTestClient(t)
	defer cleanup()

	ctx := context.Background()
	from := common.HexToAddress("0xb422a2991bf0212aae4f7493ff06ad5d076fa274b49c297f3fe9e29b5ba9aadc")

	setSignerArgs := SetSignerArgs{
		From:        from,
		SignerType:  "ed25519",
		SignerValue: "z6Mkj...",
	}
	leaseDeployArgs := LeaseDeployArgs{
		From:        from,
		Code:        hexutil.Bytes{0x01, 0x02},
		LeaseBlocks: hexutil.Uint64(123),
		Value:       (*hexutil.Big)(big.NewInt(55)),
	}
	leaseRenewArgs := LeaseRenewArgs{
		From:         from,
		ContractAddr: common.HexToAddress("0x9999"),
		DeltaBlocks:  hexutil.Uint64(22),
	}
	leaseCloseArgs := LeaseCloseArgs{
		From:         from,
		ContractAddr: common.HexToAddress("0xaaaa"),
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
	if svc.lastBuildSignerArgs.From != from {
		t.Fatalf("buildSetSigner args were not forwarded")
	}

	deployRes, err := client.LeaseDeploy(ctx, leaseDeployArgs)
	if err != nil {
		t.Fatalf("LeaseDeploy error: %v", err)
	}
	if deployRes == nil {
		t.Fatal("expected leaseDeploy result")
	}
	if deployRes.TxHash != common.HexToHash("0x10") || deployRes.ContractAddress != common.HexToAddress("0x1010") || svc.lastLeaseDeployArgs.LeaseBlocks != leaseDeployArgs.LeaseBlocks {
		t.Fatalf("unexpected leaseDeploy result: %+v args=%+v", deployRes, svc.lastLeaseDeployArgs)
	}

	deployTx, err := client.BuildLeaseDeployTx(ctx, leaseDeployArgs)
	if err != nil {
		t.Fatalf("BuildLeaseDeployTx error: %v", err)
	}
	if deployTx == nil || len(deployTx.Raw) != 2 || deployTx.Raw[0] != 0x31 {
		t.Fatalf("unexpected buildLeaseDeployTx result: %+v", deployTx)
	}
	if deployTx.ContractAddress == nil || *deployTx.ContractAddress != common.HexToAddress("0x1010") {
		t.Fatalf("unexpected buildLeaseDeployTx contract address: %+v", deployTx)
	}

	renewHash, err := client.LeaseRenew(ctx, leaseRenewArgs)
	if err != nil {
		t.Fatalf("LeaseRenew error: %v", err)
	}
	if renewHash != common.HexToHash("0x11") || svc.lastLeaseRenewArgs.ContractAddr != leaseRenewArgs.ContractAddr {
		t.Fatalf("unexpected leaseRenew result: hash=%s args=%+v", renewHash.Hex(), svc.lastLeaseRenewArgs)
	}

	renewTx, err := client.BuildLeaseRenewTx(ctx, leaseRenewArgs)
	if err != nil {
		t.Fatalf("BuildLeaseRenewTx error: %v", err)
	}
	if renewTx == nil || len(renewTx.Raw) != 2 || renewTx.Raw[0] != 0x33 {
		t.Fatalf("unexpected buildLeaseRenewTx result: %+v", renewTx)
	}

	closeHash, err := client.LeaseClose(ctx, leaseCloseArgs)
	if err != nil {
		t.Fatalf("LeaseClose error: %v", err)
	}
	if closeHash != common.HexToHash("0x12") || svc.lastLeaseCloseArgs.ContractAddr != leaseCloseArgs.ContractAddr {
		t.Fatalf("unexpected leaseClose result: hash=%s args=%+v", closeHash.Hex(), svc.lastLeaseCloseArgs)
	}

	closeTx, err := client.BuildLeaseCloseTx(ctx, leaseCloseArgs)
	if err != nil {
		t.Fatalf("BuildLeaseCloseTx error: %v", err)
	}
	if closeTx == nil || len(closeTx.Raw) != 2 || closeTx.Raw[0] != 0x35 {
		t.Fatalf("unexpected buildLeaseCloseTx result: %+v", closeTx)
	}

	maintenanceArgs := ValidatorMaintenanceArgs{From: from}
	enterHash, err := client.EnterMaintenance(ctx, maintenanceArgs)
	if err != nil {
		t.Fatalf("EnterMaintenance error: %v", err)
	}
	if enterHash != common.HexToHash("0x2") || svc.lastMaintenanceMethod != "enter" {
		t.Fatalf("unexpected enterMaintenance result: hash=%s method=%s", enterHash.Hex(), svc.lastMaintenanceMethod)
	}

	enterTx, err := client.BuildEnterMaintenanceTx(ctx, maintenanceArgs)
	if err != nil {
		t.Fatalf("BuildEnterMaintenanceTx error: %v", err)
	}
	if enterTx == nil || len(enterTx.Raw) != 2 || enterTx.Raw[0] != 0xcc {
		t.Fatalf("unexpected buildEnterMaintenanceTx result: %+v", enterTx)
	}
	if svc.lastMaintenanceBuildArgs.From != from || svc.lastMaintenanceMethod != "build-enter" {
		t.Fatalf("buildEnterMaintenance args were not forwarded")
	}

	exitHash, err := client.ExitMaintenance(ctx, maintenanceArgs)
	if err != nil {
		t.Fatalf("ExitMaintenance error: %v", err)
	}
	if exitHash != common.HexToHash("0x3") || svc.lastMaintenanceMethod != "exit" {
		t.Fatalf("unexpected exitMaintenance result: hash=%s method=%s", exitHash.Hex(), svc.lastMaintenanceMethod)
	}

	exitTx, err := client.BuildExitMaintenanceTx(ctx, maintenanceArgs)
	if err != nil {
		t.Fatalf("BuildExitMaintenanceTx error: %v", err)
	}
	if exitTx == nil || len(exitTx.Raw) != 2 || exitTx.Raw[0] != 0xee {
		t.Fatalf("unexpected buildExitMaintenanceTx result: %+v", exitTx)
	}
	if svc.lastMaintenanceBuildArgs.From != from || svc.lastMaintenanceMethod != "build-exit" {
		t.Fatalf("buildExitMaintenance args were not forwarded")
	}

	evidence := types.MaliciousVoteEvidence{
		Version:      "GTOS_MALICIOUS_VOTE_EVIDENCE_V1",
		Kind:         "checkpoint_equivocation",
		ChainID:      big.NewInt(1666),
		Number:       64,
		Signer:       from,
		SignerType:   "ed25519",
		SignerPubKey: "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
	}
	submitArgs := SubmitMaliciousVoteEvidenceArgs{From: from, Evidence: evidence}
	evidenceHash, err := client.SubmitMaliciousVoteEvidence(ctx, submitArgs)
	if err != nil {
		t.Fatalf("SubmitMaliciousVoteEvidence error: %v", err)
	}
	if evidenceHash != common.HexToHash("0x4") || svc.lastEvidenceSubmitArgs.From != from {
		t.Fatalf("unexpected malicious vote submit result: hash=%s args=%+v", evidenceHash.Hex(), svc.lastEvidenceSubmitArgs)
	}

	evidenceTx, err := client.BuildSubmitMaliciousVoteEvidenceTx(ctx, submitArgs)
	if err != nil {
		t.Fatalf("BuildSubmitMaliciousVoteEvidenceTx error: %v", err)
	}
	if evidenceTx == nil || len(evidenceTx.Raw) != 2 || evidenceTx.Raw[0] != 0x11 {
		t.Fatalf("unexpected buildSubmitMaliciousVoteEvidenceTx result: %+v", evidenceTx)
	}
	if svc.lastEvidenceBuildArgs.From != from {
		t.Fatalf("buildSubmitMaliciousVoteEvidence args were not forwarded")
	}

	rec, err := client.GetMaliciousVoteEvidence(ctx, common.HexToHash("0xa1"), big.NewInt(12))
	if err != nil {
		t.Fatalf("GetMaliciousVoteEvidence error: %v", err)
	}
	if svc.lastGetCodeBlock != "0xc" || rec == nil || rec.Number != 64 || rec.Status != "submitted" || rec.OffenseKey != common.HexToHash("0xf1") {
		t.Fatalf("unexpected GetMaliciousVoteEvidence response: block=%q rec=%+v", svc.lastGetCodeBlock, rec)
	}

	list, err := client.ListMaliciousVoteEvidence(ctx, 5, nil)
	if err != nil {
		t.Fatalf("ListMaliciousVoteEvidence error: %v", err)
	}
	if svc.lastGetCodeBlock != "latest" || len(list) != 1 || list[0].Number != 5 {
		t.Fatalf("unexpected ListMaliciousVoteEvidence response: block=%q list=%+v", svc.lastGetCodeBlock, list)
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
	if epoch.TargetBlockPeriodMs != 1000 || epoch.ValidatorCount != 7 || epoch.TurnLength != 16 || epoch.RecentSignerWindow != 31 {
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
		From:        common.HexToAddress("0x6ab1757c2549dcaafef121277564105e977516c53be337314c7e53838967bdac"),
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
