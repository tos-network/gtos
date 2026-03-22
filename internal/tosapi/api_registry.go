package tosapi

import (
	"context"
	"strings"

	"github.com/tos-network/gtos/agent"
	"github.com/tos-network/gtos/agentdiscovery"
	"github.com/tos-network/gtos/capability"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/paypolicy"
	"github.com/tos-network/gtos/pkgregistry"
	"github.com/tos-network/gtos/registry"
	"github.com/tos-network/gtos/rpc"
	"github.com/tos-network/gtos/verifyregistry"
)

// ---------------------------------------------------------------------------
// Protocol Registry RPC types
//
// v1 registry query surfaces for the protocol registry RPCs defined in
// docs/GTOS_PROTOCOL_REGISTRIES.md.
// ---------------------------------------------------------------------------

// CapabilityInfo describes a single capability record from the protocol
// Capability Registry.
type CapabilityInfo struct {
	Name        string `json:"name"`
	BitIndex    uint64 `json:"bit_index"`
	Category    uint64 `json:"category"`
	Version     uint64 `json:"version"`
	Status      string `json:"status"` // "active", "deprecated", "revoked"
	ManifestRef string `json:"manifest_ref,omitempty"`
}

// DelegationInfo describes a single delegation record from the protocol
// Delegation Registry.
type DelegationInfo struct {
	Principal     string `json:"principal"`
	Delegate      string `json:"delegate"`
	ScopeRef      string `json:"scope_ref"`
	CapabilityRef string `json:"capability_ref"`
	PolicyRef     string `json:"policy_ref"`
	NotBeforeMS   uint64 `json:"not_before_ms"`
	ExpiryMS      uint64 `json:"expiry_ms"`
	Status        string `json:"status"`
}

// PackageInfo describes a single package record from the protocol
// Package Registry.
type PackageInfo struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	PackageHash   string `json:"package_hash"`
	ManifestHash  string `json:"manifest_hash,omitempty"`
	PublisherID   string `json:"publisher_id"`
	Channel       string `json:"channel"`
	Status        string `json:"status"`
	ContractCount uint64 `json:"contract_count"`
	DiscoveryRef  string `json:"discovery_ref,omitempty"`
	PublishedAt   uint64 `json:"published_at"`
}

// PublisherInfo describes a single publisher record from the protocol
// Publisher Registry.
type PublisherInfo struct {
	PublisherID string `json:"publisher_id"`
	Controller  string `json:"controller"`
	MetadataRef string `json:"metadata_ref"`
	Status      string `json:"status"`
}

type VerifierInfo struct {
	Name         string `json:"name"`
	VerifierType uint64 `json:"verifier_type"`
	VerifierAddr string `json:"verifier_addr"`
	PolicyRef    string `json:"policy_ref,omitempty"`
	Version      uint64 `json:"version"`
	Status       string `json:"status"`
}

type VerificationClaimInfo struct {
	Subject    string `json:"subject"`
	ProofType  string `json:"proof_type"`
	VerifiedAt uint64 `json:"verified_at"`
	ExpiryMS   uint64 `json:"expiry_ms"`
	Status     string `json:"status"`
}

type SettlementPolicyInfo struct {
	PolicyID  string `json:"policy_id"`
	Kind      uint64 `json:"kind"`
	Owner     string `json:"owner"`
	Asset     string `json:"asset"`
	MaxAmount string `json:"max_amount"`
	RulesRef  string `json:"rules_ref,omitempty"`
	Status    string `json:"status"`
}

type AgentIdentityInfo struct {
	AgentAddress    string `json:"agent_address"`
	Registered      bool   `json:"registered"`
	Suspended       bool   `json:"suspended"`
	Status          uint64 `json:"status"`
	Stake           string `json:"stake"`
	MetadataURI     string `json:"metadata_uri,omitempty"`
	BindingHash     string `json:"binding_hash,omitempty"`
	BindingActive   bool   `json:"binding_active"`
	BindingVerified bool   `json:"binding_verified"`
	BindingExpiry   uint64 `json:"binding_expiry"`
}

// ---------------------------------------------------------------------------
// RPC methods — v1
//
// These methods read from StateDB via the protocol registry state packages.
// They return nil to indicate "no record found" so callers can safely probe
// the registry surface.
// ---------------------------------------------------------------------------

// TolGetCapability returns the capability record for the given canonical
// name, or nil if no record exists.
func (s *TOSAPI) TolGetCapability(ctx context.Context, name string) (*CapabilityInfo, error) {
	st, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil || st == nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, nil
	}
	rec := registry.ReadCapability(st, name)
	if rec.Name == "" {
		if bit, ok := capability.CapabilityBit(st, name); ok {
			return &CapabilityInfo{
				Name:     name,
				BitIndex: uint64(bit),
				Status:   "active",
			}, nil
		}
		return nil, nil
	}
	info := &CapabilityInfo{
		Name:        rec.Name,
		BitIndex:    uint64(rec.BitIndex),
		Category:    uint64(rec.Category),
		Version:     uint64(rec.Version),
		Status:      capabilityStatusString(rec.Status),
		ManifestRef: common.Hash(rec.ManifestRef).Hex(),
	}
	return info, nil
}

// TolGetDelegation returns the delegation record for the given
// (principal, delegate, scopeRef) triple, or nil if no record exists.
func (s *TOSAPI) TolGetDelegation(ctx context.Context, principalHex, delegateHex, scopeHex string) (*DelegationInfo, error) {
	st, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil || st == nil {
		return nil, err
	}
	principal := common.HexToAddress(principalHex)
	delegate := common.HexToAddress(delegateHex)
	scopeHash := common.HexToHash(scopeHex)
	if !registry.DelegationExists(st, principal, delegate, scopeHash) {
		return nil, nil
	}
	rec := registry.ReadDelegation(st, principal, delegate, scopeHash)
	return &DelegationInfo{
		Principal:     rec.Principal.Hex(),
		Delegate:      rec.Delegate.Hex(),
		ScopeRef:      common.Hash(rec.ScopeRef).Hex(),
		CapabilityRef: common.Hash(rec.CapabilityRef).Hex(),
		PolicyRef:     common.Hash(rec.PolicyRef).Hex(),
		NotBeforeMS:   rec.NotBeforeMS,
		ExpiryMS:      rec.ExpiryMS,
		Status:        delegationStatusString(rec.Status),
	}, nil
}

// TolGetPackage returns the package record for the given name and version,
// or nil if no record exists.
func (s *TOSAPI) TolGetPackage(ctx context.Context, name, version string) (*PackageInfo, error) {
	st, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil || st == nil {
		return nil, err
	}
	rec := pkgregistry.ReadPackage(st, strings.TrimSpace(name), strings.TrimSpace(version))
	if rec.PackageHash == ([32]byte{}) {
		return nil, nil
	}
	return packageInfoFromRecord(rec), nil
}

// TolGetPackageByHash returns the package record for the given package hash.
func (s *TOSAPI) TolGetPackageByHash(ctx context.Context, packageHash string) (*PackageInfo, error) {
	st, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil || st == nil {
		return nil, err
	}
	hash := common.HexToHash(packageHash)
	rec := pkgregistry.ReadPackageByHash(st, hash)
	if rec.PackageHash == ([32]byte{}) {
		return nil, nil
	}
	return packageInfoFromRecord(rec), nil
}

// TolGetLatestPackage returns the latest active package currently indexed for
// the given package name and channel. Supported channels are "dev", "beta",
// "stable", and "deprecated". Empty channel defaults to "stable".
func (s *TOSAPI) TolGetLatestPackage(ctx context.Context, name, channel string) (*PackageInfo, error) {
	st, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil || st == nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, nil
	}
	ch, ok := parsePackageChannel(channel)
	if !ok {
		return nil, nil
	}
	rec := pkgregistry.ReadLatestPackage(st, name, ch)
	if rec.PackageHash == ([32]byte{}) {
		return nil, nil
	}
	return packageInfoFromRecord(rec), nil
}

// TolGetPublisher returns the publisher record for the given publisher ID,
// or nil if no record exists.
func (s *TOSAPI) TolGetPublisher(ctx context.Context, publisherID string) (*PublisherInfo, error) {
	st, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil || st == nil {
		return nil, err
	}
	pubHash := common.HexToHash(strings.TrimSpace(publisherID))
	var pubID [32]byte
	copy(pubID[:], pubHash[:])
	rec := pkgregistry.ReadPublisher(st, pubID)
	if rec.Controller == (common.Address{}) {
		return nil, nil
	}
	return publisherInfoFromRecord(rec), nil
}

func (s *TOSAPI) TolGetVerifier(ctx context.Context, name string) (*VerifierInfo, error) {
	st, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil || st == nil {
		return nil, err
	}
	rec := verifyregistry.ReadVerifier(st, strings.TrimSpace(name))
	if rec.Name == "" {
		return nil, nil
	}
	return &VerifierInfo{
		Name:         rec.Name,
		VerifierType: uint64(rec.VerifierType),
		VerifierAddr: rec.VerifierAddr.Hex(),
		PolicyRef:    common.Hash(rec.PolicyRef).Hex(),
		Version:      uint64(rec.Version),
		Status:       verifierStatusString(rec.Status),
	}, nil
}

func (s *TOSAPI) TolGetVerification(ctx context.Context, subjectHex, proofType string) (*VerificationClaimInfo, error) {
	st, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil || st == nil {
		return nil, err
	}
	subject := common.HexToAddress(subjectHex)
	rec := verifyregistry.ReadSubjectVerification(st, subject, strings.TrimSpace(proofType))
	if rec.Subject == (common.Address{}) {
		return nil, nil
	}
	return &VerificationClaimInfo{
		Subject:    rec.Subject.Hex(),
		ProofType:  rec.ProofType,
		VerifiedAt: rec.VerifiedAt,
		ExpiryMS:   rec.ExpiryMS,
		Status:     verificationStatusString(rec.Status),
	}, nil
}

func (s *TOSAPI) TolGetSettlementPolicy(ctx context.Context, ownerHex, asset string) (*SettlementPolicyInfo, error) {
	st, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil || st == nil {
		return nil, err
	}
	rec := paypolicy.ReadPolicyByOwnerAsset(st, common.HexToAddress(ownerHex), strings.ToUpper(strings.TrimSpace(asset)))
	if rec.PolicyID == ([32]byte{}) {
		return nil, nil
	}
	maxAmount := "0"
	if rec.MaxAmount != nil {
		maxAmount = rec.MaxAmount.String()
	}
	return &SettlementPolicyInfo{
		PolicyID:  common.Hash(rec.PolicyID).Hex(),
		Kind:      uint64(rec.Kind),
		Owner:     rec.Owner.Hex(),
		Asset:     rec.Asset,
		MaxAmount: maxAmount,
		RulesRef:  common.Hash(rec.RulesRef).Hex(),
		Status:    payPolicyStatusString(rec.Status),
	}, nil
}

func (s *TOSAPI) TolGetAgentIdentity(ctx context.Context, agentHex string) (*AgentIdentityInfo, error) {
	st, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil || st == nil {
		return nil, err
	}
	addr := common.HexToAddress(agentHex)
	if !agent.IsRegistered(st, addr) {
		return nil, nil
	}
	info := &AgentIdentityInfo{
		AgentAddress: addr.Hex(),
		Registered:   true,
		Suspended:    agent.IsSuspended(st, addr),
		Status:       uint64(agent.ReadStatus(st, addr)),
		Stake:        agent.ReadStake(st, addr).String(),
		MetadataURI:  agent.MetadataOf(st, addr),
	}
	if binding := agentdiscovery.ReadIdentityBinding(st, addr); binding != nil {
		info.BindingHash = binding.BindingHash.Hex()
		info.BindingActive = binding.Active
		info.BindingVerified = binding.OnChainVerified
		info.BindingExpiry = binding.ExpiresAt
	}
	return info, nil
}

func capabilityStatusString(status registry.CapabilityStatus) string {
	switch status {
	case registry.CapDeprecated:
		return "deprecated"
	case registry.CapRevoked:
		return "revoked"
	default:
		return "active"
	}
}

func delegationStatusString(status registry.DelegationStatus) string {
	switch status {
	case registry.DelRevoked:
		return "revoked"
	case registry.DelExpired:
		return "expired"
	default:
		return "active"
	}
}

func packageStatusString(status pkgregistry.PackageStatus) string {
	switch status {
	case pkgregistry.PkgDeprecated:
		return "deprecated"
	case pkgregistry.PkgRevoked:
		return "revoked"
	default:
		return "active"
	}
}

func verifierStatusString(status verifyregistry.VerifierStatus) string {
	switch status {
	case verifyregistry.VerifierRevoked:
		return "revoked"
	default:
		return "active"
	}
}

func verificationStatusString(status verifyregistry.VerificationStatus) string {
	switch status {
	case verifyregistry.VerificationRevoked:
		return "revoked"
	default:
		return "active"
	}
}

func payPolicyStatusString(status paypolicy.PolicyStatus) string {
	switch status {
	case paypolicy.PolicyRevoked:
		return "revoked"
	default:
		return "active"
	}
}

func packageChannelString(channel pkgregistry.ChannelKind) string {
	switch channel {
	case pkgregistry.ChannelBeta:
		return "beta"
	case pkgregistry.ChannelStable:
		return "stable"
	case pkgregistry.ChannelDeprecated:
		return "deprecated"
	default:
		return "dev"
	}
}

func parsePackageChannel(channel string) (pkgregistry.ChannelKind, bool) {
	switch strings.ToLower(strings.TrimSpace(channel)) {
	case "", "stable":
		return pkgregistry.ChannelStable, true
	case "dev":
		return pkgregistry.ChannelDev, true
	case "beta":
		return pkgregistry.ChannelBeta, true
	case "deprecated":
		return pkgregistry.ChannelDeprecated, true
	default:
		return 0, false
	}
}

func packageInfoFromRecord(rec pkgregistry.PackageRecord) *PackageInfo {
	return &PackageInfo{
		Name:          rec.PackageName,
		Version:       rec.PackageVersion,
		PackageHash:   common.Hash(rec.PackageHash).Hex(),
		ManifestHash:  common.Hash(rec.ManifestHash).Hex(),
		PublisherID:   common.Hash(rec.PublisherID).Hex(),
		Channel:       packageChannelString(rec.Channel),
		Status:        packageStatusString(rec.Status),
		ContractCount: uint64(rec.ContractCount),
		DiscoveryRef:  common.Hash(rec.DiscoveryRef).Hex(),
		PublishedAt:   rec.PublishedAt,
	}
}

func publisherInfoFromRecord(rec pkgregistry.PublisherRecord) *PublisherInfo {
	return &PublisherInfo{
		PublisherID: common.Hash(rec.PublisherID).Hex(),
		Controller:  rec.Controller.Hex(),
		MetadataRef: common.Hash(rec.MetadataRef).Hex(),
		Status:      packageStatusString(rec.Status),
	}
}
