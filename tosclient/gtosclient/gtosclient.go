// Package gethclient provides an RPC client for gtos-specific APIs.
package gtosclient

import (
	"context"
	"math/big"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/tos-network/gtos"
	"github.com/tos-network/gtos/agentdiscovery"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/p2p"
	"github.com/tos-network/gtos/rpc"
	"github.com/tos-network/gtos/tosclient"
	tolmeta "github.com/tos-network/tolang/metadata"
)

// Client is a wrapper around rpc.Client that implements gtos-specific functionality.
//
// If you want to use the standardized TOS RPC functionality, use tosclient.Client instead.
type Client struct {
	c *rpc.Client
}

// AgentRuntimeSurface is the normalized client-side view of deployed agent code.
// It flattens the most commonly consumed pieces of deployed metadata so agent
// runtimes do not need to branch separately on `.toc` vs `.tor` inspection.
type AgentRuntimeSurface struct {
	Address        common.Address
	CodeKind       string
	ContractName   string
	PackageName    string
	PackageVersion string
	Profile        *tolmeta.AgentContractProfile
	BundleProfile  *tolmeta.AgentBundleProfile
	Routing        *agentdiscovery.TypedRoutingProfile
	SuggestedCard  *agentdiscovery.PublishedCard
	Published      *tosclient.PackageInfo
	Publisher      *tosclient.PublisherInfo
	Artifact       *tosclient.TOLArtifactInfo
	Package        *tosclient.TOLPackageInfo
}

// SettlementRuntimeSurface is the normalized client-side view of one runtime
// settlement receipt/effect pair, optionally joined with deployed metadata for
// the sender and recipient when those endpoints are contracts/packages.
type SettlementRuntimeSurface struct {
	Receipt          *tosclient.RuntimeReceiptInfo
	Effect           *tosclient.SettlementEffectInfo
	SenderRuntime    *AgentRuntimeSurface
	RecipientRuntime *AgentRuntimeSurface
}

// DiscoveredAgentSurface joins a published discovery card with the normalized
// deployed runtime metadata for the advertised agent address when available.
type DiscoveredAgentSurface struct {
	NodeRecord string
	Card       *agentdiscovery.CardResponse
	Runtime    *AgentRuntimeSurface
}

// SearchResultSurface joins one discovery search result with the published card
// and normalized runtime metadata for that result when available.
type SearchResultSurface struct {
	Result  agentdiscovery.SearchResult
	Surface *DiscoveredAgentSurface
}

// TrustedSearchResultSurface is a filtered/ranked search result that satisfied
// the basic trust gate and carries the rank score used for ordering.
type TrustedSearchResultSurface struct {
	SearchResultSurface
	TrustScore int64
}

// ProviderSelectionDiagnostics explains how one discovery/runtime surface moved
// through trust gating and higher-level preference filtering.
type ProviderSelectionDiagnostics struct {
	SearchResultSurface
	TrustScore         int64
	Trusted            bool
	Preferred          bool
	TrustFailures      []string
	PreferenceFailures []string
}

// ProviderSelectionPreferences describes higher-level client-side filtering
// preferences on top of trusted/ranked provider surfaces.
type ProviderSelectionPreferences struct {
	RequiredConnectionModes uint8
	PackagePrefix           string
	ServiceKind             string
	CapabilityKind          string
	PrivacyMode             string
	ReceiptMode             string
	RequireDisclosureReady  bool
	MinTrustScore           int64
}

// New creates a client that uses the given RPC client.
func New(c *rpc.Client) *Client {
	return &Client{c}
}

// GetAgentRuntimeSurface returns a normalized metadata surface for deployed
// raw, `.toc`, or `.tor` code. It is a higher-level helper built on top of
// the typed tosclient metadata wrapper.
func (ec *Client) GetAgentRuntimeSurface(ctx context.Context, address common.Address, blockNumber *big.Int) (*AgentRuntimeSurface, error) {
	metaClient := tosclient.NewClient(ec.c)
	info, err := metaClient.GetContractMetadata(ctx, address, blockNumber)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, nil
	}
	out := &AgentRuntimeSurface{
		Address:  info.Address,
		CodeKind: info.CodeKind,
		Artifact: info.Artifact,
		Package:  info.Package,
	}
	if info.Artifact != nil {
		out.ContractName = info.Artifact.ContractName
		if info.Artifact.Profile != nil {
			out.Profile = info.Artifact.Profile
			out.PackageName = info.Artifact.Profile.Identity.PackageName
			out.PackageVersion = info.Artifact.Profile.Identity.PackageVersion
		}
		out.Routing = info.Artifact.Routing
		out.SuggestedCard = info.Artifact.SuggestedCard
	}
	if info.Package != nil {
		if out.PackageName == "" {
			if info.Package.Package != "" {
				out.PackageName = info.Package.Package
			} else {
				out.PackageName = info.Package.Name
			}
		}
		if out.PackageVersion == "" {
			out.PackageVersion = info.Package.Version
		}
		if out.ContractName == "" {
			out.ContractName = info.Package.MainContract
		}
		out.BundleProfile = info.Package.Profile
		out.Published = info.Package.Published
		out.Publisher = info.Package.Publisher
		if out.SuggestedCard == nil {
			out.SuggestedCard = info.Package.SuggestedCard
		}
	}
	return out, nil
}

// GetDiscoveredAgentSurface fetches a published discovery card by node record
// and, when the structured card advertises a canonical agent address, joins it
// with the deployed runtime surface for that address.
func (ec *Client) GetDiscoveredAgentSurface(ctx context.Context, nodeRecord string, blockNumber *big.Int) (*DiscoveredAgentSurface, error) {
	metaClient := tosclient.NewClient(ec.c)
	card, err := metaClient.AgentDiscoveryGetCard(ctx, nodeRecord)
	if err != nil {
		return nil, err
	}
	out := &DiscoveredAgentSurface{
		NodeRecord: nodeRecord,
		Card:       card,
	}
	if card == nil || card.ParsedCard == nil {
		return out, nil
	}
	rawAddr := strings.TrimSpace(card.ParsedCard.AgentAddress)
	if rawAddr == "" || !common.IsHexAddress(rawAddr) {
		return out, nil
	}
	runtimeSurface, err := ec.GetAgentRuntimeSurface(ctx, common.HexToAddress(rawAddr), blockNumber)
	if err != nil {
		return nil, err
	}
	out.Runtime = runtimeSurface
	return out, nil
}

// GetRuntimeReceiptSurface returns one runtime settlement receipt plus its
// settlement effect and any deployed metadata surfaces reachable from sender
// and recipient addresses.
func (ec *Client) GetRuntimeReceiptSurface(ctx context.Context, receiptRef common.Hash, blockNumber *big.Int) (*SettlementRuntimeSurface, error) {
	metaClient := tosclient.NewClient(ec.c)
	receipt, err := metaClient.GetRuntimeReceipt(ctx, receiptRef)
	if err != nil {
		return nil, err
	}
	out := &SettlementRuntimeSurface{Receipt: receipt}
	if receipt == nil {
		return out, nil
	}
	if strings.TrimSpace(receipt.SettlementRef) != "" {
		effect, err := metaClient.GetSettlementEffect(ctx, common.HexToHash(receipt.SettlementRef))
		if err != nil {
			return nil, err
		}
		out.Effect = effect
	}
	if common.IsHexAddress(strings.TrimSpace(receipt.Sender)) {
		senderRuntime, err := ec.GetAgentRuntimeSurface(ctx, common.HexToAddress(receipt.Sender), blockNumber)
		if err != nil {
			return nil, err
		}
		out.SenderRuntime = senderRuntime
	}
	if common.IsHexAddress(strings.TrimSpace(receipt.Recipient)) {
		recipientRuntime, err := ec.GetAgentRuntimeSurface(ctx, common.HexToAddress(receipt.Recipient), blockNumber)
		if err != nil {
			return nil, err
		}
		out.RecipientRuntime = recipientRuntime
	}
	return out, nil
}

// GetSettlementEffectSurface returns one runtime settlement effect plus the
// linked receipt and any deployed metadata surfaces reachable from sender and
// recipient addresses.
func (ec *Client) GetSettlementEffectSurface(ctx context.Context, settlementRef common.Hash, blockNumber *big.Int) (*SettlementRuntimeSurface, error) {
	metaClient := tosclient.NewClient(ec.c)
	effect, err := metaClient.GetSettlementEffect(ctx, settlementRef)
	if err != nil {
		return nil, err
	}
	out := &SettlementRuntimeSurface{Effect: effect}
	if effect == nil {
		return out, nil
	}
	if strings.TrimSpace(effect.ReceiptRef) != "" {
		receipt, err := metaClient.GetRuntimeReceipt(ctx, common.HexToHash(effect.ReceiptRef))
		if err != nil {
			return nil, err
		}
		out.Receipt = receipt
	}
	if common.IsHexAddress(strings.TrimSpace(effect.Sender)) {
		senderRuntime, err := ec.GetAgentRuntimeSurface(ctx, common.HexToAddress(effect.Sender), blockNumber)
		if err != nil {
			return nil, err
		}
		out.SenderRuntime = senderRuntime
	}
	if common.IsHexAddress(strings.TrimSpace(effect.Recipient)) {
		recipientRuntime, err := ec.GetAgentRuntimeSurface(ctx, common.HexToAddress(effect.Recipient), blockNumber)
		if err != nil {
			return nil, err
		}
		out.RecipientRuntime = recipientRuntime
	}
	return out, nil
}

// SearchDiscoveredAgentSurfaces runs discovery search for a capability and
// joins each search result with its published card and runtime metadata.
func (ec *Client) SearchDiscoveredAgentSurfaces(ctx context.Context, capability string, limit *int, blockNumber *big.Int) ([]SearchResultSurface, error) {
	metaClient := tosclient.NewClient(ec.c)
	results, err := metaClient.AgentDiscoverySearch(ctx, capability, limit)
	if err != nil {
		return nil, err
	}
	return ec.joinSearchResults(ctx, results, blockNumber)
}

// DirectorySearchDiscoveredAgentSurfaces runs directory search for a capability
// and joins each search result with its published card and runtime metadata.
func (ec *Client) DirectorySearchDiscoveredAgentSurfaces(ctx context.Context, nodeRecord string, capability string, limit *int, blockNumber *big.Int) ([]SearchResultSurface, error) {
	metaClient := tosclient.NewClient(ec.c)
	results, err := metaClient.AgentDiscoveryDirectorySearch(ctx, nodeRecord, capability, limit)
	if err != nil {
		return nil, err
	}
	return ec.joinSearchResults(ctx, results, blockNumber)
}

func (ec *Client) joinSearchResults(ctx context.Context, results []agentdiscovery.SearchResult, blockNumber *big.Int) ([]SearchResultSurface, error) {
	out := make([]SearchResultSurface, 0, len(results))
	for _, result := range results {
		entry := SearchResultSurface{Result: result}
		if strings.TrimSpace(result.NodeRecord) != "" {
			surface, err := ec.GetDiscoveredAgentSurface(ctx, result.NodeRecord, blockNumber)
			if err != nil {
				return nil, err
			}
			entry.Surface = surface
		}
		out = append(out, entry)
	}
	return out, nil
}

// SearchTrustedAgentSurfaces searches providers for a capability, joins them
// with discovery/runtime metadata, filters out entries that fail the trust
// gate, and sorts the remaining surfaces by descending local rank score.
func (ec *Client) SearchTrustedAgentSurfaces(ctx context.Context, capability string, limit *int, blockNumber *big.Int) ([]TrustedSearchResultSurface, error) {
	joined, err := ec.SearchDiscoveredAgentSurfaces(ctx, capability, limit, blockNumber)
	if err != nil {
		return nil, err
	}
	return RankTrustedAgentSurfaces(joined), nil
}

// DirectorySearchTrustedAgentSurfaces performs the same trust gate and ranking
// on top of directory search results.
func (ec *Client) DirectorySearchTrustedAgentSurfaces(ctx context.Context, nodeRecord string, capability string, limit *int, blockNumber *big.Int) ([]TrustedSearchResultSurface, error) {
	joined, err := ec.DirectorySearchDiscoveredAgentSurfaces(ctx, nodeRecord, capability, limit, blockNumber)
	if err != nil {
		return nil, err
	}
	return RankTrustedAgentSurfaces(joined), nil
}

// RankTrustedAgentSurfaces filters search results to the trust-minimum set and
// sorts them by descending local rank score, using node record as a stable
// tiebreaker.
func RankTrustedAgentSurfaces(entries []SearchResultSurface) []TrustedSearchResultSurface {
	out := make([]TrustedSearchResultSurface, 0, len(entries))
	for _, entry := range entries {
		if !isTrustedSearchSurface(entry) {
			continue
		}
		score := int64(0)
		if entry.Result.Trust != nil {
			score = entry.Result.Trust.LocalRankScore
		}
		out = append(out, TrustedSearchResultSurface{
			SearchResultSurface: entry,
			TrustScore:          score,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].TrustScore != out[j].TrustScore {
			return out[i].TrustScore > out[j].TrustScore
		}
		return out[i].Result.NodeRecord < out[j].Result.NodeRecord
	})
	return out
}

// FilterPreferredAgentSurfaces applies higher-level client-side preferences on
// top of trusted/ranked provider surfaces while preserving their existing
// ordering.
func FilterPreferredAgentSurfaces(entries []TrustedSearchResultSurface, prefs ProviderSelectionPreferences) []TrustedSearchResultSurface {
	out := make([]TrustedSearchResultSurface, 0, len(entries))
	for _, entry := range entries {
		if !matchesProviderPreferences(entry, prefs) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// SearchPreferredAgentSurfaces searches, joins, trust-filters, ranks, then
// applies higher-level provider selection preferences.
func (ec *Client) SearchPreferredAgentSurfaces(ctx context.Context, capability string, limit *int, blockNumber *big.Int, prefs ProviderSelectionPreferences) ([]TrustedSearchResultSurface, error) {
	trusted, err := ec.SearchTrustedAgentSurfaces(ctx, capability, limit, blockNumber)
	if err != nil {
		return nil, err
	}
	return FilterPreferredAgentSurfaces(trusted, prefs), nil
}

// DirectorySearchPreferredAgentSurfaces performs the same preference filtering
// on top of directory search results.
func (ec *Client) DirectorySearchPreferredAgentSurfaces(ctx context.Context, nodeRecord string, capability string, limit *int, blockNumber *big.Int, prefs ProviderSelectionPreferences) ([]TrustedSearchResultSurface, error) {
	trusted, err := ec.DirectorySearchTrustedAgentSurfaces(ctx, nodeRecord, capability, limit, blockNumber)
	if err != nil {
		return nil, err
	}
	return FilterPreferredAgentSurfaces(trusted, prefs), nil
}

// SelectPreferredAgentSurface returns the first provider that matches the
// supplied preferences from an already-ranked trusted surface list.
func SelectPreferredAgentSurface(entries []TrustedSearchResultSurface, prefs ProviderSelectionPreferences) *TrustedSearchResultSurface {
	filtered := FilterPreferredAgentSurfaces(entries, prefs)
	if len(filtered) == 0 {
		return nil
	}
	return &filtered[0]
}

// ResolvePreferredAgentSurface performs discovery search, joins runtime
// metadata, applies trust/ranking, applies the supplied preferences, and
// returns the best remaining provider when one exists.
func (ec *Client) ResolvePreferredAgentSurface(ctx context.Context, capability string, limit *int, blockNumber *big.Int, prefs ProviderSelectionPreferences) (*TrustedSearchResultSurface, error) {
	preferred, err := ec.SearchPreferredAgentSurfaces(ctx, capability, limit, blockNumber, prefs)
	if err != nil {
		return nil, err
	}
	return SelectPreferredAgentSurface(preferred, ProviderSelectionPreferences{}), nil
}

// ResolveDirectoryPreferredAgentSurface performs the same end-to-end provider
// resolution on top of directory search.
func (ec *Client) ResolveDirectoryPreferredAgentSurface(ctx context.Context, nodeRecord string, capability string, limit *int, blockNumber *big.Int, prefs ProviderSelectionPreferences) (*TrustedSearchResultSurface, error) {
	preferred, err := ec.DirectorySearchPreferredAgentSurfaces(ctx, nodeRecord, capability, limit, blockNumber, prefs)
	if err != nil {
		return nil, err
	}
	return SelectPreferredAgentSurface(preferred, ProviderSelectionPreferences{}), nil
}

// SearchPreferredAgentSurfaceDiagnostics runs search and returns per-provider
// diagnostic records describing trust and preference failures.
func (ec *Client) SearchPreferredAgentSurfaceDiagnostics(ctx context.Context, capability string, limit *int, blockNumber *big.Int, prefs ProviderSelectionPreferences) ([]ProviderSelectionDiagnostics, error) {
	joined, err := ec.SearchDiscoveredAgentSurfaces(ctx, capability, limit, blockNumber)
	if err != nil {
		return nil, err
	}
	return DiagnosePreferredAgentSurfaces(joined, prefs), nil
}

// DirectorySearchPreferredAgentSurfaceDiagnostics runs directory search and
// returns per-provider diagnostic records describing trust and preference
// failures.
func (ec *Client) DirectorySearchPreferredAgentSurfaceDiagnostics(ctx context.Context, nodeRecord string, capability string, limit *int, blockNumber *big.Int, prefs ProviderSelectionPreferences) ([]ProviderSelectionDiagnostics, error) {
	joined, err := ec.DirectorySearchDiscoveredAgentSurfaces(ctx, nodeRecord, capability, limit, blockNumber)
	if err != nil {
		return nil, err
	}
	return DiagnosePreferredAgentSurfaces(joined, prefs), nil
}

// DiagnosePreferredAgentSurfaces annotates joined provider surfaces with the
// reasons they failed trust gating or higher-level preference filters.
func DiagnosePreferredAgentSurfaces(entries []SearchResultSurface, prefs ProviderSelectionPreferences) []ProviderSelectionDiagnostics {
	out := make([]ProviderSelectionDiagnostics, 0, len(entries))
	for _, entry := range entries {
		diag := ProviderSelectionDiagnostics{
			SearchResultSurface: entry,
		}
		if entry.Result.Trust != nil {
			diag.TrustScore = entry.Result.Trust.LocalRankScore
		} else {
			diag.TrustFailures = append(diag.TrustFailures, "missing trust summary")
		}
		trust := entry.Result.Trust
		if trust != nil {
			if !trust.Registered {
				diag.TrustFailures = append(diag.TrustFailures, "provider not registered")
			}
			if trust.Suspended {
				diag.TrustFailures = append(diag.TrustFailures, "provider suspended")
			}
			if !trust.HasOnchainCapability {
				diag.TrustFailures = append(diag.TrustFailures, "capability missing on-chain")
			}
		}
		if entry.Surface != nil && entry.Surface.Runtime != nil && entry.Surface.Runtime.Published != nil && !entry.Surface.Runtime.Published.Trusted {
			diag.TrustFailures = append(diag.TrustFailures, "package is untrusted")
		}
		diag.Trusted = len(diag.TrustFailures) == 0
		diag.PreferenceFailures = preferenceFailures(entry, diag.TrustScore, prefs)
		diag.Preferred = diag.Trusted && len(diag.PreferenceFailures) == 0
		out = append(out, diag)
	}
	return out
}

func isTrustedSearchSurface(entry SearchResultSurface) bool {
	trust := entry.Result.Trust
	if trust == nil {
		return false
	}
	if !trust.Registered || trust.Suspended || !trust.HasOnchainCapability {
		return false
	}
	if entry.Surface != nil && entry.Surface.Runtime != nil && entry.Surface.Runtime.Published != nil && !entry.Surface.Runtime.Published.Trusted {
		return false
	}
	return true
}

func matchesProviderPreferences(entry TrustedSearchResultSurface, prefs ProviderSelectionPreferences) bool {
	return len(preferenceFailures(entry.SearchResultSurface, entry.TrustScore, prefs)) == 0
}

func preferenceFailures(entry SearchResultSurface, trustScore int64, prefs ProviderSelectionPreferences) []string {
	var failures []string
	if prefs.MinTrustScore > 0 && trustScore < prefs.MinTrustScore {
		failures = append(failures, "trust score below minimum")
	}
	if prefs.RequiredConnectionModes != 0 && (entry.Result.ConnectionModes&prefs.RequiredConnectionModes) != prefs.RequiredConnectionModes {
		failures = append(failures, "required connection modes missing")
	}
	if entry.Surface == nil || entry.Surface.Runtime == nil {
		if prefs.PackagePrefix != "" || prefs.ServiceKind != "" || prefs.CapabilityKind != "" || prefs.PrivacyMode != "" || prefs.ReceiptMode != "" || prefs.RequireDisclosureReady {
			failures = append(failures, "runtime metadata missing")
		}
		return failures
	}
	runtime := entry.Surface.Runtime
	if prefs.PackagePrefix != "" && !strings.HasPrefix(runtime.PackageName, prefs.PackagePrefix) {
		failures = append(failures, "package prefix mismatch")
	}
	if prefs.ServiceKind == "" && prefs.CapabilityKind == "" && prefs.PrivacyMode == "" && prefs.ReceiptMode == "" && !prefs.RequireDisclosureReady {
		return failures
	}
	if runtime.Routing == nil {
		failures = append(failures, "routing profile missing")
		return failures
	}
	if prefs.ServiceKind != "" {
		match := runtime.Routing.ServiceKind == prefs.ServiceKind
		if !match {
			for _, kind := range runtime.Routing.ServiceKinds {
				if kind == prefs.ServiceKind {
					match = true
					break
				}
			}
		}
		if !match {
			failures = append(failures, "service kind mismatch")
		}
	}
	if prefs.CapabilityKind != "" && runtime.Routing.CapabilityKind != prefs.CapabilityKind {
		failures = append(failures, "capability kind mismatch")
	}
	if prefs.PrivacyMode != "" && runtime.Routing.PrivacyMode != prefs.PrivacyMode {
		failures = append(failures, "privacy mode mismatch")
	}
	if prefs.ReceiptMode != "" && runtime.Routing.ReceiptMode != prefs.ReceiptMode {
		failures = append(failures, "receipt mode mismatch")
	}
	if prefs.RequireDisclosureReady && !runtime.Routing.DisclosureReady {
		failures = append(failures, "disclosure-ready requirement not met")
	}
	return failures
}

// CreateAccessList tries to create an access list for a specific transaction based on the
// current pending state of the blockchain.
func (ec *Client) CreateAccessList(ctx context.Context, msg gtos.CallMsg) (*types.AccessList, uint64, string, error) {
	type accessListResult struct {
		Accesslist *types.AccessList `json:"accessList"`
		Error      string            `json:"error,omitempty"`
		GasUsed    hexutil.Uint64    `json:"gasUsed"`
	}
	var result accessListResult
	if err := ec.c.CallContext(ctx, &result, "tos_createAccessList", toCallArg(msg)); err != nil {
		return nil, 0, "", err
	}
	return result.Accesslist, uint64(result.GasUsed), result.Error, nil
}

// AccountResult is the result of a GetProof operation.
type AccountResult struct {
	Address      common.Address  `json:"address"`
	AccountProof []string        `json:"accountProof"`
	Balance      *big.Int        `json:"balance"`
	CodeHash     common.Hash     `json:"codeHash"`
	Nonce        uint64          `json:"nonce"`
	StorageHash  common.Hash     `json:"storageHash"`
	StorageProof []StorageResult `json:"storageProof"`
}

// StorageResult provides a proof for a key-value pair.
type StorageResult struct {
	Key   string   `json:"key"`
	Value *big.Int `json:"value"`
	Proof []string `json:"proof"`
}

// GetProof returns the account and storage values of the specified account including the Merkle-proof.
// The block number can be nil, in which case the value is taken from the latest known block.
func (ec *Client) GetProof(ctx context.Context, account common.Address, keys []string, blockNumber *big.Int) (*AccountResult, error) {
	type storageResult struct {
		Key   string       `json:"key"`
		Value *hexutil.Big `json:"value"`
		Proof []string     `json:"proof"`
	}

	type accountResult struct {
		Address      common.Address  `json:"address"`
		AccountProof []string        `json:"accountProof"`
		Balance      *hexutil.Big    `json:"balance"`
		CodeHash     common.Hash     `json:"codeHash"`
		Nonce        hexutil.Uint64  `json:"nonce"`
		StorageHash  common.Hash     `json:"storageHash"`
		StorageProof []storageResult `json:"storageProof"`
	}

	var res accountResult
	err := ec.c.CallContext(ctx, &res, "tos_getProof", account, keys, toBlockNumArg(blockNumber))
	// Turn hexutils back to normal datatypes
	storageResults := make([]StorageResult, 0, len(res.StorageProof))
	for _, st := range res.StorageProof {
		storageResults = append(storageResults, StorageResult{
			Key:   st.Key,
			Value: st.Value.ToInt(),
			Proof: st.Proof,
		})
	}
	result := AccountResult{
		Address:      res.Address,
		AccountProof: res.AccountProof,
		Balance:      res.Balance.ToInt(),
		Nonce:        uint64(res.Nonce),
		CodeHash:     res.CodeHash,
		StorageHash:  res.StorageHash,
		StorageProof: storageResults,
	}
	return &result, err
}

// OverrideAccount specifies the state of an account to be overridden.
type OverrideAccount struct {
	Nonce     uint64                      `json:"nonce"`
	Code      []byte                      `json:"code"`
	Balance   *big.Int                    `json:"balance"`
	State     map[common.Hash]common.Hash `json:"state"`
	StateDiff map[common.Hash]common.Hash `json:"stateDiff"`
}

// CallContract executes a message call transaction, which is directly executed in the VM
// of the node, but never mined into the blockchain.
//
// blockNumber selects the block height at which the call runs. It can be nil, in which
// case the code is taken from the latest known block. Note that state from very old
// blocks might not be available.
//
// overrides specifies a map of contract states that should be overwritten before executing
// the message call.
// Please use tosclient.CallContract instead if you don't need the override functionality.
func (ec *Client) CallContract(ctx context.Context, msg gtos.CallMsg, blockNumber *big.Int, overrides *map[common.Address]OverrideAccount) ([]byte, error) {
	var hex hexutil.Bytes
	err := ec.c.CallContext(
		ctx, &hex, "tos_call", toCallArg(msg),
		toBlockNumArg(blockNumber), toOverrideMap(overrides),
	)
	return hex, err
}

// GCStats retrieves the current garbage collection stats from a gtos node.
func (ec *Client) GCStats(ctx context.Context) (*debug.GCStats, error) {
	var result debug.GCStats
	err := ec.c.CallContext(ctx, &result, "debug_gcStats")
	return &result, err
}

// MemStats retrieves the current memory stats from a gtos node.
func (ec *Client) MemStats(ctx context.Context) (*runtime.MemStats, error) {
	var result runtime.MemStats
	err := ec.c.CallContext(ctx, &result, "debug_memStats")
	return &result, err
}

// SetHead sets the current head of the local chain by block number.
// Note, this is a destructive action and may severely damage your chain.
// Use with extreme caution.
func (ec *Client) SetHead(ctx context.Context, number *big.Int) error {
	return ec.c.CallContext(ctx, nil, "debug_setHead", toBlockNumArg(number))
}

// GetNodeInfo retrieves the node info of a gtos node.
func (ec *Client) GetNodeInfo(ctx context.Context) (*p2p.NodeInfo, error) {
	var result p2p.NodeInfo
	err := ec.c.CallContext(ctx, &result, "admin_nodeInfo")
	return &result, err
}

// SubscribePendingTransactions subscribes to new pending transactions.
func (ec *Client) SubscribePendingTransactions(ctx context.Context, ch chan<- common.Hash) (*rpc.ClientSubscription, error) {
	return ec.c.TOSSubscribe(ctx, ch, "newPendingTransactions")
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
	return arg
}

func toOverrideMap(overrides *map[common.Address]OverrideAccount) interface{} {
	if overrides == nil {
		return nil
	}
	type overrideAccount struct {
		Nonce     hexutil.Uint64              `json:"nonce"`
		Code      hexutil.Bytes               `json:"code"`
		Balance   *hexutil.Big                `json:"balance"`
		State     map[common.Hash]common.Hash `json:"state"`
		StateDiff map[common.Hash]common.Hash `json:"stateDiff"`
	}
	result := make(map[common.Address]overrideAccount)
	for addr, override := range *overrides {
		result[addr] = overrideAccount{
			Nonce:     hexutil.Uint64(override.Nonce),
			Code:      override.Code,
			Balance:   (*hexutil.Big)(override.Balance),
			State:     override.State,
			StateDiff: override.StateDiff,
		}
	}
	return &result
}
