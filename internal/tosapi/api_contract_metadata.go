package tosapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tos-network/gtos/agentdiscovery"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/pkgregistry"
	"github.com/tos-network/gtos/rpc"
	lua "github.com/tos-network/tolang"
	tolmeta "github.com/tos-network/tolang/metadata"
)

// DeployedCodeInfo describes the code stored at an address, including
// agent-native TOL metadata when the code is a .toc artifact or .tor package.
type DeployedCodeInfo struct {
	Address  common.Address   `json:"address"`
	CodeHash common.Hash      `json:"code_hash"`
	CodeKind string           `json:"code_kind"` // "empty", "raw", "toc", "tor"
	Artifact *TOLArtifactInfo `json:"artifact,omitempty"`
	Package  *TOLPackageInfo  `json:"package,omitempty"`
}

// TOLArtifactInfo is the inspection payload for one compiled .toc artifact.
type TOLArtifactInfo struct {
	ContractName  string                              `json:"contract_name"`
	BytecodeHash  string                              `json:"bytecode_hash"`
	ABI           json.RawMessage                     `json:"abi"`
	Metadata      *tolmeta.ContractMetadata           `json:"metadata,omitempty"`
	Discovery     *tolmeta.DiscoveryManifest          `json:"discovery,omitempty"`
	AgentPackage  *tolmeta.AgentPackageInfo           `json:"agent_package,omitempty"`
	Profile       *tolmeta.AgentContractProfile       `json:"profile,omitempty"`
	Routing       *agentdiscovery.TypedRoutingProfile `json:"routing_profile,omitempty"`
	SuggestedCard *agentdiscovery.PublishedCard       `json:"suggested_card,omitempty"`
}

// TOLPackageInfo is the inspection payload for one deployed .tor package.
type TOLPackageInfo struct {
	Name          string                        `json:"name,omitempty"`
	Package       string                        `json:"package,omitempty"`
	Version       string                        `json:"version,omitempty"`
	MainContract  string                        `json:"main_contract,omitempty"`
	InitCode      string                        `json:"init_code,omitempty"`
	Manifest      json.RawMessage               `json:"manifest"`
	Contracts     []TOLPackageContractInfo      `json:"contracts"`
	Profile       *tolmeta.AgentBundleProfile   `json:"bundle_profile,omitempty"`
	Published     *PackageInfo                  `json:"published,omitempty"`
	Publisher     *PublisherInfo                `json:"publisher,omitempty"`
	SuggestedCard *agentdiscovery.PublishedCard `json:"suggested_card,omitempty"`
}

// TOLPackageContractInfo describes one manifest contract entry inside a .tor package.
type TOLPackageContractInfo struct {
	Name          string           `json:"name"`
	ArtifactPath  string           `json:"artifact_path,omitempty"`
	InterfacePath string           `json:"interface_path,omitempty"`
	Artifact      *TOLArtifactInfo `json:"artifact,omitempty"`
}

type rpcTOLPackageManifest struct {
	Name         string                      `json:"name"`
	Package      string                      `json:"package,omitempty"`
	Version      string                      `json:"version"`
	MainContract string                      `json:"main_contract,omitempty"`
	InitCode     string                      `json:"init_code,omitempty"`
	Contracts    []rpcTOLPackageManifestItem `json:"contracts"`
}

type rpcTOLPackageManifestItem struct {
	Name      string `json:"name"`
	Artifact  string `json:"toc,omitempty"`
	Interface string `json:"abi,omitempty"`
}

// GetContractMetadata returns structural information about code stored at an
// address. For raw non-TOL code it reports only the code kind/hash. For .toc
// and .tor deployments it decodes the artifact/package and returns ABI,
// extracted metadata, discovery manifest, and agent package info.
func (s *BlockChainAPI) GetContractMetadata(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*DeployedCodeInfo, error) {
	if err := enforceHistoryRetentionByBlockArg(s.b, blockNrOrHash); err != nil {
		return nil, err
	}
	state, header, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || header == nil || err != nil {
		return nil, err
	}
	info, err := inspectDeployedCode(address, state.GetCodeHash(address), state.GetCode(address), state)
	if err != nil {
		return nil, err
	}
	return info, state.Error()
}

func inspectDeployedCode(address common.Address, codeHash common.Hash, code []byte, st *state.StateDB) (*DeployedCodeInfo, error) {
	info := &DeployedCodeInfo{
		Address:  address,
		CodeHash: codeHash,
	}
	if len(code) == 0 {
		info.CodeKind = "empty"
		return info, nil
	}
	if lua.IsPackage(code) {
		pkgInfo, err := inspectTOLPackage(code, st)
		if err != nil {
			return nil, err
		}
		info.CodeKind = "tor"
		info.Package = pkgInfo
		return info, nil
	}
	if lua.IsArtifact(code) {
		artInfo, err := inspectTOLArtifact(code, "")
		if err != nil {
			return nil, err
		}
		info.CodeKind = "toc"
		info.Artifact = artInfo
		return info, nil
	}
	info.CodeKind = "raw"
	return info, nil
}

func inspectTOLPackage(pkgBytes []byte, st *state.StateDB) (*TOLPackageInfo, error) {
	pkg, err := lua.DecodePackage(pkgBytes)
	if err != nil {
		return nil, fmt.Errorf("decode deployed .tor package: %w", err)
	}
	var manifest rpcTOLPackageManifest
	if err := json.Unmarshal(pkg.ManifestJSON, &manifest); err != nil {
		return nil, fmt.Errorf("decode deployed .tor manifest: %w", err)
	}
	packageName := strings.TrimSpace(manifest.Package)
	if packageName == "" {
		packageName = strings.TrimSpace(manifest.Name)
	}

	info := &TOLPackageInfo{
		Name:         manifest.Name,
		Package:      manifest.Package,
		Version:      manifest.Version,
		MainContract: manifest.MainContract,
		InitCode:     manifest.InitCode,
		Manifest:     append(json.RawMessage(nil), pkg.ManifestJSON...),
		Contracts:    make([]TOLPackageContractInfo, 0, len(manifest.Contracts)),
	}
	profiles := make([]*tolmeta.AgentContractProfile, 0, len(manifest.Contracts))
	for _, contract := range manifest.Contracts {
		entry := TOLPackageContractInfo{
			Name:          contract.Name,
			ArtifactPath:  contract.Artifact,
			InterfacePath: contract.Interface,
		}
		if strings.TrimSpace(contract.Artifact) != "" {
			artifactBytes, ok := pkg.Files[contract.Artifact]
			if !ok {
				return nil, fmt.Errorf("package contract %q missing artifact %q", contract.Name, contract.Artifact)
			}
			artInfo, err := inspectTOLArtifact(artifactBytes, packageName)
			if err != nil {
				return nil, fmt.Errorf("package contract %q: %w", contract.Name, err)
			}
			entry.Artifact = artInfo
			if artInfo.Profile != nil {
				profiles = append(profiles, artInfo.Profile)
			}
		}
		info.Contracts = append(info.Contracts, entry)
	}
	if len(profiles) > 0 {
		info.Profile = tolmeta.BuildAgentBundleProfile(inferPackageProfileFamily(packageName, manifest.Name), packageName, manifest.Version, profiles)
	}
	info.SuggestedCard = agentdiscovery.BuildPublishedCardFromBundle(info.Profile)
	if st != nil {
		if published, publisher := inspectPublishedPackage(st, pkgBytes); published != nil {
			info.Published = published
			info.Publisher = publisher
		}
	}
	return info, nil
}

func inspectTOLArtifact(artifactBytes []byte, packageName string) (*TOLArtifactInfo, error) {
	art, err := lua.DecodeArtifact(artifactBytes)
	if err != nil {
		return nil, fmt.Errorf("decode deployed .toc artifact: %w", err)
	}
	meta, err := tolmeta.ExtractFromABI(art.ABIJSON)
	if err != nil {
		return nil, fmt.Errorf("extract deployed TOL metadata: %w", err)
	}
	if strings.TrimSpace(meta.Contract.Name) == "" && strings.TrimSpace(art.ContractName) != "" {
		meta.Contract.Name = strings.TrimSpace(art.ContractName)
	}
	if strings.TrimSpace(packageName) == "" {
		packageName = defaultArtifactPackageName(meta, art)
	}
	discovery := tolmeta.BuildDiscoveryManifest(meta, packageName)
	profile := tolmeta.BuildAgentProfile(meta, packageName)
	profile.Identity.PackageName = packageName
	return &TOLArtifactInfo{
		ContractName:  art.ContractName,
		BytecodeHash:  art.BytecodeHash,
		ABI:           append(json.RawMessage(nil), art.ABIJSON...),
		Metadata:      meta,
		Discovery:     discovery,
		AgentPackage:  tolmeta.BuildAgentPackageInfo(meta, packageName),
		Profile:       profile,
		Routing:       agentdiscovery.BuildTypedRoutingProfile(discovery),
		SuggestedCard: agentdiscovery.BuildPublishedCardFromProfile(profile, discovery),
	}, nil
}

func defaultArtifactPackageName(meta *tolmeta.ContractMetadata, art *lua.Artifact) string {
	if meta != nil && strings.TrimSpace(meta.Contract.Name) != "" {
		return strings.ToLower(strings.TrimSpace(meta.Contract.Name))
	}
	if art != nil && strings.TrimSpace(art.ContractName) != "" {
		return strings.ToLower(strings.TrimSpace(art.ContractName))
	}
	return "contract"
}

func inferPackageProfileFamily(packageName, manifestName string) string {
	name := strings.TrimSpace(packageName)
	if name == "" {
		name = strings.TrimSpace(manifestName)
	}
	if strings.HasPrefix(name, "tolang.openlib.") {
		rest := strings.TrimPrefix(name, "tolang.openlib.")
		if idx := strings.Index(rest, "."); idx >= 0 {
			return rest[:idx]
		}
		return rest
	}
	return name
}

func inspectPublishedPackage(st *state.StateDB, pkgBytes []byte) (*PackageInfo, *PublisherInfo) {
	pkgHash := crypto.Keccak256Hash(pkgBytes)
	rec := pkgregistry.ReadPackageByHash(st, pkgHash)
	if rec.PackageHash == ([32]byte{}) {
		return nil, nil
	}
	pubRec := pkgregistry.ReadPublisher(st, rec.PublisherID)
	nsRec := pkgregistry.ReadNamespaceGovernance(st, pubRec.Namespace)
	published := packageInfoFromRecord(rec, pubRec, nsRec)
	if pubRec.Controller == (common.Address{}) {
		return published, nil
	}
	return published, publisherInfoFromRecord(pubRec, nsRec)
}
