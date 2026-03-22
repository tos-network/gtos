package tosapi

import (
	"context"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/pkgregistry"
	"github.com/tos-network/gtos/rpc"
	lua "github.com/tos-network/tolang"
)

const contractMetadataPackageSource = `pragma tolang 0.4.0;
package demo.checkout;

contract Alpha {
    error NotReady();

    function ping() public pure returns (u256) {
        return 1;
    }

    function fail() public pure {
        revert NotReady();
    }
}

contract Beta {
    function pong() public pure returns (u256) {
        return 2;
    }
}
`

const contractMetadataArtifactSource = `pragma tolang 0.4.0;

contract Solo {
    error Halted();

    function ping() public pure returns (u256) {
        return 7;
    }

    function fail() public pure {
        revert Halted();
    }
}
`

const contractMetadataDiscoverySource = `pragma tolang 0.4.0;

contract ServiceDirectory {
    function registerService(bytes32 manifest_ref, bytes32 capability_ref, bytes32 version_ref, bytes32 quote_ref) public returns (u256 service_id) {
        return 1;
    }

    function serviceKindOf(u256 service_id) public pure returns (u256 service_kind) {
        return 8;
    }

    function capabilityTypeOf(u256 service_id) public pure returns (u256 capability_type) {
        return 1;
    }

    function pricingKindOf(u256 service_id) public pure returns (u256 pricing_kind) {
        return 1;
    }

    function privacyModeOf(u256 service_id) public pure returns (u256 privacy_mode) {
        return 4;
    }

    function receiptModeOf(u256 service_id) public pure returns (u256 receipt_mode) {
        return 4;
    }

    function trustFloorRefOf(u256 service_id) public pure returns (bytes32 trust_floor_ref) {
        return bytes32(0);
    }
}
`

func TestGetContractMetadataReturnsPackageDescriptor(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	pkgBytes, err := lua.CompilePackage([]byte(contractMetadataPackageSource), "DemoCheckout.tol", &lua.PackageOptions{
		PackageName:    "demo.checkout",
		PackageVersion: "1.2.3",
	})
	if err != nil {
		t.Fatalf("CompilePackage failed: %v", err)
	}
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111111111111111111111111111")
	st.SetCode(addr, pkgBytes)

	api := NewBlockChainAPI(&getCodeBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(199)},
	})
	got, err := api.GetContractMetadata(context.Background(), addr, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil response")
	}
	if got.CodeKind != "tor" {
		t.Fatalf("unexpected code kind %q", got.CodeKind)
	}
	if got.Package == nil {
		t.Fatal("expected package descriptor")
	}
	if got.Package.Package != "demo.checkout" {
		t.Fatalf("unexpected package name %q", got.Package.Package)
	}
	if got.Package.Version != "1.2.3" {
		t.Fatalf("unexpected package version %q", got.Package.Version)
	}
	if len(got.Package.Contracts) != 2 {
		t.Fatalf("unexpected contract count %d", len(got.Package.Contracts))
	}
	alpha := got.Package.Contracts[0]
	if alpha.Name != "Alpha" {
		t.Fatalf("unexpected first contract %q", alpha.Name)
	}
	if alpha.Artifact == nil || alpha.Artifact.Metadata == nil {
		t.Fatal("expected decoded Alpha artifact metadata")
	}
	if alpha.Artifact.Metadata.Contract.Name != "Alpha" {
		t.Fatalf("unexpected metadata contract name %q", alpha.Artifact.Metadata.Contract.Name)
	}
	if alpha.Artifact.Discovery == nil || alpha.Artifact.Discovery.PackageName != "demo.checkout" {
		t.Fatalf("unexpected discovery package name %#v", alpha.Artifact.Discovery)
	}
	if alpha.Artifact.AgentPackage == nil || len(alpha.Artifact.AgentPackage.Errors) == 0 {
		t.Fatal("expected declared errors in agent package")
	}
	foundFail := false
	for _, method := range alpha.Artifact.Discovery.InterfaceMethods {
		if method.Name != "fail" {
			continue
		}
		foundFail = true
		if len(method.FailureModes) == 0 {
			t.Fatal("expected failure modes for Alpha.fail")
		}
		if method.FailureModes[0].Name != "NotReady" {
			t.Fatalf("unexpected failure mode %#v", method.FailureModes[0])
		}
	}
	if !foundFail {
		t.Fatal("expected fail method in discovery manifest")
	}
	beta := got.Package.Contracts[1]
	if beta.Name != "Beta" {
		t.Fatalf("unexpected second contract %q", beta.Name)
	}
	if beta.Artifact == nil || beta.Artifact.Metadata == nil || beta.Artifact.Metadata.Contract.Name != "Beta" {
		t.Fatalf("unexpected Beta artifact %#v", beta.Artifact)
	}
}

func TestGetContractMetadataReturnsPublishedPackageIdentity(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	pkgBytes, err := lua.CompilePackage([]byte(contractMetadataPackageSource), "DemoCheckout.tol", &lua.PackageOptions{
		PackageName:    "demo.checkout",
		PackageVersion: "1.2.3",
	})
	if err != nil {
		t.Fatalf("CompilePackage failed: %v", err)
	}
	addr := common.HexToAddress("0x1212121212121212121212121212121212121212121212121212121212121212")
	st.SetCode(addr, pkgBytes)

	pubID := [32]byte{0x42}
	pkgregistry.WritePublisher(st, pkgregistry.PublisherRecord{
		PublisherID: pubID,
		Controller:  common.HexToAddress("0x1234000000000000000000000000000000000000"),
		Status:      pkgregistry.PkgActive,
	})
	pkgregistry.WritePackage(st, pkgregistry.PackageRecord{
		PackageName:    "demo.checkout",
		PackageVersion: "1.2.3",
		PackageHash:    crypto.Keccak256Hash(pkgBytes),
		PublisherID:    pubID,
		Channel:        pkgregistry.ChannelStable,
		Status:         pkgregistry.PkgActive,
		ContractCount:  2,
	})

	api := NewBlockChainAPI(&getCodeBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(199)},
	})
	got, err := api.GetContractMetadata(context.Background(), addr, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.Package == nil {
		t.Fatal("expected package descriptor")
	}
	if got.Package.Published == nil {
		t.Fatal("expected published package info")
	}
	if got.Package.Published.Name != "demo.checkout" || got.Package.Published.Channel != "stable" {
		t.Fatalf("unexpected published package %+v", got.Package.Published)
	}
	if got.Package.Publisher == nil || got.Package.Publisher.Status != "active" {
		t.Fatalf("unexpected publisher info %+v", got.Package.Publisher)
	}
}

func TestGetContractMetadataReturnsArtifactDescriptor(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	artifactBytes, err := lua.CompileArtifact([]byte(contractMetadataArtifactSource), "Solo.tol")
	if err != nil {
		t.Fatalf("CompileArtifact failed: %v", err)
	}
	addr := common.HexToAddress("0x2222222222222222222222222222222222222222222222222222222222222222")
	st.SetCode(addr, artifactBytes)

	api := NewBlockChainAPI(&getCodeBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(199)},
	})
	got, err := api.GetContractMetadata(context.Background(), addr, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil response")
	}
	if got.CodeKind != "toc" {
		t.Fatalf("unexpected code kind %q", got.CodeKind)
	}
	if got.Package != nil {
		t.Fatal("did not expect package descriptor for raw artifact")
	}
	if got.Artifact == nil || got.Artifact.Metadata == nil {
		t.Fatal("expected artifact descriptor")
	}
	if got.Artifact.ContractName != "Solo" {
		t.Fatalf("unexpected contract name %q", got.Artifact.ContractName)
	}
	if got.Artifact.Discovery == nil || got.Artifact.Discovery.PackageName != "solo" {
		t.Fatalf("unexpected discovery manifest %#v", got.Artifact.Discovery)
	}
	if got.Artifact.AgentPackage == nil || len(got.Artifact.AgentPackage.Errors) != 1 {
		t.Fatalf("unexpected agent package %#v", got.Artifact.AgentPackage)
	}
}

func TestGetContractMetadataReturnsRoutingProfile(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	artifactBytes, err := lua.CompileArtifact([]byte(contractMetadataDiscoverySource), "ServiceDirectory.tol")
	if err != nil {
		t.Fatalf("CompileArtifact failed: %v", err)
	}
	addr := common.HexToAddress("0x2525252525252525252525252525252525252525252525252525252525252525")
	st.SetCode(addr, artifactBytes)

	api := NewBlockChainAPI(&getCodeBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(199)},
	})
	got, err := api.GetContractMetadata(context.Background(), addr, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.Artifact == nil {
		t.Fatal("expected artifact descriptor")
	}
	if got.Artifact.Discovery == nil || got.Artifact.Discovery.TypedDiscovery == nil {
		t.Fatalf("expected typed discovery manifest, got %#v", got.Artifact.Discovery)
	}
	if got.Artifact.Routing == nil {
		t.Fatal("expected routing profile")
	}
	if got.Artifact.Routing.ServiceKind != "DISCOVERY" {
		t.Fatalf("routing service kind: got %q want %q", got.Artifact.Routing.ServiceKind, "DISCOVERY")
	}
	if got.Artifact.Routing.CapabilityKind != "READ_ONLY" {
		t.Fatalf("routing capability kind: got %q want %q", got.Artifact.Routing.CapabilityKind, "READ_ONLY")
	}
	if got.Artifact.Routing.PrivacyMode != "PUBLIC_ONLY" {
		t.Fatalf("routing privacy mode: got %q want %q", got.Artifact.Routing.PrivacyMode, "PUBLIC_ONLY")
	}
}

func TestGetContractMetadataReturnsRawCodeKind(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0x3333333333333333333333333333333333333333333333333333333333333333")
	st.SetCode(addr, []byte{0x60, 0x00, 0x60, 0x00})

	api := NewBlockChainAPI(&getCodeBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(199)},
	})
	got, err := api.GetContractMetadata(context.Background(), addr, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil response")
	}
	if got.CodeKind != "raw" {
		t.Fatalf("unexpected code kind %q", got.CodeKind)
	}
	if got.Artifact != nil || got.Package != nil {
		t.Fatalf("unexpected decoded payload %#v", got)
	}
}

func TestGetContractMetadataHistoryPrunedByRetentionWindow(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0x4444444444444444444444444444444444444444444444444444444444444444")
	st.SetCode(addr, []byte{0x60, 0x00})
	head := rpcDefaultRetainBlocks + 100
	req := oldestAvailableBlock(head, rpcDefaultRetainBlocks) - 1

	backend := newBackendMock()
	backend.current.Number = new(big.Int).SetUint64(head)
	api := NewBlockChainAPI(&getCodeBackendMock{
		backendMock: backend,
		st:          st,
		head:        &types.Header{Number: new(big.Int).SetUint64(req)},
	})
	_, err = api.GetContractMetadata(context.Background(), addr, rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(req)))
	if err == nil {
		t.Fatal("expected history pruned error")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrHistoryPruned {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrHistoryPruned)
	}
}
