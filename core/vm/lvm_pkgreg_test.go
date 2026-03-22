package vm

import (
	"encoding/hex"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/pkgregistry"
	lua "github.com/tos-network/tolang"
)

// makeTorPackage builds a minimal .tor package containing a single contract
// with valid .toc artifact bytes.
func makeTorPackage(t *testing.T, contractName string) []byte {
	t.Helper()
	luaSrc := []byte(`local x = 1`)

	// Compile Lua source to bytecode for a valid .toc artifact.
	bytecode, err := lua.CompileSourceToBytecode(luaSrc, contractName)
	if err != nil {
		t.Fatalf("CompileSourceToBytecode: %v", err)
	}

	srcHash := crypto.Keccak256(luaSrc)
	bcHash := crypto.Keccak256(bytecode)
	art := &lua.Artifact{
		Version:      lua.ArtifactFormatVersion,
		Compiler:     "test",
		ContractName: contractName,
		Bytecode:     bytecode,
		ABIJSON:      []byte(`[]`),
		SourceHash:   "0x" + hex.EncodeToString(srcHash),
		BytecodeHash: "0x" + hex.EncodeToString(bcHash),
	}
	tocBytes, err := lua.EncodeArtifact(art)
	if err != nil {
		t.Fatalf("EncodeArtifact: %v", err)
	}

	tocFile := contractName + ".toc"
	manifest := []byte(`{"name":"testpkg","version":"1.0.0","contracts":[{"name":"` +
		contractName + `","toc":"` + tocFile + `"}]}`)
	files := map[string][]byte{
		tocFile: tocBytes,
	}
	data, err := lua.EncodePackage(manifest, files)
	if err != nil {
		t.Fatalf("EncodePackage: %v", err)
	}
	return data
}

// deployTorPackage deploys a .tor package to an address and returns the code bytes.
func deployTorPackage(t *testing.T, st StateDB, addr common.Address, contractName string) []byte {
	t.Helper()
	code := makeTorPackage(t, contractName)
	st.CreateAccount(addr)
	st.SetCode(addr, code)
	return code
}

// TestPackageCallNoRegistryRecord verifies that a package_call to a deployed
// package with no registry record succeeds (backward-compatible).
func TestPackageCallNoRegistryRecord(t *testing.T) {
	st := newAgentTestState()
	calleeAddr := common.Address{0xD1}
	contractName := "Greeter"
	deployTorPackage(t, st, calleeAddr, contractName)

	parentAddr := common.Address{0xA1}
	src := `
local ok, ret = tos.package_call("` + calleeAddr.Hex() + `", "` + contractName + `", nil)
tos.sstore("ok", ok and 1 or 0)
`
	_, _, _, err := runLua(st, parentAddr, src, 5_000_000)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	okSlot := st.GetState(parentAddr, StorageSlot("ok"))
	if got := okSlot.Big().Uint64(); got != 1 {
		t.Fatalf("expected ok=1 (call succeeded), got %d", got)
	}
}

// TestPackageCallRegisteredActive verifies that a package_call to a package
// with an active registry record and active publisher succeeds.
func TestPackageCallRegisteredActive(t *testing.T) {
	st := newAgentTestState()
	calleeAddr := common.Address{0xD2}
	contractName := "Greeter"
	code := deployTorPackage(t, st, calleeAddr, contractName)

	// Write active package + publisher records.
	pkgHash := crypto.Keccak256Hash(code)
	pubID := [32]byte{0x01}
	pkgregistry.WritePublisher(st, pkgregistry.PublisherRecord{
		PublisherID: pubID,
		Controller:  common.Address{0xBB},
		Status:      pkgregistry.PkgActive,
	})
	pkgregistry.WritePackage(st, pkgregistry.PackageRecord{
		PackageName:    "testpkg",
		PackageVersion: "1.0.0",
		PackageHash:    pkgHash,
		PublisherID:    pubID,
		Status:         pkgregistry.PkgActive,
	})

	parentAddr := common.Address{0xA2}
	src := `
local ok, ret = tos.package_call("` + calleeAddr.Hex() + `", "` + contractName + `", nil)
tos.sstore("ok", ok and 1 or 0)
`
	_, _, _, err := runLua(st, parentAddr, src, 5_000_000)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	okSlot := st.GetState(parentAddr, StorageSlot("ok"))
	if got := okSlot.Big().Uint64(); got != 1 {
		t.Fatalf("expected ok=1 (call succeeded), got %d", got)
	}
}

// TestPackageCallRegisteredRevoked verifies that a package_call to a revoked
// package returns (false, "PACKAGE_REVOKED").
func TestPackageCallRegisteredRevoked(t *testing.T) {
	st := newAgentTestState()
	calleeAddr := common.Address{0xD3}
	contractName := "Greeter"
	code := deployTorPackage(t, st, calleeAddr, contractName)

	pkgHash := crypto.Keccak256Hash(code)
	pubID := [32]byte{0x02}
	pkgregistry.WritePublisher(st, pkgregistry.PublisherRecord{
		PublisherID: pubID,
		Controller:  common.Address{0xCC},
		Status:      pkgregistry.PkgActive,
	})
	pkgregistry.WritePackage(st, pkgregistry.PackageRecord{
		PackageName:    "testpkg",
		PackageVersion: "1.0.0",
		PackageHash:    pkgHash,
		PublisherID:    pubID,
		Status:         pkgregistry.PkgRevoked,
	})

	parentAddr := common.Address{0xA3}
	// ok should be false; ret should be "PACKAGE_REVOKED" (a string, not storable
	// via sstore which expects a number — so we just check ok).
	src := `
local ok, ret = tos.package_call("` + calleeAddr.Hex() + `", "` + contractName + `", nil)
tos.sstore("ok", ok and 1 or 0)
`
	_, _, _, err := runLua(st, parentAddr, src, 5_000_000)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	okSlot := st.GetState(parentAddr, StorageSlot("ok"))
	if got := okSlot.Big().Uint64(); got != 0 {
		t.Fatalf("expected ok=0 (call rejected), got %d", got)
	}
}

// TestPackageCallPublisherRevoked verifies that a package_call to an active
// package whose publisher has been revoked returns (false, "PUBLISHER_REVOKED").
func TestPackageCallPublisherRevoked(t *testing.T) {
	st := newAgentTestState()
	calleeAddr := common.Address{0xD4}
	contractName := "Greeter"
	code := deployTorPackage(t, st, calleeAddr, contractName)

	pkgHash := crypto.Keccak256Hash(code)
	pubID := [32]byte{0x03}
	pkgregistry.WritePublisher(st, pkgregistry.PublisherRecord{
		PublisherID: pubID,
		Controller:  common.Address{0xDD},
		Status:      pkgregistry.PkgRevoked,
	})
	pkgregistry.WritePackage(st, pkgregistry.PackageRecord{
		PackageName:    "testpkg",
		PackageVersion: "1.0.0",
		PackageHash:    pkgHash,
		PublisherID:    pubID,
		Status:         pkgregistry.PkgActive,
	})

	parentAddr := common.Address{0xA4}
	src := `
local ok, ret = tos.package_call("` + calleeAddr.Hex() + `", "` + contractName + `", nil)
tos.sstore("ok", ok and 1 or 0)
`
	_, _, _, err := runLua(st, parentAddr, src, 5_000_000)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	okSlot := st.GetState(parentAddr, StorageSlot("ok"))
	if got := okSlot.Big().Uint64(); got != 0 {
		t.Fatalf("expected ok=0 (call rejected), got %d", got)
	}
}
