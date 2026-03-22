package vm

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
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
// package with no registry record fails closed.
func TestPackageCallNoRegistryRecord(t *testing.T) {
	st := newAgentTestState()
	calleeAddr := common.Address{0xD1}
	contractName := "Greeter"
	deployTorPackage(t, st, calleeAddr, contractName)

	parentAddr := common.Address{0xA1}
	src := `
local ok, ret = tos.package_call("` + calleeAddr.Hex() + `", "` + contractName + `", nil)
tos.sstore("ok", ok and 1 or 0)
if ret ~= nil then
  tos.setStr("ret", ret)
end
`
	_, _, _, err := runLua(st, parentAddr, src, 5_000_000)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	okSlot := st.GetState(parentAddr, StorageSlot("ok"))
	if got := okSlot.Big().Uint64(); got != 0 {
		t.Fatalf("expected ok=0 (call rejected), got %d", got)
	}
	if got := readStateString(t, st, parentAddr, "ret"); got != "PACKAGE_UNPUBLISHED" {
		t.Fatalf("expected PACKAGE_UNPUBLISHED, got %q", got)
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

func TestPackageCallMalformedAddrRejected(t *testing.T) {
	st := newAgentTestState()
	parentAddr := common.Address{0xA5}
	src := `
local ok, ret = tos.package_call("0x1234", "Greeter", nil)
tos.sstore("ok", ok and 1 or 0)
`
	_, _, _, err := runLua(st, parentAddr, src, 5_000_000)
	if err == nil {
		t.Fatal("expected malformed addr to raise an error")
	}
	if got := err.Error(); got == "" || !containsAll(got, "bad argument #1", "invalid addr") {
		t.Fatalf("unexpected malformed addr error: %v", err)
	}
}

func TestPackageCallMalformedDataRejected(t *testing.T) {
	st := newAgentTestState()
	calleeAddr := common.Address{0xD5}
	parentAddr := common.Address{0xA6}
	contractName := "Greeter"
	deployTorPackage(t, st, calleeAddr, contractName)

	src := `
local ok, ret = tos.package_call("` + calleeAddr.Hex() + `", "` + contractName + `", "0xxyz")
tos.sstore("ok", ok and 1 or 0)
`
	_, _, _, err := runLua(st, parentAddr, src, 5_000_000)
	if err == nil {
		t.Fatal("expected malformed data to raise an error")
	}
	if got := err.Error(); got == "" || !containsAll(got, "bad argument #3", "invalid data") {
		t.Fatalf("unexpected malformed data error: %v", err)
	}
}

func readStateString(t *testing.T, st StateDB, addr common.Address, key string) string {
	t.Helper()
	lenSlot := st.GetState(addr, StrLenSlot(key))
	if lenSlot == (common.Hash{}) {
		return ""
	}
	length := int(binary.BigEndian.Uint64(lenSlot[24:])) - 1
	if length <= 0 {
		return ""
	}
	data := make([]byte, length)
	base := StrLenSlot(key)
	for i := 0; i < length; i += 32 {
		chunk := st.GetState(addr, StrChunkSlot(base, i/32))
		end := i + 32
		if end > length {
			end = length
		}
		copy(data[i:end], chunk[:end-i])
	}
	return string(data)
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}
