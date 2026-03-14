package vm

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/lease"
	"github.com/tos-network/gtos/params"
)

func TestCreateXActivatesLeaseMeta(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x51}
	owner := common.Address{0x61}
	childCode := `local x = 1`
	leaseBlocks := uint64(100)

	deposit, err := lease.DepositFor(uint64(len(childCode)), leaseBlocks)
	if err != nil {
		t.Fatalf("DepositFor: %v", err)
	}
	st.AddBalance(contractAddr, new(big.Int).Add(deposit, big.NewInt(1)))

	src := `
local child = tos.createx([=[` + childCode + `]=], ` + big.NewInt(int64(leaseBlocks)).String() + `, "` + owner.Hex() + `")
`
	if _, _, _, err := runLua(st, contractAddr, src, 5_000_000); err != nil {
		t.Fatalf("runLua createx: %v", err)
	}

	childAddr := crypto.CreateAddress(contractAddr, 0)
	meta, ok := lease.ReadMeta(st, childAddr)
	if !ok {
		t.Fatal("expected lease metadata for createx child")
	}
	if meta.LeaseOwner != owner {
		t.Fatalf("LeaseOwner: want %s, got %s", owner.Hex(), meta.LeaseOwner.Hex())
	}
	if string(st.GetCode(childAddr)) != childCode {
		t.Fatalf("child code mismatch: want %q, got %q", childCode, string(st.GetCode(childAddr)))
	}
	if st.GetBalance(params.LeaseRegistryAddress).Cmp(deposit) != 0 {
		t.Fatalf("registry balance: want %v, got %v", deposit, st.GetBalance(params.LeaseRegistryAddress))
	}
}

func TestCreate2XActivatesLeaseMeta(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x71}
	owner := common.Address{0x81}
	childCode := `local y = 2`
	leaseBlocks := uint64(150)
	saltHex := "0x1234"

	deposit, err := lease.DepositFor(uint64(len(childCode)), leaseBlocks)
	if err != nil {
		t.Fatalf("DepositFor: %v", err)
	}
	st.AddBalance(contractAddr, new(big.Int).Add(deposit, big.NewInt(1)))

	src := `
local child = tos.create2x([=[` + childCode + `]=], "` + saltHex + `", ` + big.NewInt(int64(leaseBlocks)).String() + `, "` + owner.Hex() + `")
`
	if _, _, _, err := runLua(st, contractAddr, src, 5_000_000); err != nil {
		t.Fatalf("runLua create2x: %v", err)
	}

	var salt [32]byte
	copy(salt[30:], common.FromHex(saltHex))
	childAddr := crypto.CreateAddress2(contractAddr, salt, crypto.Keccak256([]byte(childCode)))
	meta, ok := lease.ReadMeta(st, childAddr)
	if !ok {
		t.Fatal("expected lease metadata for create2x child")
	}
	if meta.LeaseOwner != owner {
		t.Fatalf("LeaseOwner: want %s, got %s", owner.Hex(), meta.LeaseOwner.Hex())
	}
	if string(st.GetCode(childAddr)) != childCode {
		t.Fatalf("child code mismatch: want %q, got %q", childCode, string(st.GetCode(childAddr)))
	}
}
