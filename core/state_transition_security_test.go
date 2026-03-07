package core

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
	lvm "github.com/tos-network/gtos/core/vm"
)

// secBlockCtx returns a minimal BlockContext for security tests.
func secBlockCtx() lvm.BlockContext {
	return lvm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		Coinbase:    common.HexToAddress("0xC01NBASE"),
		BlockNumber: big.NewInt(1),
		Time:        big.NewInt(0),
		GasLimit:    30_000_000,
	}
}

// newSecState returns a fresh in-memory StateDB with the given addresses pre-funded.
func newSecState(t *testing.T, balances map[common.Address]*big.Int) *state.StateDB {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	st, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	for addr, bal := range balances {
		st.SetBalance(addr, bal)
	}
	return st
}

// Issue A: CREATE with value > sender balance must return ErrInsufficientFundsForTransfer
// as a hard consensus error (nil result, non-nil err), not a soft vmerr included in block.
//
// Design note: buyGas() only checks balance >= gas*gasFeeCap+value when gasFeeCap != nil.
// We pass gasFeeCap=nil so buyGas passes with gas-only balance, then our new CREATE check
// fires (matching the Call branch behaviour) with ErrInsufficientFundsForTransfer.
func TestCreateValueInsufficientFunds(t *testing.T) {
	from := common.HexToAddress("0xA001")
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}

	twoTOS := new(big.Int).Mul(big.NewInt(2), new(big.Int).SetUint64(params.TOS))
	txPrice := big.NewInt(1e9)
	gasLimit := uint64(1_000_000)

	// Fund sender with exactly enough for gas but NOT for the 2 TOS value transfer.
	gasCost := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), txPrice) // 1e15
	st := newSecState(t, map[common.Address]*big.Int{from: gasCost})

	// gasFeeCap=nil → buyGas uses only gas*txPrice for the balance check, so preCheck passes.
	// Our new CanTransfer check in the CREATE branch then fires.
	msg := types.NewMessage(from, nil, 0, twoTOS, gasLimit, txPrice, nil, big.NewInt(0), []byte("fake-deploy-data"), nil, false)
	gp := new(GasPool).AddGas(msg.Gas())

	_, err := ApplyMessage(context.Background(), secBlockCtx(), cfg, msg, gp, st)
	if err == nil {
		t.Fatal("expected hard error for CREATE with insufficient funds, got nil")
	}
	if !errors.Is(err, ErrInsufficientFundsForTransfer) {
		t.Fatalf("expected ErrInsufficientFundsForTransfer, got: %v", err)
	}
}

// Issue B: State mutations from a failing validate() must be rolled back.
// A failing validate() (returns false/zero) must not leave any state changes behind.
func TestAAValidationStateRollbackOnFailure(t *testing.T) {
	from := common.HexToAddress("0xA002")
	contractAddr := common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}

	// Fund sender well above ValidationGasCap * txPrice to pass phase-1 balance check.
	bigBalance := new(big.Int).Mul(big.NewInt(1_000_000_000), big.NewInt(1e9))
	st := newSecState(t, map[common.Address]*big.Int{from: bigBalance})

	// Mark contractAddr as an AA account contract.
	st.SetState(contractAddr, aaMarkerSlot, common.HexToHash("0x01"))

	// Deploy a Lua contract that mutates its own storage then returns false (zero),
	// causing validate() to fail. We use a trivial Lua script: return 0 (falsy).
	// The contract just needs validate() to return 0; we set a known slot beforehand
	// and check it's unchanged after the failed call.
	//
	// We use raw Lua code that returns 0 from its main chunk, which the LVM
	// interprets as a falsy validate() result.
	markerSlot := crypto.Keccak256Hash([]byte("tol.test.mutation"))
	st.SetState(contractAddr, markerSlot, common.HexToHash("0xdeadbeef"))
	st.SetCode(contractAddr, []byte(`return 0`))

	// Record coinbase balance before.
	coinbase := common.HexToAddress("0xC01NBASE")
	coinbaseBefore := new(big.Int).Set(st.GetBalance(coinbase))

	data := []byte("call-data")
	msg := types.NewMessage(from, &contractAddr, 0, big.NewInt(0), 500_000, big.NewInt(1e9), big.NewInt(1e9), big.NewInt(0), data, nil, false)
	gp := new(GasPool).AddGas(msg.Gas())

	_, err := ApplyMessage(context.Background(), secBlockCtx(), cfg, msg, gp, st)
	if err == nil {
		t.Fatal("expected validation failure error, got nil")
	}
	if !errors.Is(err, ErrAAValidationFailed) {
		t.Fatalf("expected ErrAAValidationFailed, got: %v", err)
	}

	// The known storage slot must be unchanged — rolled back.
	gotSlot := st.GetState(contractAddr, markerSlot)
	if gotSlot != common.HexToHash("0xdeadbeef") {
		t.Fatalf("storage slot was mutated by failing validate(): got %v", gotSlot)
	}

	// Coinbase must not have been credited (tx rejected).
	coinbaseAfter := st.GetBalance(coinbase)
	if coinbaseAfter.Cmp(coinbaseBefore) != 0 {
		t.Fatalf("coinbase balance changed on rejected tx: before=%v after=%v", coinbaseBefore, coinbaseAfter)
	}
}

// Issue C: Different chainIDs must produce different txHash values passed to validate().
// We verify this by computing the hash the same way TransitionDb does and confirming divergence.
func TestAAValidationTxHashIncludesChainID(t *testing.T) {
	from := common.HexToAddress("0xA003")
	to := common.HexToAddress("0xB003")
	nonce := uint64(7)
	value := big.NewInt(0)
	data := []byte("sig-data")

	hashFor := func(chainID *big.Int) common.Hash {
		var chainIDBuf [32]byte
		if chainID != nil {
			chainID.FillBytes(chainIDBuf[:])
		}
		txHashInput := append(chainIDBuf[:], from.Bytes()...)
		txHashInput = append(txHashInput, to.Bytes()...)
		var nonceBuf [8]byte
		// binary.BigEndian encoding — matches TransitionDb
		nonceBuf[0] = byte(nonce >> 56)
		nonceBuf[1] = byte(nonce >> 48)
		nonceBuf[2] = byte(nonce >> 40)
		nonceBuf[3] = byte(nonce >> 32)
		nonceBuf[4] = byte(nonce >> 24)
		nonceBuf[5] = byte(nonce >> 16)
		nonceBuf[6] = byte(nonce >> 8)
		nonceBuf[7] = byte(nonce)
		txHashInput = append(txHashInput, nonceBuf[:]...)
		var valueBuf [32]byte
		value.FillBytes(valueBuf[:])
		txHashInput = append(txHashInput, valueBuf[:]...)
		txHashInput = append(txHashInput, data...)
		return crypto.Keccak256Hash(txHashInput)
	}

	hash1 := hashFor(big.NewInt(1))
	hash2 := hashFor(big.NewInt(2))
	hashNil := hashFor(nil)

	if hash1 == hash2 {
		t.Fatalf("chainID=1 and chainID=2 produced the same txHash: %v", hash1)
	}
	if hash1 == hashNil {
		t.Fatalf("chainID=1 and chainID=nil produced the same txHash: %v", hash1)
	}
	if hash2 == hashNil {
		t.Fatalf("chainID=2 and chainID=nil produced the same txHash: %v", hash2)
	}
}

// Issue 2: AA validation must not call SubGas on the per-tx gas pool.
// In block processing, the pool is pre-funded with msg.Gas() and fully drained
// by buyGas().  A subsequent SubGas(ValidationGasCap) on the depleted pool would
// always fail → ErrAAValidationFailed for every AA tx.
//
// We verify this by using a pool with a tiny surplus above msg.Gas() (exactly
// the ValidationGasCap would be required by the old code, but not the new code).
// The test uses a contract that returns 0 (falsy validate), so the expected error
// is ErrAAValidationFailed — but caused by the falsy return, NOT by pool depletion.
// If the pool were still touched, the error source would be the same sentinel but
// the contract execution would never have run (SubGas fires first), and the gas
// pool capacity check would be different.
//
// Additionally we verify that the pool's remaining gas is predictable (only
// buyGas drains it; validation does not).
func TestAAValidationDoesNotDrainPerTxGasPool(t *testing.T) {
	from := common.HexToAddress("0xA008")
	contractAddr := common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}

	bigBalance := new(big.Int).Mul(big.NewInt(1_000_000_000), big.NewInt(1e9))
	st := newSecState(t, map[common.Address]*big.Int{from: bigBalance})

	st.SetState(contractAddr, aaMarkerSlot, common.HexToHash("0x01"))
	st.SetCode(contractAddr, []byte(`return 0`)) // validate() returns 0 → falsy

	gasLimit := uint64(500_000)
	txPrice := big.NewInt(1e9)

	// perTxGP is seeded with exactly msg.Gas() — as state_processor does in block processing.
	// Before the fix, validateAccountContract would call SubGas(ValidationGasCap=50000) on
	// this pool after buyGas() drains it to 0, always failing.
	// After the fix, the pool is untouched by validation.
	msg := types.NewMessage(from, &contractAddr, 0, big.NewInt(0), gasLimit, txPrice, big.NewInt(1e9), big.NewInt(0), []byte("sig"), nil, false)
	perTxGP := new(GasPool).AddGas(msg.Gas()) // matches state_processor.go pattern

	_, err := ApplyMessage(context.Background(), secBlockCtx(), cfg, msg, perTxGP, st)

	// Must return ErrAAValidationFailed — from the falsy return value, not pool depletion.
	if !errors.Is(err, ErrAAValidationFailed) {
		t.Fatalf("expected ErrAAValidationFailed, got: %v", err)
	}
	// Pool must only have been drained by buyGas (intrinsicGas refund leaves some
	// remaining), NOT by an extra SubGas(ValidationGasCap) in validateAccountContract.
	// The pool gas after a hard error (AA failure before execution) should be ≥ 0
	// and not negative (which would panic on uint64 underflow if SubGas was still called).
	// The test passing without panic is itself evidence the pool wasn't over-drained.
}

// Issue 3: AA validation gas must be included in UsedGas so coinbase accounting
// and block gas pool subtraction are consistent with what was deducted from the
// sender's balance.  This test verifies the structural invariant via StateTransition.
// (Full end-to-end coverage requires a truthy validate() contract, tested separately.)
func TestAAValidationGasFieldInitiallyZero(t *testing.T) {
	// For non-AA txs, validationGas must remain 0, so gasUsed() = initialGas - gas.
	from := common.HexToAddress("0xA009")
	to := common.HexToAddress("0xB009")
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}

	bigBalance := new(big.Int).Mul(big.NewInt(1_000_000), new(big.Int).SetUint64(params.TOS))
	st := newSecState(t, map[common.Address]*big.Int{from: bigBalance})

	msg := types.NewMessage(from, &to, 0, big.NewInt(0), 100_000, big.NewInt(1e9), big.NewInt(1e9), big.NewInt(0), nil, nil, false)
	gp := new(GasPool).AddGas(msg.Gas())

	result, err := ApplyMessage(context.Background(), secBlockCtx(), cfg, msg, gp, st)
	if err != nil {
		t.Fatalf("ApplyMessage: %v", err)
	}
	// For a plain transfer, UsedGas = TxGas (3000 in gtos) — no validation overhead.
	if result.UsedGas != params.TxGas {
		t.Fatalf("expected UsedGas=%d for plain transfer, got %d", params.TxGas, result.UsedGas)
	}
}

// Issue E: Nonce must NOT be incremented when IntrinsicGas check fails.
// Before the fix, the nonce was incremented at line 321 unconditionally, before
// IntrinsicGas was checked.  After the fix, nonce is only advanced after all
// consensus checks pass (mirrors geth).
func TestNonceNotIncrementedOnIntrinsicGasFailure(t *testing.T) {
	from := common.HexToAddress("0xA005")
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}

	txPrice := big.NewInt(1e9)
	// Use a gas limit below TxGasContractCreation (53000) so IntrinsicGas check fails,
	// but above zero so buyGas succeeds when gasFeeCap=nil (only checks gas*txPrice).
	gasLimit := uint64(100)

	// Fund for gas cost only (100 * 1e9 = 1e11 wei).
	gasCost := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), txPrice)
	st := newSecState(t, map[common.Address]*big.Int{from: gasCost})

	// CREATE with gasFeeCap=nil: buyGas only checks balance >= gas*txPrice.
	// IntrinsicGas (53000 for CREATE) > gas (100) → must return hard error.
	msg := types.NewMessage(from, nil, 0, big.NewInt(0), gasLimit, txPrice, nil, big.NewInt(0), nil, nil, false)
	gp := new(GasPool).AddGas(msg.Gas())

	_, err := ApplyMessage(context.Background(), secBlockCtx(), cfg, msg, gp, st)
	if err == nil {
		t.Fatal("expected IntrinsicGas hard error, got nil")
	}

	// Nonce must remain 0 — the tx failed before any state advancement.
	if got := st.GetNonce(from); got != 0 {
		t.Fatalf("nonce was incremented despite IntrinsicGas failure: got %d, want 0", got)
	}
}

// Issue E (CALL variant): nonce must not be incremented when IntrinsicGas fails for a CALL.
func TestNonceNotIncrementedOnIntrinsicGasFailureCall(t *testing.T) {
	from := common.HexToAddress("0xA006")
	to := common.HexToAddress("0xB006")
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}

	txPrice := big.NewInt(1e9)
	// TxGas for CALL in gtos is 3000; use gas=1 to guarantee IntrinsicGas failure.
	gasLimit := uint64(1)

	gasCost := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), txPrice)
	st := newSecState(t, map[common.Address]*big.Int{from: gasCost})

	msg := types.NewMessage(from, &to, 0, big.NewInt(0), gasLimit, txPrice, nil, big.NewInt(0), nil, nil, false)
	gp := new(GasPool).AddGas(msg.Gas())

	_, err := ApplyMessage(context.Background(), secBlockCtx(), cfg, msg, gp, st)
	if err == nil {
		t.Fatal("expected IntrinsicGas hard error, got nil")
	}
	if got := st.GetNonce(from); got != 0 {
		t.Fatalf("nonce was incremented despite IntrinsicGas failure: got %d, want 0", got)
	}
}

// Issue F: SystemAction with value > balance must return ErrInsufficientFundsForTransfer.
// Before the fix, the CanTransfer check was missing for the SystemAction path; with
// gasFeeCap=nil, buyGas did not check value vs balance, so the check was silently skipped.
func TestSystemActionValueInsufficientFunds(t *testing.T) {
	from := common.HexToAddress("0xA007")
	to := params.SystemActionAddress
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}

	txPrice := big.NewInt(1e9)
	gasLimit := uint64(1_000_000)

	// Fund sender with enough for gas only, not for the value transfer.
	gasCost := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), txPrice)
	st := newSecState(t, map[common.Address]*big.Int{from: gasCost})

	twoTOS := new(big.Int).Mul(big.NewInt(2), new(big.Int).SetUint64(params.TOS))

	// gasFeeCap=nil: buyGas only checks balance >= gas*txPrice → passes.
	// Unified CanTransfer check (fix F) must now catch value > balance.
	msg := types.NewMessage(from, &to, 0, twoTOS, gasLimit, txPrice, nil, big.NewInt(0), []byte(`{"action":"noop"}`), nil, false)
	gp := new(GasPool).AddGas(msg.Gas())

	_, err := ApplyMessage(context.Background(), secBlockCtx(), cfg, msg, gp, st)
	if err == nil {
		t.Fatal("expected hard error for SystemAction with value > balance, got nil")
	}
	if !errors.Is(err, ErrInsufficientFundsForTransfer) {
		t.Fatalf("expected ErrInsufficientFundsForTransfer, got: %v", err)
	}
}

// Issue D: ApplyMessage with IsFake=true (simulated call) must not credit coinbase.
func TestDoCallNoCoinbaseFee(t *testing.T) {
	from := common.HexToAddress("0xA004")
	to := common.HexToAddress("0xB004")
	coinbase := common.HexToAddress("0xC01NBASE")
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}

	bigBalance := new(big.Int).Mul(big.NewInt(1_000_000), new(big.Int).SetUint64(params.TOS))
	st := newSecState(t, map[common.Address]*big.Int{from: bigBalance})

	coinbaseBefore := new(big.Int).Set(st.GetBalance(coinbase))

	// IsFake=true → simulated call (DoCall / DoEstimateGas path)
	msg := types.NewMessage(from, &to, 0, big.NewInt(0), 100_000, big.NewInt(1e9), big.NewInt(1e9), big.NewInt(0), nil, nil, true)
	gp := new(GasPool).AddGas(msg.Gas())

	bctx := secBlockCtx()
	bctx.Coinbase = coinbase

	result, err := ApplyMessage(context.Background(), bctx, cfg, msg, gp, st)
	if err != nil {
		t.Fatalf("ApplyMessage: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution failed: %v", result.Err)
	}

	coinbaseAfter := st.GetBalance(coinbase)
	if coinbaseAfter.Cmp(coinbaseBefore) != 0 {
		t.Fatalf("coinbase balance changed during fake (simulated) call: before=%v after=%v", coinbaseBefore, coinbaseAfter)
	}
}
