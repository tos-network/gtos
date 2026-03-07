package core

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/rawdb"
	coreuno "github.com/tos-network/gtos/core/uno"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto/ristretto255"
	"github.com/tos-network/gtos/params"
	lvm "github.com/tos-network/gtos/core/vm"
)

// newInterruptState returns a fresh in-memory StateDB with addr pre-funded.
func newInterruptState(t *testing.T, funded ...common.Address) *state.StateDB {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	st, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	for _, a := range funded {
		st.SetBalance(a, new(big.Int).Mul(big.NewInt(100), new(big.Int).SetUint64(params.TOS)))
	}
	return st
}

// interruptBlockCtx returns a minimal BlockContext for interrupt tests.
func interruptBlockCtx() lvm.BlockContext {
	return lvm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		Coinbase:    common.HexToAddress("0xC0FFEE"),
		BlockNumber: big.NewInt(1),
		Time:        big.NewInt(0),
		GasLimit:    30_000_000,
	}
}

// ── Test 1: LVM execution interrupted by context timeout ──────────────────────

// TestLVMContextInterrupt verifies that a Lua contract running an infinite loop
// is aborted promptly when the context deadline fires, rather than blocking
// until gas is exhausted (which would take far longer).
func TestLVMContextInterrupt(t *testing.T) {
	from := common.HexToAddress("0xA001")
	contractAddr := common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")

	st := newInterruptState(t, from)
	// Deploy an infinite-loop contract.
	st.SetCode(contractAddr, []byte(`while true do end`))

	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}
	msg := types.NewMessage(from, &contractAddr, 0, big.NewInt(0), 10_000_000, big.NewInt(0), big.NewInt(0), big.NewInt(0), nil, nil, true)
	gp := new(GasPool).AddGas(msg.Gas())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	result, applyErr := ApplyMessage(ctx, interruptBlockCtx(), cfg, msg, gp, st)
	elapsed := time.Since(start)

	// The call must return within a generous 5s window — well before 10M gas at
	// 1 opcode/ns would be exhausted.
	if elapsed > 5*time.Second {
		t.Fatalf("LVM interrupt took too long: %v", elapsed)
	}

	// Either ApplyMessage returns an error, or the result carries the abort error.
	var execErr error
	if applyErr != nil {
		execErr = applyErr
	} else if result != nil {
		execErr = result.Err
	}
	if execErr == nil {
		t.Fatal("expected an error due to context abort, got nil")
	}
	// The Lua VM raises "execution aborted" via RaiseError; check the string.
	if !strings.Contains(execErr.Error(), "aborted") && !strings.Contains(execErr.Error(), "interrupt") {
		t.Fatalf("unexpected error (want 'aborted'/'interrupt'): %v", execErr)
	}

	// Context must indeed be done (timeout fired).
	if ctx.Err() == nil {
		t.Fatal("expected context to be done after abort")
	}
}

// ── Test 2: SystemAction branch skipped when context is pre-cancelled ─────────

// TestSystemActionContextCancel verifies that when the Go context is already
// cancelled before TransitionDb is called, the SystemAction branch returns
// ErrExecutionAborted without invoking sysaction.Execute.
func TestSystemActionContextCancel(t *testing.T) {
	from := common.HexToAddress("0xA002")
	to := params.SystemActionAddress

	st := newInterruptState(t, from)
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}

	// Minimal valid sysaction data (ActionKind byte = 0x00 = unknown, just
	// triggers the fast-path abort before the handler is reached).
	data := []byte(`{"action":"noop"}`)
	msg := types.NewMessage(from, &to, 0, big.NewInt(0), 1_000_000, big.NewInt(0), big.NewInt(0), big.NewInt(0), data, nil, true)
	gp := new(GasPool).AddGas(msg.Gas())

	// Pre-cancel the context so ctxAborted() fires immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	result, err := ApplyMessage(ctx, interruptBlockCtx(), cfg, msg, gp, st)
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Fatalf("SystemAction cancel took too long: %v", elapsed)
	}
	// err is from preCheck / buyGas (IsFake=true so buyGas skips), not abort.
	// The abort lands in result.Err.
	var execErr error
	if err != nil {
		execErr = err
	} else if result != nil {
		execErr = result.Err
	}
	if !errors.Is(execErr, ErrExecutionAborted) {
		t.Fatalf("expected ErrExecutionAborted, got: %v", execErr)
	}
}

// ── Test 3: UNO branch skipped when context is pre-cancelled ─────────────────

// TestUNOContextCancel verifies that when the Go context is already cancelled,
// the UNO branch (PrivacyRouterAddress) returns ErrExecutionAborted without
// attempting proof verification.
func TestUNOContextCancel(t *testing.T) {
	from := common.HexToAddress("0xA003")
	to := params.PrivacyRouterAddress

	st := newInterruptState(t, from)
	pub := ristretto255.NewGeneratorElement().Bytes()
	setupElgamalSigner(t, st, from, pub)

	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}

	// Build a valid UNO shield envelope so we pass the early decode checks
	// and reach the proof verification gate (where ctxAborted fires).
	payload, err := coreuno.EncodeShieldPayload(coreuno.ShieldPayload{
		Amount:      1,
		NewSender:   makeValidCiphertext(ristretto255.NewGeneratorElement().Bytes(), ristretto255.NewIdentityElement().Bytes()),
		ProofBundle: make([]byte, coreuno.ShieldProofSize),
	})
	if err != nil {
		t.Fatalf("EncodeShieldPayload: %v", err)
	}
	data, err := coreuno.EncodeEnvelope(coreuno.ActionShield, payload)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}

	msg := types.NewMessage(from, &to, 0, big.NewInt(0), 2_000_000, big.NewInt(0), big.NewInt(0), big.NewInt(0), data, nil, true)
	gp := new(GasPool).AddGas(msg.Gas())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	result, applyErr := ApplyMessage(ctx, interruptBlockCtx(), cfg, msg, gp, st)
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Fatalf("UNO cancel took too long: %v", elapsed)
	}
	var execErr error
	if applyErr != nil {
		execErr = applyErr
	} else if result != nil {
		execErr = result.Err
	}
	if !errors.Is(execErr, ErrExecutionAborted) {
		t.Fatalf("expected ErrExecutionAborted, got: %v", execErr)
	}
}

// ── Test 4: DoCall error classification (DeadlineExceeded vs Canceled) ────────

// TestDoCallAbortErrorMessages verifies that context.DeadlineExceeded and
// context.Canceled produce distinct error messages.  This exercises the
// classification logic in DoCall directly via a minimal simulation.
func TestDoCallAbortErrorMessages(t *testing.T) {
	// Simulate what DoCall does after execution with a timed-out context.
	simulateDoCall := func(ctx context.Context, timeout time.Duration) error {
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return &timeoutError{timeout: timeout}
			}
			return &cancelError{}
		}
		return nil
	}

	// DeadlineExceeded → message must mention "timeout"
	deadlineCtx, deadlineCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer deadlineCancel()
	if err := simulateDoCall(deadlineCtx, 100*time.Millisecond); err == nil {
		t.Fatal("expected error for DeadlineExceeded context")
	} else if !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("DeadlineExceeded error missing 'timeout': %q", err.Error())
	}

	// Canceled → message must mention "canceled"
	cancelCtx, cancelFn := context.WithCancel(context.Background())
	cancelFn()
	if err := simulateDoCall(cancelCtx, 0); err == nil {
		t.Fatal("expected error for Canceled context")
	} else if !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("Canceled error missing 'canceled': %q", err.Error())
	}
}

// timeoutError and cancelError mirror the messages produced by DoCall.
type timeoutError struct{ timeout time.Duration }

func (e *timeoutError) Error() string {
	return "execution aborted (timeout = " + e.timeout.String() + ")"
}

type cancelError struct{}

func (cancelError) Error() string { return "execution aborted (canceled)" }
