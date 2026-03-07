package dpos

import (
	"bytes"
	"crypto/ed25519"
	"math/big"
	"sort"
	"testing"
	"time"

	"github.com/tos-network/gtos/accounts"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

func testEd25519Key(seed byte) (ed25519.PublicKey, ed25519.PrivateKey, common.Address) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, common.BytesToAddress(crypto.Keccak256(pub))
}

func signTestHeader(t *testing.T, d *DPoS, header *types.Header, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	sig := ed25519.Sign(priv, d.SealHash(header).Bytes())
	seal := make([]byte, 0, ed25519.PublicKeySize+ed25519.SignatureSize)
	seal = append(seal, pub...)
	seal = append(seal, sig...)
	copy(header.Extra[len(header.Extra)-extraSealEd25519:], seal)
}

// ── New / Config validation ──────────────────────────────────────────────────

// TestNewInvalidConfig verifies that New() returns error for invalid configs (R2-C4).
func TestNewInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		config params.DPoSConfig
	}{
		{"epoch=0", params.DPoSConfig{Epoch: 0, PeriodMs: 3000, MaxValidators: 21, TurnLength: params.DPoSTurnLength}},
		{"periodMs=0", params.DPoSConfig{Epoch: 208, PeriodMs: 0, MaxValidators: 21, TurnLength: params.DPoSTurnLength}},
		{"maxValidators=0", params.DPoSConfig{Epoch: 208, PeriodMs: 3000, MaxValidators: 0, TurnLength: params.DPoSTurnLength}},
	}
	for _, tt := range tests {
		cfg := tt.config
		_, err := New(&cfg, nil)
		if err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
}

// ── Snapshot ─────────────────────────────────────────────────────────────────

// TestEmptyValidatorSet verifies that newSnapshot rejects an empty validator slice.
func TestEmptyValidatorSet(t *testing.T) {
	d := NewFaker()
	_, err := newSnapshot(d.config, d.signatures, 0, common.Hash{}, nil, 0, d.config.TargetBlockPeriodMs())
	if err == nil {
		t.Fatal("expected error for empty validator set")
	}
}

// TestApplyEmptyHeadersReturnsCopy verifies CF-1: apply(nil) returns a fresh copy,
// not the original pointer, so callers cannot mutate a shared LRU-cached snapshot.
func TestApplyEmptyHeadersReturnsCopy(t *testing.T) {
	d := NewFaker()
	addrs := []common.Address{{0x01}, {0x02}}
	snap, err := newSnapshot(d.config, d.signatures, 0, common.Hash{1}, addrs, 0, d.config.TargetBlockPeriodMs())
	if err != nil {
		t.Fatalf("newSnapshot: %v", err)
	}
	result, err := snap.apply(nil)
	if err != nil {
		t.Fatalf("apply(nil): %v", err)
	}
	if result == snap {
		t.Fatal("apply(nil) returned the original pointer; expected a copy")
	}
	result.FinalizedNumber = 999
	if snap.FinalizedNumber != 0 {
		t.Errorf("mutating result affected original: FinalizedNumber = %d", snap.FinalizedNumber)
	}
}

// TestSnapshotDeepCopy verifies that mutating an applied snapshot does not
// corrupt the original cached snapshot (data-race guard).
func TestSnapshotDeepCopy(t *testing.T) {
	d := NewFaker()
	addrs := []common.Address{{0x01}, {0x02}}
	snap, err := newSnapshot(d.config, d.signatures, 0, common.Hash{1}, addrs, 0, d.config.TargetBlockPeriodMs())
	if err != nil {
		t.Fatalf("newSnapshot: %v", err)
	}
	cpy := snap.copy()

	// Mutate copy; original must be unchanged.
	cpy.Validators[0] = common.Address{0xFF}
	if snap.Validators[0] == (common.Address{0xFF}) {
		t.Error("copy mutation affected original Validators slice")
	}
	cpy.Recents[99] = common.Address{0xFF}
	if _, ok := snap.Recents[99]; ok {
		t.Error("copy mutation affected original Recents map")
	}
}

// ── Extra data parsing ────────────────────────────────────────────────────────

// TestGenesisExtraParse tests parseGenesisValidators for various inputs.
func TestGenesisExtraParse(t *testing.T) {
	vanity := make([]byte, extraVanity)

	// Empty payload — zero validators allowed by parser (empty slice).
	extra0 := vanity
	out, err := parseGenesisValidators(extra0)
	if err != nil {
		t.Errorf("empty payload: unexpected error %v", err)
	}
	if len(out) != 0 {
		t.Errorf("empty payload: want 0 validators, got %d", len(out))
	}

	// N=1.
	a1 := common.Address{0x01}
	extra1 := append(vanity, a1.Bytes()...)
	out, err = parseGenesisValidators(extra1)
	if err != nil {
		t.Fatalf("N=1: %v", err)
	}
	if len(out) != 1 || out[0] != a1 {
		t.Errorf("N=1: got %v", out)
	}

	// N=21 (max).
	var extra21 []byte
	extra21 = append(extra21, vanity...)
	for i := 0; i < 21; i++ {
		extra21 = append(extra21, common.Address{byte(i + 1)}.Bytes()...)
	}
	out, err = parseGenesisValidators(extra21)
	if err != nil {
		t.Fatalf("N=21: %v", err)
	}
	if len(out) != 21 {
		t.Errorf("N=21: got %d validators", len(out))
	}

	// Bad alignment (19 bytes = not multiple of 20).
	badExtra := append(vanity, make([]byte, 19)...)
	if _, err := parseGenesisValidators(badExtra); err == nil {
		t.Error("bad alignment: expected error")
	}

	// Too short (less than extraVanity).
	if _, err := parseGenesisValidators(make([]byte, 10)); err == nil {
		t.Error("too short: expected error")
	}
}

// TestEpochExtraParse tests parseEpochValidators for various inputs.
func TestEpochExtraParse(t *testing.T) {
	vanity := make([]byte, extraVanity)
	seal := make([]byte, extraSealEd25519)

	// N=1.
	a1 := common.Address{0x01}
	extra := append(append(vanity, a1.Bytes()...), seal...)
	d := NewFaker()
	out, err := parseEpochValidators(extra, d.config, false)
	if err != nil {
		t.Fatalf("N=1: %v", err)
	}
	if len(out) != 1 || out[0] != a1 {
		t.Errorf("N=1: got %v", out)
	}

	// Missing seal (too short).
	if _, err := parseEpochValidators(append(vanity, a1.Bytes()...), d.config, false); err == nil {
		t.Error("missing seal: expected error")
	}

	// Bad alignment: vanity + 19 bytes + seal.
	badPayload := append(append(vanity, make([]byte, 19)...), seal...)
	if _, err := parseEpochValidators(badPayload, d.config, false); err == nil {
		t.Error("bad alignment: expected error")
	}
}

// ── SealHash / ecrecover ──────────────────────────────────────────────────────

// TestSealHashRoundTrip verifies that recoverHeaderSigner(sign(SealHash(h))) == signer.
func TestSealHashRoundTrip(t *testing.T) {
	pub, priv, signer := testEd25519Key(0x01)

	header := &types.Header{
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(2),
		Extra:      make([]byte, extraVanity+extraSealEd25519),
		Coinbase:   signer,
		Time:       uint64(time.Now().UnixMilli()),
	}

	d := NewFaker()
	signTestHeader(t, d, header, pub, priv)

	recovered, err := recoverHeaderSigner(d.config, header, d.signatures)
	if err != nil {
		t.Fatalf("recoverHeaderSigner: %v", err)
	}
	if recovered != signer {
		t.Errorf("recoverHeaderSigner: want %v, got %v", signer, recovered)
	}
}

// ── verifySeal ────────────────────────────────────────────────────────────────

// TestCoinbaseMismatch verifies that verifySeal rejects a header where
// the recovered signer differs from header.Coinbase.
func TestCoinbaseMismatch(t *testing.T) {
	pub1, priv1, signer1 := testEd25519Key(0x02)
	_, _, signer2 := testEd25519Key(0x03)

	addrs := []common.Address{signer1, signer2}
	d := NewFaker()
	snap, _ := newSnapshot(d.config, d.signatures, 0, common.Hash{}, addrs, 0, d.config.TargetBlockPeriodMs())

	header := &types.Header{
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		Coinbase:   signer2, // deliberately wrong: will sign with key1
		Extra:      make([]byte, extraVanity+extraSealEd25519),
		Time:       uint64(time.Now().UnixMilli()),
	}
	signTestHeader(t, d, header, pub1, priv1)

	if err := d.verifySeal(snap, header); err != errInvalidCoinbase {
		t.Errorf("want errInvalidCoinbase, got %v", err)
	}
}

// TestRecentlySigned verifies grouped-turn recency:
// a validator may sign its own full 16-slot turn group, but is blocked from
// entering the next turn group too early.
func TestRecentlySigned(t *testing.T) {
	pub, priv, signer := testEd25519Key(0x04)

	addrs := []common.Address{signer, {0x02}, {0x03}}
	d := NewFaker()

	const genesisTime = uint64(1_000_000) // arbitrary fixed ms
	const periodMs = uint64(360)
	snap, _ := newSnapshot(d.config, d.signatures, 0, common.Hash{}, addrs, genesisTime, periodMs)

	header := &types.Header{
		Number:     big.NewInt(17),
		Difficulty: big.NewInt(2),
		Coinbase:   signer,
		Extra:      make([]byte, extraVanity+extraSealEd25519),
		Time:       genesisTime + 17*periodMs, // slot 17
	}
	signTestHeader(t, d, header, pub, priv)

	// Allowed: consume the full current turn group.
	for slot := uint64(1); slot <= d.config.TurnLength; slot++ {
		snap.Recents[slot] = signer
	}

	if err := d.verifySeal(snap, header); err != errRecentlySigned {
		t.Errorf("want errRecentlySigned, got %v", err)
	}
}

func TestFinalizedValidatorSetHashRestoresFromDB(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	want := common.HexToHash("0x1234")
	rawdb.WriteFinalizedValidatorSetHash(db, want)
	rawdb.WriteFinalizedBlockHash(db, common.HexToHash("0x1"))

	d, err := New(&params.DPoSConfig{
		Epoch:          208,
		MaxValidators:  21,
		PeriodMs:       3000,
		TurnLength:     params.DPoSTurnLength,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
	}, db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if have := d.FinalizedValidatorSetHash(); have != want {
		t.Fatalf("FinalizedValidatorSetHash mismatch: have %s want %s", have.Hex(), want.Hex())
	}

	rawdb.WriteFinalizedBlockHash(db, common.Hash{})
	if have := d.FinalizedValidatorSetHash(); have != (common.Hash{}) {
		t.Fatalf("FinalizedValidatorSetHash should clear when finalized head is reset, have %s", have.Hex())
	}
}

func TestOnCanonicalBlockCommitsStagedFinality(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	d, err := New(&params.DPoSConfig{
		Epoch:          208,
		MaxValidators:  21,
		PeriodMs:       3000,
		TurnLength:     params.DPoSTurnLength,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
	}, db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	finalizedHeader := &types.Header{Number: big.NewInt(10), Extra: make([]byte, extraVanity+extraSealEd25519)}
	rawdb.WriteHeader(db, finalizedHeader)

	carrier := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(11)})
	other := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(12)})
	vsHash := common.HexToHash("0xbeef")

	var committed *types.Header
	d.SetVoteCallbacks(nil, nil, func(h *types.Header) {
		committed = h
		rawdb.WriteFinalizedBlockHash(db, h.Hash())
	}, big.NewInt(1))
	d.stageFinalityResult(carrier.Hash(), finalizedHeader.Number.Uint64(), finalizedHeader.Hash(), vsHash)

	d.OnCanonicalBlock(other)
	if committed != nil {
		t.Fatal("unexpected finality commit for unrelated canonical block")
	}
	if got := rawdb.ReadFinalizedBlockHash(db); got != (common.Hash{}) {
		t.Fatalf("unexpected finalized block hash before carrier commit: %s", got.Hex())
	}

	d.OnCanonicalBlock(carrier)
	if committed == nil || committed.Hash() != finalizedHeader.Hash() {
		t.Fatalf("finalized header mismatch: have=%v want=%s", committed, finalizedHeader.Hash().Hex())
	}
	if got := rawdb.ReadFinalizedBlockHash(db); got != finalizedHeader.Hash() {
		t.Fatalf("finalized block hash mismatch: have %s want %s", got.Hex(), finalizedHeader.Hash().Hex())
	}
	if got := rawdb.ReadFinalizedValidatorSetHash(db); got != vsHash {
		t.Fatalf("finalized validatorSetHash mismatch: have %s want %s", got.Hex(), vsHash.Hex())
	}
}

// ── nil-db (NewFaker) ─────────────────────────────────────────────────────────

// TestNilDbFaker verifies that NewFaker() snapshot() does not panic
// when db is nil (R2-C3: all store() calls guarded with "if d.db != nil").
func TestNilDbFaker(t *testing.T) {
	d := NewFaker()
	_, _, signer := testEd25519Key(0x05)

	// Build a minimal chain reader that returns a genesis with one validator.
	genesis := &types.Header{
		Number: big.NewInt(0),
		Extra:  append(make([]byte, extraVanity), signer.Bytes()...),
	}
	chain := &fakeChainReader{headers: map[uint64]*types.Header{0: genesis}}

	snap, err := d.snapshot(chain, 0, genesis.Hash(), nil)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(snap.Validators) != 1 || snap.Validators[0] != signer {
		t.Errorf("unexpected validators: %v", snap.Validators)
	}
}

// ── Future block ──────────────────────────────────────────────────────────────

// TestAllowedFutureBlock verifies the clock-skew grace period (R2-M1).
func TestAllowedFutureBlock(t *testing.T) {
	d := NewFaker()
	chain := &fakeChainReader{}

	now := uint64(time.Now().UnixMilli())
	grace := 3 * d.config.TargetBlockPeriodMs()

	// Slightly below grace window: allowed.
	hAllowed := &types.Header{
		Number:     big.NewInt(1),
		Time:       now + grace - 100,
		Difficulty: diffInTurn,
		Extra:      make([]byte, extraVanity+extraSealEd25519),
		UncleHash:  types.EmptyUncleHash,
	}
	if err := d.verifyHeader(chain, hAllowed, nil); err == consensus.ErrFutureBlock {
		t.Error("block within future-block grace should be allowed, got ErrFutureBlock")
	}

	// Slightly above grace window: rejected.
	hRejected := &types.Header{
		Number:     big.NewInt(1),
		Time:       now + grace + 100,
		Difficulty: diffInTurn,
		Extra:      make([]byte, extraVanity+extraSealEd25519),
		UncleHash:  types.EmptyUncleHash,
	}
	if err := d.verifyHeader(chain, hRejected, nil); err != consensus.ErrFutureBlock {
		t.Errorf("block above future-block grace should be rejected as ErrFutureBlock, got %v", err)
	}
}

// ── vote signing helpers ─────────────────────────────────────────────────────

func TestVoteSigningLifecycle(t *testing.T) {
	d := NewFaker()
	if d.CanSignVotes() {
		t.Fatal("unexpected vote signer readiness before Authorize")
	}

	digest := crypto.Keccak256Hash([]byte("dpos-vote-digest"))
	if _, err := d.SignVote(digest); err == nil {
		t.Fatal("expected SignVote to fail when signer is not configured")
	}

	pub, priv, addr := testEd25519Key(0x06)
	var gotMime string

	d.Authorize(addr, func(_ accounts.Account, mime string, hash []byte) ([]byte, error) {
		gotMime = mime
		sig := ed25519.Sign(priv, hash)
		out := make([]byte, 0, ed25519.PublicKeySize+ed25519.SignatureSize)
		out = append(out, pub...)
		out = append(out, sig...)
		return out, nil
	})

	if !d.CanSignVotes() {
		t.Fatal("expected vote signer readiness after Authorize")
	}

	sig, err := d.SignVote(digest)
	if err != nil {
		t.Fatalf("SignVote: %v", err)
	}
	if gotMime != accounts.MimetypeDPoS {
		t.Fatalf("unexpected MIME type: have %q want %q", gotMime, accounts.MimetypeDPoS)
	}

	if len(sig) != ed25519.PublicKeySize+ed25519.SignatureSize {
		t.Fatalf("unexpected DPoS vote signature length: have %d want %d", len(sig), ed25519.PublicKeySize+ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(sig[:ed25519.PublicKeySize]), digest.Bytes(), sig[ed25519.PublicKeySize:]) {
		t.Fatal("ed25519 vote signature verification failed")
	}
	if recovered := common.BytesToAddress(crypto.Keccak256(sig[:ed25519.PublicKeySize])); recovered != addr {
		t.Fatalf("vote signature signer mismatch: have %s want %s", recovered.Hex(), addr.Hex())
	}
}

func TestOutOfTurnWiggleWindow(t *testing.T) {
	d := NewFaker()
	if got := d.outOfTurnWiggleWindow(); got != maxWiggleTime {
		t.Fatalf("unexpected default wiggle window: have %s want %s", got, maxWiggleTime)
	}

	msCfg := &params.DPoSConfig{
		PeriodMs:       500,
		Epoch:          208,
		MaxValidators:  21,
		TurnLength:     params.DPoSTurnLength,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
	}
	dms, err := New(msCfg, nil)
	if err != nil {
		t.Fatalf("New(msCfg): %v", err)
	}
	if got := dms.outOfTurnWiggleWindow(); got != maxWiggleTime {
		t.Fatalf("unexpected 500ms wiggle window: have %s want %s", got, maxWiggleTime)
	}

	tinyCfg := &params.DPoSConfig{
		PeriodMs:       10,
		Epoch:          208,
		MaxValidators:  21,
		TurnLength:     params.DPoSTurnLength,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
	}
	dtiny, err := New(tinyCfg, nil)
	if err != nil {
		t.Fatalf("New(tinyCfg): %v", err)
	}
	if got := dtiny.outOfTurnWiggleWindow(); got != minWiggleTime {
		t.Fatalf("unexpected min wiggle window: have %s want %s", got, minWiggleTime)
	}
}

func TestPrepareUsesPeriodMs(t *testing.T) {
	signer := common.Address{0x01}
	now := uint64(time.Now().UnixMilli())
	genesis := &types.Header{
		Number: big.NewInt(0),
		Time:   now + 2000,
		Extra:  append(make([]byte, extraVanity), signer.Bytes()...),
	}
	chain := &fakeChainReader{headers: map[uint64]*types.Header{0: genesis}}

	d, err := New(&params.DPoSConfig{
		PeriodMs:       500,
		Epoch:          208,
		MaxValidators:  21,
		TurnLength:     params.DPoSTurnLength,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	header := &types.Header{
		Number:     big.NewInt(1),
		ParentHash: genesis.Hash(),
	}
	if err := d.Prepare(chain, header); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if want := genesis.Time + 500; header.Time != want {
		t.Fatalf("prepared time mismatch: have %d want %d", header.Time, want)
	}
}

// ── inturnSlot / addressAscending ────────────────────────────────────────────

// TestInturnSlot verifies grouped-turn assignment of in-turn validators by slot number.
func TestInturnSlot(t *testing.T) {
	addrs := []common.Address{{0x01}, {0x02}, {0x03}}
	d := NewFaker()
	const genesisTime = uint64(1_000_000)
	const periodMs = uint64(360)
	snap, _ := newSnapshot(d.config, d.signatures, 0, common.Hash{}, addrs, genesisTime, periodMs)

	// Slots are grouped in 16-slot turns:
	// 1..16 -> addrs[0], 17..32 -> addrs[1], 33..48 -> addrs[2].
	cases := map[uint64]common.Address{
		1:  addrs[0],
		16: addrs[0],
		17: addrs[1],
		32: addrs[1],
		33: addrs[2],
		48: addrs[2],
	}
	for slot, want := range cases {
		if !snap.inturnSlot(slot, want) {
			t.Errorf("slot %d: %v should be in-turn", slot, want)
		}
		// Also verify the other validators are out-of-turn at this slot.
		for _, other := range addrs {
			if other == want {
				continue
			}
			if snap.inturnSlot(slot, other) {
				t.Errorf("slot %d: %v should be out-of-turn", slot, other)
			}
		}
	}
}

// TestAddressAscendingSort verifies the addressAscending sort type.
func TestAddressAscendingSort(t *testing.T) {
	in := []common.Address{{0x03}, {0x01}, {0x02}}
	want := []common.Address{{0x01}, {0x02}, {0x03}}

	sort.Sort(addressAscending(in))

	for i, got := range in {
		if got != want[i] {
			t.Errorf("index %d: want %v got %v", i, want[i], got)
		}
	}
}

// ── SLOT_V3 new tests ─────────────────────────────────────────────────────────

// TestSlotBasedRecentsAfterSkip demonstrates grouped-turn recency: a validator
// that has signed fewer than TurnLength times inside the active window remains
// eligible, even when slots are skipped.
func TestSlotBasedRecentsAfterSkip(t *testing.T) {
	pub, priv, signer := testEd25519Key(0x07)

	addrs := []common.Address{signer, {0x02}, {0x03}}
	d := NewFaker()
	const genesisTime = uint64(1_000_000)
	const periodMs = uint64(360)
	snap, _ := newSnapshot(d.config, d.signatures, 0, common.Hash{}, addrs, genesisTime, periodMs)

	// Signer has signed 15 times inside the active window; slot 17 is still allowed.
	for slot := uint64(1); slot < d.config.TurnLength; slot++ {
		snap.Recents[slot] = signer
	}

	header := &types.Header{
		Number:     big.NewInt(17),
		Difficulty: big.NewInt(2),
		Coinbase:   signer,
		Extra:      make([]byte, extraVanity+extraSealEd25519),
		Time:       genesisTime + 17*periodMs, // slot 17
	}
	signTestHeader(t, d, header, pub, priv)

	if err := d.verifySeal(snap, header); err == errRecentlySigned {
		t.Error("validator should remain allowed until it exhausts all 16 appearances in the active window")
	}
}

// TestHeaderSlotHelper tests the headerSlot() helper for edge cases.
func TestHeaderSlotHelper(t *testing.T) {
	// periodMs=0: invalid.
	if _, ok := headerSlot(1000, 0, 0); ok {
		t.Error("periodMs=0 should return ok=false")
	}
	// headerTime < genesisTime: invalid.
	if _, ok := headerSlot(500, 1000, 360); ok {
		t.Error("headerTime < genesisTime should return ok=false")
	}
	// Exact boundary: headerTime == genesisTime → slot 0.
	slot, ok := headerSlot(1000, 1000, 360)
	if !ok || slot != 0 {
		t.Errorf("exact boundary: want slot=0 ok=true; got slot=%d ok=%v", slot, ok)
	}
	// Normal case: (1000 + 3*360 - 1000) / 360 = 3.
	slot, ok = headerSlot(1000+3*360, 1000, 360)
	if !ok || slot != 3 {
		t.Errorf("normal: want slot=3 ok=true; got slot=%d ok=%v", slot, ok)
	}
	// Partial slot (remainder is discarded).
	slot, ok = headerSlot(1000+3*360+100, 1000, 360)
	if !ok || slot != 3 {
		t.Errorf("partial: want slot=3 ok=true; got slot=%d ok=%v", slot, ok)
	}
}

// TestM2Guard verifies that verifyCascadingFields rejects a block when
// parent.Time < snap.GenesisTime (uint64 underflow guard).
func TestM2Guard(t *testing.T) {
	d, err := New(&params.DPoSConfig{
		PeriodMs: 360, Epoch: 208, MaxValidators: 21,
		TurnLength:     params.DPoSTurnLength,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Parent block at time 0; we will set snap.GenesisTime=1000 so parent.Time < GenesisTime.
	parent := &types.Header{
		Number: big.NewInt(0),
		Time:   0,
		Extra:  make([]byte, extraVanity),
	}

	// Pre-load a snapshot into d.recents keyed by parent.Hash(), with GenesisTime=1000.
	addrs := []common.Address{{0x01}}
	snap, _ := newSnapshot(d.config, d.signatures, 0, parent.Hash(), addrs, 1000, 360)
	d.recents.Add(parent.Hash(), snap)

	// header.Time = parent.Time + periodMs = 360 passes the period check.
	// Both header.Time(360) < snap.GenesisTime(1000) and parent.Time(0) < snap.GenesisTime(1000).
	header := &types.Header{
		Number:     big.NewInt(1),
		ParentHash: parent.Hash(),
		Time:       360, // passes period check (0+360), but < GenesisTime(1000)
		Difficulty: diffNoTurn,
		Extra:      make([]byte, extraVanity+extraSealEd25519),
	}
	chain := &fakeChainReader{headers: map[uint64]*types.Header{0: parent}}

	if err := d.verifyCascadingFields(chain, header, nil); err != errInvalidTimestamp {
		t.Errorf("M2Guard: want errInvalidTimestamp, got %v", err)
	}
}

// TestRecentlySignedAllowAtWindowEdge verifies that a validator becomes eligible
// again exactly at the grouped-turn window boundary.
func TestRecentlySignedAllowAtWindowEdge(t *testing.T) {
	pub, priv, signer := testEd25519Key(0x08)

	addrs := []common.Address{signer, {0x02}, {0x03}}
	d := NewFaker()
	const genesisTime = uint64(1_000_000)
	const periodMs = uint64(360)
	snap, _ := newSnapshot(d.config, d.signatures, 0, common.Hash{}, addrs, genesisTime, periodMs)

	// For N=3, T=16, recent window = 31.
	// Put 16 signatures in slots 1..16. At slot 32 the left bound is 1 (exclusive),
	// so slot 1 drops out of the active window and the validator is allowed again.
	for slot := uint64(1); slot <= d.config.TurnLength; slot++ {
		snap.Recents[slot] = signer
	}

	header := &types.Header{
		Number:     big.NewInt(32),
		Difficulty: big.NewInt(2),
		Coinbase:   signer,
		Extra:      make([]byte, extraVanity+extraSealEd25519),
		Time:       genesisTime + 32*periodMs, // slot 32
	}
	signTestHeader(t, d, header, pub, priv)

	if err := d.verifySeal(snap, header); err == errRecentlySigned {
		t.Error("window-edge: validator should be allowed again exactly at the grouped-turn window boundary")
	}
}

// TestApplyBulkEviction verifies that apply() evicts all stale Recents entries
// in a single step (not just one) when slot numbers jump.
func TestApplyBulkEviction(t *testing.T) {
	pub1, priv1, addr1 := testEd25519Key(0x09)
	pub2, priv2, addr2 := testEd25519Key(0x0a)
	pub3, priv3, addr3 := testEd25519Key(0x0b)
	keysByAddr := map[common.Address]struct {
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	}{
		addr1: {pub: pub1, priv: priv1},
		addr2: {pub: pub2, priv: priv2},
		addr3: {pub: pub3, priv: priv3},
	}

	// Sort ascending so newSnapshot accepts them.
	addrs := []common.Address{addr1, addr2, addr3}
	sort.Sort(addressAscending(addrs))

	d := NewFaker()
	const genesisTime = uint64(1_000_000)
	const periodMs = uint64(360)
	snap, _ := newSnapshot(d.config, d.signatures, 0, common.Hash{}, addrs, genesisTime, periodMs)

	// Pre-populate Recents with two stale entries at slots 0 and 1.
	// With N=3 and T=16, limit = 31. For an incoming block at slot 40:
	// staleThreshold = 40-31 = 9, so both slot 0 and slot 1 must be evicted.
	snap.Recents[0] = addrs[0]
	snap.Recents[1] = addrs[1]

	// Apply one header at slot 40 signed by addrs[2].
	h := &types.Header{
		Number:     big.NewInt(1),
		ParentHash: common.Hash{},
		Difficulty: big.NewInt(1),
		Coinbase:   addrs[2],
		Extra:      make([]byte, extraVanity+extraSealEd25519),
		Time:       genesisTime + 40*periodMs, // slot 40
	}
	entry := keysByAddr[addrs[2]]
	signTestHeader(t, d, h, entry.pub, entry.priv)

	next, err := snap.apply([]*types.Header{h})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Slots 0 and 1 must be gone; only slot 40 (addrs[2]) must remain.
	if _, ok := next.Recents[0]; ok {
		t.Error("slot 0 should have been evicted")
	}
	if _, ok := next.Recents[1]; ok {
		t.Error("slot 1 should have been evicted")
	}
	if signer, ok := next.Recents[40]; !ok || signer != addrs[2] {
		t.Errorf("slot 40 should map to addrs[2]; got %v ok=%v", signer, ok)
	}
}

// TestCalcDifficultyUsesTime verifies that CalcDifficulty uses the caller-supplied
// time argument rather than parent.Time+periodMs to determine the in-turn validator.
//
// With 2 validators and TurnLength=16:
//   - slot 1 is still in the first proposer's turn group
//   - slot 17 is the second proposer's first in-turn slot
//
// The test asserts that CalcDifficulty uses the caller-supplied time and grouped-turn
// slot mapping, not parent.Time+periodMs.
func TestCalcDifficultyUsesTime(t *testing.T) {
	const genesisTime = uint64(1_000_000)
	const periodMs = uint64(360)

	// Two validators, sorted ascending so addrs[0] owns slots 1..16.
	_, _, addr0 := testEd25519Key(0x0c)
	_, _, addr1 := testEd25519Key(0x0d)
	addrs := []common.Address{addr0, addr1}
	sort.Sort(addressAscending(addrs))

	extra := make([]byte, extraVanity)
	for _, a := range addrs {
		extra = append(extra, a.Bytes()...)
	}
	genesis := &types.Header{
		Number: big.NewInt(0),
		Time:   genesisTime,
		Extra:  extra,
	}
	chain := &fakeChainReader{headers: map[uint64]*types.Header{0: genesis}}

	d, err := New(&params.DPoSConfig{
		PeriodMs: periodMs, Epoch: 208, MaxValidators: 21,
		TurnLength:     params.DPoSTurnLength,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Authorize addrs[0] as the local validator.
	d.Authorize(addrs[0], nil)

	parent := genesis // parent at slot 0 (genesisTime)

	// Passed time = slot 17 -> second validator in-turn -> addrs[0] must be out-of-turn.
	// Old code using parent.Time+periodMs would look at slot 1 instead.
	diff := d.CalcDifficulty(chain, genesisTime+17*periodMs, parent)
	if diff == nil {
		t.Fatal("CalcDifficulty returned nil")
	}
	if diff.Cmp(diffNoTurn) != 0 {
		t.Errorf("CalcDifficulty: want diffNoTurn for addrs[0] at slot 17, got %v", diff)
	}

	// Cross-check: slot 1 remains addrs[0]'s in-turn slot.
	diff2 := d.CalcDifficulty(chain, genesisTime+periodMs, parent)
	if diff2 == nil {
		t.Fatal("CalcDifficulty (slot 1) returned nil")
	}
	if diff2.Cmp(diffInTurn) != 0 {
		t.Errorf("CalcDifficulty: want diffInTurn for addrs[0] at slot 1, got %v", diff2)
	}
}

// ── fakeChainReader ───────────────────────────────────────────────────────────

// fakeChainReader implements consensus.ChainHeaderReader for tests.
type fakeChainReader struct {
	headers map[uint64]*types.Header
}

func (f *fakeChainReader) Config() *params.ChainConfig {
	return params.TestChainConfig
}
func (f *fakeChainReader) CurrentHeader() *types.Header {
	return &types.Header{Number: big.NewInt(0)}
}
func (f *fakeChainReader) GetHeader(hash common.Hash, number uint64) *types.Header {
	if f.headers == nil {
		return nil
	}
	return f.headers[number]
}
func (f *fakeChainReader) GetHeaderByNumber(number uint64) *types.Header {
	if f.headers == nil {
		return nil
	}
	return f.headers[number]
}
func (f *fakeChainReader) GetHeaderByHash(hash common.Hash) *types.Header { return nil }
func (f *fakeChainReader) GetTd(hash common.Hash, number uint64) *big.Int {
	return big.NewInt(0)
}
