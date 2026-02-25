package dpos

import (
	"crypto/ed25519"
	"crypto/rand"
	"math/big"
	"sort"
	"testing"
	"time"

	"github.com/tos-network/gtos/accounts"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

// ── New / Config validation ──────────────────────────────────────────────────

// TestNewInvalidConfig verifies that New() returns error for invalid configs (R2-C4).
func TestNewInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		config params.DPoSConfig
	}{
		{"epoch=0", params.DPoSConfig{Epoch: 0, PeriodMs: 3000, MaxValidators: 21}},
		{"periodMs=0", params.DPoSConfig{Epoch: 200, PeriodMs: 0, MaxValidators: 21}},
		{"maxValidators=0", params.DPoSConfig{Epoch: 200, PeriodMs: 3000, MaxValidators: 0}},
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
	_, err := newSnapshot(d.config, d.signatures, 0, common.Hash{}, nil)
	if err == nil {
		t.Fatal("expected error for empty validator set")
	}
}

// TestSnapshotDeepCopy verifies that mutating an applied snapshot does not
// corrupt the original cached snapshot (data-race guard).
func TestSnapshotDeepCopy(t *testing.T) {
	d := NewFaker()
	addrs := []common.Address{{0x01}, {0x02}}
	snap, err := newSnapshot(d.config, d.signatures, 0, common.Hash{1}, addrs)
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
	seal := make([]byte, extraSeal)

	// N=1.
	a1 := common.Address{0x01}
	extra := append(append(vanity, a1.Bytes()...), seal...)
	d := NewFaker()
	out, err := parseEpochValidators(extra, d.config)
	if err != nil {
		t.Fatalf("N=1: %v", err)
	}
	if len(out) != 1 || out[0] != a1 {
		t.Errorf("N=1: got %v", out)
	}

	// Missing seal (too short).
	if _, err := parseEpochValidators(append(vanity, a1.Bytes()...), d.config); err == nil {
		t.Error("missing seal: expected error")
	}

	// Bad alignment: vanity + 19 bytes + seal.
	badPayload := append(append(vanity, make([]byte, 19)...), seal...)
	if _, err := parseEpochValidators(badPayload, d.config); err == nil {
		t.Error("bad alignment: expected error")
	}
}

// ── SealHash / ecrecover ──────────────────────────────────────────────────────

// TestSealHashRoundTrip verifies that recoverHeaderSigner(sign(SealHash(h))) == signer.
func TestSealHashRoundTrip(t *testing.T) {
	key, _ := crypto.GenerateKey()
	signer := crypto.PubkeyToAddress(key.PublicKey)

	header := &types.Header{
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(2),
		Extra:      make([]byte, extraVanity+extraSeal),
		Time:       uint64(time.Now().UnixMilli()),
	}

	d := NewFaker()
	sig, err := crypto.Sign(d.SealHash(header).Bytes(), key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	copy(header.Extra[len(header.Extra)-extraSeal:], sig)

	recovered, err := recoverHeaderSigner(d.config, header, d.signatures)
	if err != nil {
		t.Fatalf("ecrecover: %v", err)
	}
	if recovered != signer {
		t.Errorf("ecrecover: want %v, got %v", signer, recovered)
	}
}

func TestSealHashRoundTripEd25519(t *testing.T) {
	d, err := New(&params.DPoSConfig{
		PeriodMs:       3000,
		Epoch:          200,
		MaxValidators:  21,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer := common.BytesToAddress(crypto.Keccak256(pub))

	header := &types.Header{
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(2),
		Extra:      make([]byte, extraVanity+d.sealLength),
		Coinbase:   signer,
		Time:       uint64(time.Now().UnixMilli()),
	}
	digest := d.SealHash(header).Bytes()
	sig := ed25519.Sign(priv, digest)
	seal := make([]byte, 0, len(pub)+len(sig))
	seal = append(seal, pub...)
	seal = append(seal, sig...)
	copy(header.Extra[len(header.Extra)-d.sealLength:], seal)

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
	key1, _ := crypto.GenerateKey()
	key2, _ := crypto.GenerateKey()
	signer1 := crypto.PubkeyToAddress(key1.PublicKey)
	signer2 := crypto.PubkeyToAddress(key2.PublicKey)

	addrs := []common.Address{signer1, signer2}
	d := NewFaker()
	snap, _ := newSnapshot(d.config, d.signatures, 0, common.Hash{}, addrs)

	header := &types.Header{
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		Coinbase:   signer2, // deliberately wrong: will sign with key1
		Extra:      make([]byte, extraVanity+extraSeal),
		Time:       uint64(time.Now().UnixMilli()),
	}
	sig, _ := crypto.Sign(SealHash(header).Bytes(), key1)
	copy(header.Extra[len(header.Extra)-extraSeal:], sig)

	if err := d.verifySeal(snap, header); err != errInvalidCoinbase {
		t.Errorf("want errInvalidCoinbase, got %v", err)
	}
}

// TestRecentlySigned verifies that a block is rejected when the validator
// signed within the recency window (len(Validators)/2+1 blocks).
//
// With 3 validators, limit = 3/2+1 = 2.
// If signer last signed at block 2 and current block is 3:
//
//	seen=2, number=3, limit=2 → seen > number-limit ↔ 2 > 3-2 ↔ 2 > 1 → REJECT ✓
//
// If signer last signed at block 1 and current block is 3:
//
//	seen=1, number=3, limit=2 → seen > number-limit ↔ 1 > 3-2 ↔ 1 > 1 → ALLOW
func TestRecentlySigned(t *testing.T) {
	key, _ := crypto.GenerateKey()
	signer := crypto.PubkeyToAddress(key.PublicKey)

	// Three-validator set; recency window = 3/2+1 = 2.
	addrs := []common.Address{signer, {0x02}, {0x03}}
	d := NewFaker()
	snap, _ := newSnapshot(d.config, d.signatures, 0, common.Hash{}, addrs)

	// Signer signed block 2; current block is 3. seen=2 > number-limit = 3-2 = 1 → REJECT.
	snap.Recents[2] = signer

	header := &types.Header{
		Number:     big.NewInt(3),
		Difficulty: big.NewInt(1),
		Coinbase:   signer,
		Extra:      make([]byte, extraVanity+extraSeal),
		Time:       uint64(time.Now().UnixMilli()),
	}
	sig, _ := crypto.Sign(SealHash(header).Bytes(), key)
	copy(header.Extra[len(header.Extra)-extraSeal:], sig)

	if err := d.verifySeal(snap, header); err != errRecentlySigned {
		t.Errorf("want errRecentlySigned, got %v", err)
	}
}

// ── nil-db (NewFaker) ─────────────────────────────────────────────────────────

// TestNilDbFaker verifies that NewFaker() snapshot() does not panic
// when db is nil (R2-C3: all store() calls guarded with "if d.db != nil").
func TestNilDbFaker(t *testing.T) {
	d := NewFaker()
	key, _ := crypto.GenerateKey()
	signer := crypto.PubkeyToAddress(key.PublicKey)

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

	// 4 seconds into the future: allowed.
	h4 := &types.Header{
		Number:     big.NewInt(1),
		Time:       now + 4000,
		Difficulty: diffInTurn,
		Extra:      make([]byte, extraVanity+extraSeal),
		UncleHash:  types.EmptyUncleHash,
	}
	if err := d.verifyHeader(chain, h4, nil); err == consensus.ErrFutureBlock {
		t.Error("4s ahead should be allowed, got ErrFutureBlock")
	}

	// 6 seconds into the future: rejected.
	h6 := &types.Header{
		Number:     big.NewInt(1),
		Time:       now + 6000,
		Difficulty: diffInTurn,
		Extra:      make([]byte, extraVanity+extraSeal),
		UncleHash:  types.EmptyUncleHash,
	}
	if err := d.verifyHeader(chain, h6, nil); err != consensus.ErrFutureBlock {
		t.Errorf("6s ahead should be rejected as ErrFutureBlock, got %v", err)
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

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	var gotMime string

	d.Authorize(addr, func(_ accounts.Account, mime string, hash []byte) ([]byte, error) {
		gotMime = mime
		return crypto.Sign(hash, key)
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

	pub, err := crypto.SigToPub(digest.Bytes(), sig)
	if err != nil {
		t.Fatalf("SigToPub: %v", err)
	}
	if recovered := crypto.PubkeyToAddress(*pub); recovered != addr {
		t.Fatalf("vote signature signer mismatch: have %s want %s", recovered.Hex(), addr.Hex())
	}
}

func TestOutOfTurnWiggleWindow(t *testing.T) {
	d := NewFaker()
	if got := d.outOfTurnWiggleWindow(); got != 1500*time.Millisecond {
		t.Fatalf("unexpected default wiggle window: have %s want %s", got, 1500*time.Millisecond)
	}

	msCfg := &params.DPoSConfig{
		PeriodMs:       500,
		Epoch:          200,
		MaxValidators:  21,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
	}
	dms, err := New(msCfg, nil)
	if err != nil {
		t.Fatalf("New(msCfg): %v", err)
	}
	if got := dms.outOfTurnWiggleWindow(); got != 250*time.Millisecond {
		t.Fatalf("unexpected 500ms wiggle window: have %s want %s", got, 250*time.Millisecond)
	}

	tinyCfg := &params.DPoSConfig{
		PeriodMs:       10,
		Epoch:          200,
		MaxValidators:  21,
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
		Epoch:          200,
		MaxValidators:  21,
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

func TestPrepareLegacyPeriodMappedToMs(t *testing.T) {
	signer := common.Address{0x01}
	now := uint64(time.Now().UnixMilli())
	genesis := &types.Header{
		Number: big.NewInt(0),
		Time:   now + 2000,
		Extra:  append(make([]byte, extraVanity), signer.Bytes()...),
	}
	chain := &fakeChainReader{headers: map[uint64]*types.Header{0: genesis}}

	d, err := New(&params.DPoSConfig{
		Period:         2, // legacy seconds field
		Epoch:          200,
		MaxValidators:  21,
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
	if want := genesis.Time + 2000; header.Time != want {
		t.Fatalf("prepared legacy time mismatch: have %d want %d", header.Time, want)
	}
}

// ── inturn / addressAscending ─────────────────────────────────────────────────

// TestInturn verifies round-robin assignment of in-turn validators.
func TestInturn(t *testing.T) {
	addrs := []common.Address{{0x01}, {0x02}, {0x03}}
	d := NewFaker()
	snap, _ := newSnapshot(d.config, d.signatures, 0, common.Hash{}, addrs)

	// Block 0 → addrs[0], block 1 → addrs[1], block 3 → addrs[0] again.
	for block, want := range map[uint64]common.Address{
		0: addrs[0], 1: addrs[1], 2: addrs[2], 3: addrs[0],
	} {
		if !snap.inturn(block, want) {
			t.Errorf("block %d: %v should be in-turn", block, want)
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
