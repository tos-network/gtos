package core

import (
	cryptoRand "crypto/rand"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/types"
	coreuno "github.com/tos-network/gtos/core/uno"
	"github.com/tos-network/gtos/params"
)

func makeUNOFailingShieldTx(t *testing.T, chainID *big.Int, priv []byte, from common.Address, nonce uint64, amount uint64) *types.Transaction {
	t.Helper()

	body, err := coreuno.EncodeShieldPayload(coreuno.ShieldPayload{
		Amount: amount,
		NewSender: coreuno.Ciphertext{
			Commitment: [32]byte{},
			Handle:     [32]byte{},
		},
		// Correct shape, intentionally invalid bytes so execution path fails proof
		// verification deterministically without mutating UNO ciphertext/version.
		ProofBundle: make([]byte, coreuno.ShieldProofSize),
	})
	if err != nil {
		t.Fatalf("EncodeShieldPayload: %v", err)
	}
	wire, err := coreuno.EncodeEnvelope(coreuno.ActionShield, body)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	to := params.PrivacyRouterAddress
	unsigned := types.NewTx(&types.SignerTx{
		ChainID:    chainID,
		Nonce:      nonce,
		To:         &to,
		Value:      big.NewInt(0),
		Gas:        1_200_000,
		Data:       wire,
		From:       from,
		SignerType: accountsigner.SignerTypeElgamal,
	})
	signer := types.LatestSignerForChainID(chainID)
	sig, err := accountsigner.SignElgamalHash(priv, signer.Hash(unsigned))
	if err != nil {
		t.Fatalf("SignElgamalHash: %v", err)
	}
	signed, err := unsigned.WithSignature(signer, sig)
	if err != nil {
		t.Fatalf("WithSignature: %v", err)
	}
	return signed
}

func TestUNOReorgReimportVersionConsistency(t *testing.T) {
	config := params.TestChainConfig
	db := rawdb.NewMemoryDatabase()

	priv, err := accountsigner.GenerateElgamalPrivateKey(cryptoRand.Reader)
	if err != nil {
		t.Fatalf("GenerateElgamalPrivateKey: %v", err)
	}
	pub, err := accountsigner.PublicKeyFromElgamalPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromElgamalPrivate: %v", err)
	}
	from, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeElgamal, pub)
	if err != nil {
		t.Fatalf("AddressFromSigner: %v", err)
	}

	genesisSpec := &Genesis{
		Config: config,
		Alloc: GenesisAlloc{
			from: {
				Balance:     new(big.Int).Mul(big.NewInt(1000), new(big.Int).SetUint64(params.TOS)),
				SignerType:  accountsigner.SignerTypeElgamal,
				SignerValue: hexutil.Encode(pub),
			},
		},
	}
	genesisSpec.MustCommit(db)

	chain, err := NewBlockChain(db, nil, config, dpos.NewFaker(), nil, nil)
	if err != nil {
		t.Fatalf("NewBlockChain: %v", err)
	}
	defer chain.Stop()

	shieldTx := makeUNOFailingShieldTx(t, config.ChainID, priv, from, 0, 1)
	aGenDB := rawdb.NewMemoryDatabase()
	aGenesis := genesisSpec.MustCommit(aGenDB)
	aBlocks, _ := GenerateChain(config, aGenesis, dpos.NewFaker(), aGenDB, 4, func(i int, b *BlockGen) {
		if i == 0 {
			b.AddTx(shieldTx)
		}
	})
	bGenDB := rawdb.NewMemoryDatabase()
	bGenesis := genesisSpec.MustCommit(bGenDB)
	bBlocks, _ := GenerateChain(config, bGenesis, dpos.NewFaker(), bGenDB, 3, nil)

	if n, err := chain.InsertChain(bBlocks); err != nil {
		t.Fatalf("insert bBlocks failed at %d: %v", n, err)
	}
	st, err := chain.State()
	if err != nil {
		t.Fatalf("State after B: %v", err)
	}
	if got := st.GetNonce(from); got != 0 {
		t.Fatalf("nonce on B chain: got %d want 0", got)
	}
	if got := coreuno.GetAccountState(st, from).Version; got != 0 {
		t.Fatalf("uno_version on B chain: got %d want 0", got)
	}

	if n, err := chain.InsertChain(aBlocks); err != nil {
		t.Fatalf("insert aBlocks failed at %d: %v", n, err)
	}
	if head := chain.CurrentBlock().Hash(); head != aBlocks[len(aBlocks)-1].Hash() {
		t.Fatalf("unexpected canonical head after reorg: got %s want %s", head.Hex(), aBlocks[len(aBlocks)-1].Hash().Hex())
	}
	st, err = chain.State()
	if err != nil {
		t.Fatalf("State after A reorg: %v", err)
	}
	if got := st.GetNonce(from); got != 1 {
		t.Fatalf("nonce on A chain: got %d want 1", got)
	}
	if got := coreuno.GetAccountState(st, from).Version; got != 0 {
		t.Fatalf("uno_version on A chain: got %d want 0", got)
	}

	if n, err := chain.InsertChain(aBlocks); err != nil {
		t.Fatalf("re-import aBlocks failed at %d: %v", n, err)
	}
	st, err = chain.State()
	if err != nil {
		t.Fatalf("State after A re-import: %v", err)
	}
	if got := st.GetNonce(from); got != 1 {
		t.Fatalf("nonce after re-import: got %d want 1", got)
	}
	if got := coreuno.GetAccountState(st, from).Version; got != 0 {
		t.Fatalf("uno_version after re-import: got %d want 0", got)
	}
}
