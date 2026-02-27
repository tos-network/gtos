//go:build cgo && ed25519c

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
	cryptouno "github.com/tos-network/gtos/crypto/uno"
	"github.com/tos-network/gtos/params"
)

func makeUNOSignedTx(t *testing.T, chainID *big.Int, priv []byte, from common.Address, nonce uint64, data []byte) *types.Transaction {
	t.Helper()

	to := params.PrivacyRouterAddress
	unsigned := types.NewTx(&types.SignerTx{
		ChainID:    chainID,
		Nonce:      nonce,
		To:         &to,
		Value:      big.NewInt(0),
		Gas:        1_200_000,
		Data:       data,
		From:       from,
		SignerType: accountsigner.SignerTypeElgamal,
	})
	signer := types.LatestSignerForChainID(chainID)
	sig, err := accountsigner.SignElgamalHash(priv, signer.Hash(unsigned))
	if err != nil {
		t.Fatalf("SignElgamalHash: %v", err)
	}
	tx, err := unsigned.WithSignature(signer, sig)
	if err != nil {
		t.Fatalf("WithSignature: %v", err)
	}
	return tx
}

func decryptUNOBalance(t *testing.T, priv []byte, ct coreuno.Ciphertext, max uint64) uint64 {
	t.Helper()

	var compressed [64]byte
	copy(compressed[:32], ct.Commitment[:])
	copy(compressed[32:], ct.Handle[:])
	point, err := cryptouno.DecryptToPoint(priv, compressed[:])
	if err != nil {
		t.Fatalf("DecryptToPoint: %v", err)
	}
	amount, found, err := cryptouno.SolveDiscreteLog(point, max)
	if err != nil {
		t.Fatalf("SolveDiscreteLog: %v", err)
	}
	if !found {
		t.Fatalf("SolveDiscreteLog: amount not found within max=%d", max)
	}
	return amount
}

func ciphertextFromCompressed(t *testing.T, compressed []byte) coreuno.Ciphertext {
	t.Helper()

	if len(compressed) != 64 {
		t.Fatalf("invalid compressed ciphertext length: %d", len(compressed))
	}
	var out coreuno.Ciphertext
	copy(out.Commitment[:], compressed[:32])
	copy(out.Handle[:], compressed[32:])
	return out
}

func assertUNOAccountState(t *testing.T, chain *BlockChain, addr common.Address, wantNonce uint64, wantVersion uint64, wantCiphertext coreuno.Ciphertext) {
	t.Helper()

	st, err := chain.State()
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if got := st.GetNonce(addr); got != wantNonce {
		t.Fatalf("nonce mismatch for %s: got %d want %d", addr.Hex(), got, wantNonce)
	}
	got := coreuno.GetAccountState(st, addr)
	if got.Version != wantVersion {
		t.Fatalf("uno_version mismatch for %s: got %d want %d", addr.Hex(), got.Version, wantVersion)
	}
	if got.Ciphertext != wantCiphertext {
		t.Fatalf("uno ciphertext mismatch for %s", addr.Hex())
	}
}

func TestUNOLifecycleReorgAndReimportDeterminism(t *testing.T) {
	config := params.TestChainConfig
	db := rawdb.NewMemoryDatabase()

	aPriv, err := accountsigner.GenerateElgamalPrivateKey(cryptoRand.Reader)
	if err != nil {
		t.Fatalf("GenerateElgamalPrivateKey(A): %v", err)
	}
	aPub, err := accountsigner.PublicKeyFromElgamalPrivate(aPriv)
	if err != nil {
		t.Fatalf("PublicKeyFromElgamalPrivate(A): %v", err)
	}
	aAddr, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeElgamal, aPub)
	if err != nil {
		t.Fatalf("AddressFromSigner(A): %v", err)
	}
	bPriv, err := accountsigner.GenerateElgamalPrivateKey(cryptoRand.Reader)
	if err != nil {
		t.Fatalf("GenerateElgamalPrivateKey(B): %v", err)
	}
	bPub, err := accountsigner.PublicKeyFromElgamalPrivate(bPriv)
	if err != nil {
		t.Fatalf("PublicKeyFromElgamalPrivate(B): %v", err)
	}
	bAddr, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeElgamal, bPub)
	if err != nil {
		t.Fatalf("AddressFromSigner(B): %v", err)
	}

	genesisSpec := &Genesis{
		Config: config,
		Alloc: GenesisAlloc{
			aAddr: {
				Balance:     new(big.Int).Mul(big.NewInt(1000), new(big.Int).SetUint64(params.TOS)),
				SignerType:  accountsigner.SignerTypeElgamal,
				SignerValue: hexutil.Encode(aPub),
			},
			bAddr: {
				Balance:     new(big.Int).Mul(big.NewInt(100), new(big.Int).SetUint64(params.TOS)),
				SignerType:  accountsigner.SignerTypeElgamal,
				SignerValue: hexutil.Encode(bPub),
			},
		},
	}
	genesisSpec.MustCommit(db)

	var zeroCt coreuno.Ciphertext

	shieldPayload, _, err := coreuno.BuildShieldPayloadProof(coreuno.ShieldBuildArgs{
		ChainID:   config.ChainID,
		From:      aAddr,
		Nonce:     0,
		SenderOld: zeroCt,
		SenderPub: aPub,
		Amount:    4,
	})
	if err != nil {
		t.Fatalf("BuildShieldPayloadProof: %v", err)
	}
	shieldBody, err := coreuno.EncodeShieldPayload(shieldPayload)
	if err != nil {
		t.Fatalf("EncodeShieldPayload: %v", err)
	}
	shieldWire, err := coreuno.EncodeEnvelope(coreuno.ActionShield, shieldBody)
	if err != nil {
		t.Fatalf("EncodeEnvelope(shield): %v", err)
	}
	shieldTx := makeUNOSignedTx(t, config.ChainID, aPriv, aAddr, 0, shieldWire)

	transferPayload, _, err := coreuno.BuildTransferPayloadProof(coreuno.TransferBuildArgs{
		ChainID:     config.ChainID,
		From:        aAddr,
		To:          bAddr,
		Nonce:       1,
		SenderOld:   shieldPayload.NewSender,
		ReceiverOld: zeroCt,
		SenderPriv:  aPriv,
		ReceiverPub: bPub,
		Amount:      2,
	})
	if err != nil {
		t.Fatalf("BuildTransferPayloadProof: %v", err)
	}
	transferBody, err := coreuno.EncodeTransferPayload(transferPayload)
	if err != nil {
		t.Fatalf("EncodeTransferPayload: %v", err)
	}
	transferWire, err := coreuno.EncodeEnvelope(coreuno.ActionTransfer, transferBody)
	if err != nil {
		t.Fatalf("EncodeEnvelope(transfer): %v", err)
	}
	transferTx := makeUNOSignedTx(t, config.ChainID, aPriv, aAddr, 1, transferWire)

	unshieldPayload, _, err := coreuno.BuildUnshieldPayloadProof(coreuno.UnshieldBuildArgs{
		ChainID:    config.ChainID,
		From:       bAddr,
		To:         aAddr,
		Nonce:      0,
		SenderOld:  transferPayload.ReceiverDelta,
		SenderPriv: bPriv,
		Amount:     1,
	})
	if err != nil {
		t.Fatalf("BuildUnshieldPayloadProof: %v", err)
	}
	unshieldBody, err := coreuno.EncodeUnshieldPayload(unshieldPayload)
	if err != nil {
		t.Fatalf("EncodeUnshieldPayload: %v", err)
	}
	unshieldWire, err := coreuno.EncodeEnvelope(coreuno.ActionUnshield, unshieldBody)
	if err != nil {
		t.Fatalf("EncodeEnvelope(unshield): %v", err)
	}
	unshieldTx := makeUNOSignedTx(t, config.ChainID, bPriv, bAddr, 0, unshieldWire)

	chain, err := NewBlockChain(db, nil, config, dpos.NewFaker(), nil, nil)
	if err != nil {
		t.Fatalf("NewBlockChain: %v", err)
	}
	defer chain.Stop()

	buildA := func(n int) []*types.Block {
		genDB := rawdb.NewMemoryDatabase()
		genesis := genesisSpec.MustCommit(genDB)
		blocks, _ := GenerateChain(config, genesis, dpos.NewFaker(), genDB, n, func(i int, b *BlockGen) {
			switch i {
			case 0:
				b.AddTx(shieldTx)
			case 1:
				b.AddTx(transferTx)
			case 2:
				b.AddTx(unshieldTx)
			}
		})
		return blocks
	}
	buildEmpty := func(n int) []*types.Block {
		genDB := rawdb.NewMemoryDatabase()
		genesis := genesisSpec.MustCommit(genDB)
		blocks, _ := GenerateChain(config, genesis, dpos.NewFaker(), genDB, n, nil)
		return blocks
	}

	aBlocks := buildA(6)
	if n, err := chain.InsertChain(aBlocks); err != nil {
		t.Fatalf("insert aBlocks failed at %d: %v", n, err)
	}
	if head := chain.CurrentBlock().Hash(); head != aBlocks[len(aBlocks)-1].Hash() {
		t.Fatalf("unexpected head after A insert: got %s want %s", head.Hex(), aBlocks[len(aBlocks)-1].Hash().Hex())
	}
	assertUNOAccountState(t, chain, aAddr, 2, 2, transferPayload.NewSender)
	assertUNOAccountState(t, chain, bAddr, 1, 2, unshieldPayload.NewSender)

	st, err := chain.State()
	if err != nil {
		t.Fatalf("State after A insert: %v", err)
	}
	if got := decryptUNOBalance(t, aPriv, coreuno.GetAccountState(st, aAddr).Ciphertext, 16); got != 2 {
		t.Fatalf("A decrypted UNO balance mismatch: got %d want 2", got)
	}
	if got := decryptUNOBalance(t, bPriv, coreuno.GetAccountState(st, bAddr).Ciphertext, 16); got != 1 {
		t.Fatalf("B decrypted UNO balance mismatch: got %d want 1", got)
	}

	cBlocks := buildEmpty(7)
	if n, err := chain.InsertChain(cBlocks); err != nil {
		t.Fatalf("insert cBlocks failed at %d: %v", n, err)
	}
	if head := chain.CurrentBlock().Hash(); head != cBlocks[len(cBlocks)-1].Hash() {
		t.Fatalf("unexpected head after C reorg: got %s want %s", head.Hex(), cBlocks[len(cBlocks)-1].Hash().Hex())
	}
	assertUNOAccountState(t, chain, aAddr, 0, 0, zeroCt)
	assertUNOAccountState(t, chain, bAddr, 0, 0, zeroCt)

	aPrimeBlocks := buildA(8)
	if n, err := chain.InsertChain(aPrimeBlocks); err != nil {
		t.Fatalf("insert aPrimeBlocks failed at %d: %v", n, err)
	}
	if head := chain.CurrentBlock().Hash(); head != aPrimeBlocks[len(aPrimeBlocks)-1].Hash() {
		t.Fatalf("unexpected head after A' reorg: got %s want %s", head.Hex(), aPrimeBlocks[len(aPrimeBlocks)-1].Hash().Hex())
	}
	assertUNOAccountState(t, chain, aAddr, 2, 2, transferPayload.NewSender)
	assertUNOAccountState(t, chain, bAddr, 1, 2, unshieldPayload.NewSender)

	st, err = chain.State()
	if err != nil {
		t.Fatalf("State after A' reorg: %v", err)
	}
	if got := decryptUNOBalance(t, aPriv, coreuno.GetAccountState(st, aAddr).Ciphertext, 16); got != 2 {
		t.Fatalf("A decrypted UNO balance mismatch after A' reorg: got %d want 2", got)
	}
	if got := decryptUNOBalance(t, bPriv, coreuno.GetAccountState(st, bAddr).Ciphertext, 16); got != 1 {
		t.Fatalf("B decrypted UNO balance mismatch after A' reorg: got %d want 1", got)
	}

	if n, err := chain.InsertChain(aPrimeBlocks); err != nil {
		t.Fatalf("re-import aPrimeBlocks failed at %d: %v", n, err)
	}
	assertUNOAccountState(t, chain, aAddr, 2, 2, transferPayload.NewSender)
	assertUNOAccountState(t, chain, bAddr, 1, 2, unshieldPayload.NewSender)
}

func TestUNOGenesisPreallocReorgLifecycle(t *testing.T) {
	config := params.TestChainConfig
	db := rawdb.NewMemoryDatabase()

	bPriv, err := accountsigner.GenerateElgamalPrivateKey(cryptoRand.Reader)
	if err != nil {
		t.Fatalf("GenerateElgamalPrivateKey(B): %v", err)
	}
	bPub, err := accountsigner.PublicKeyFromElgamalPrivate(bPriv)
	if err != nil {
		t.Fatalf("PublicKeyFromElgamalPrivate(B): %v", err)
	}
	bAddr, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeElgamal, bPub)
	if err != nil {
		t.Fatalf("AddressFromSigner(B): %v", err)
	}
	plainRecipient := common.HexToAddress("0x1234")

	genesisCtCompressed, err := cryptouno.Encrypt(bPub, 10)
	if err != nil {
		t.Fatalf("Encrypt(genesis prealloc): %v", err)
	}
	genesisCt := ciphertextFromCompressed(t, genesisCtCompressed)

	genesisSpec := &Genesis{
		Config: config,
		Alloc: GenesisAlloc{
			bAddr: {
				Balance:       new(big.Int).Mul(big.NewInt(100), new(big.Int).SetUint64(params.TOS)),
				SignerType:    accountsigner.SignerTypeElgamal,
				SignerValue:   hexutil.Encode(bPub),
				UNOCommitment: genesisCt.Commitment[:],
				UNOHandle:     genesisCt.Handle[:],
				UNOVersion:    5,
			},
		},
	}
	genesisSpec.MustCommit(db)

	unshieldPayload, _, err := coreuno.BuildUnshieldPayloadProof(coreuno.UnshieldBuildArgs{
		ChainID:    config.ChainID,
		From:       bAddr,
		To:         plainRecipient,
		Nonce:      0,
		SenderOld:  genesisCt,
		SenderPriv: bPriv,
		Amount:     3,
	})
	if err != nil {
		t.Fatalf("BuildUnshieldPayloadProof: %v", err)
	}
	unshieldBody, err := coreuno.EncodeUnshieldPayload(unshieldPayload)
	if err != nil {
		t.Fatalf("EncodeUnshieldPayload: %v", err)
	}
	unshieldWire, err := coreuno.EncodeEnvelope(coreuno.ActionUnshield, unshieldBody)
	if err != nil {
		t.Fatalf("EncodeEnvelope(unshield): %v", err)
	}
	unshieldTx := makeUNOSignedTx(t, config.ChainID, bPriv, bAddr, 0, unshieldWire)

	chain, err := NewBlockChain(db, nil, config, dpos.NewFaker(), nil, nil)
	if err != nil {
		t.Fatalf("NewBlockChain: %v", err)
	}
	defer chain.Stop()

	buildWithUnshield := func(n int) []*types.Block {
		genDB := rawdb.NewMemoryDatabase()
		genesis := genesisSpec.MustCommit(genDB)
		blocks, _ := GenerateChain(config, genesis, dpos.NewFaker(), genDB, n, func(i int, b *BlockGen) {
			if i == 0 {
				b.AddTx(unshieldTx)
			}
		})
		return blocks
	}
	buildEmpty := func(n int) []*types.Block {
		genDB := rawdb.NewMemoryDatabase()
		genesis := genesisSpec.MustCommit(genDB)
		blocks, _ := GenerateChain(config, genesis, dpos.NewFaker(), genDB, n, nil)
		return blocks
	}

	st, err := chain.State()
	if err != nil {
		t.Fatalf("State at genesis: %v", err)
	}
	if got := decryptUNOBalance(t, bPriv, coreuno.GetAccountState(st, bAddr).Ciphertext, 16); got != 10 {
		t.Fatalf("genesis prealloc decrypt mismatch: got %d want 10", got)
	}

	aBlocks := buildWithUnshield(4)
	if n, err := chain.InsertChain(aBlocks); err != nil {
		t.Fatalf("insert aBlocks failed at %d: %v", n, err)
	}
	if head := chain.CurrentBlock().Hash(); head != aBlocks[len(aBlocks)-1].Hash() {
		t.Fatalf("unexpected head after A insert: got %s want %s", head.Hex(), aBlocks[len(aBlocks)-1].Hash().Hex())
	}
	assertUNOAccountState(t, chain, bAddr, 1, 6, unshieldPayload.NewSender)
	st, err = chain.State()
	if err != nil {
		t.Fatalf("State after A insert: %v", err)
	}
	if got := decryptUNOBalance(t, bPriv, coreuno.GetAccountState(st, bAddr).Ciphertext, 16); got != 7 {
		t.Fatalf("post-unshield decrypt mismatch: got %d want 7", got)
	}

	cBlocks := buildEmpty(5)
	if n, err := chain.InsertChain(cBlocks); err != nil {
		t.Fatalf("insert cBlocks failed at %d: %v", n, err)
	}
	if head := chain.CurrentBlock().Hash(); head != cBlocks[len(cBlocks)-1].Hash() {
		t.Fatalf("unexpected head after C reorg: got %s want %s", head.Hex(), cBlocks[len(cBlocks)-1].Hash().Hex())
	}
	assertUNOAccountState(t, chain, bAddr, 0, 5, genesisCt)
	st, err = chain.State()
	if err != nil {
		t.Fatalf("State after C reorg: %v", err)
	}
	if got := decryptUNOBalance(t, bPriv, coreuno.GetAccountState(st, bAddr).Ciphertext, 16); got != 10 {
		t.Fatalf("post-reorg genesis decrypt mismatch: got %d want 10", got)
	}

	aPrimeBlocks := buildWithUnshield(6)
	if n, err := chain.InsertChain(aPrimeBlocks); err != nil {
		t.Fatalf("insert aPrimeBlocks failed at %d: %v", n, err)
	}
	if head := chain.CurrentBlock().Hash(); head != aPrimeBlocks[len(aPrimeBlocks)-1].Hash() {
		t.Fatalf("unexpected head after A' insert: got %s want %s", head.Hex(), aPrimeBlocks[len(aPrimeBlocks)-1].Hash().Hex())
	}
	assertUNOAccountState(t, chain, bAddr, 1, 6, unshieldPayload.NewSender)
	st, err = chain.State()
	if err != nil {
		t.Fatalf("State after A' insert: %v", err)
	}
	if got := decryptUNOBalance(t, bPriv, coreuno.GetAccountState(st, bAddr).Ciphertext, 16); got != 7 {
		t.Fatalf("post-reimport decrypt mismatch: got %d want 7", got)
	}
}
