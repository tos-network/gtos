package core

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	coreuno "github.com/tos-network/gtos/core/uno"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto/ristretto255"
	"github.com/tos-network/gtos/params"
)

func toCiphertext(commitment, handle []byte) coreuno.Ciphertext {
	var out coreuno.Ciphertext
	copy(out.Commitment[:], commitment)
	copy(out.Handle[:], handle)
	return out
}

func benchUNOShieldWire(amount uint64, proofLen int) []byte {
	payload, err := coreuno.EncodeShieldPayload(coreuno.ShieldPayload{
		Amount:      amount,
		NewSender:   toCiphertext(ristretto255.NewGeneratorElement().Bytes(), ristretto255.NewIdentityElement().Bytes()),
		ProofBundle: make([]byte, proofLen),
	})
	if err != nil {
		panic(err)
	}
	wire, err := coreuno.EncodeEnvelope(coreuno.ActionShield, payload)
	if err != nil {
		panic(err)
	}
	return wire
}

func benchUNOSenderState() (from common.Address, pub []byte, balance *big.Int) {
	pub = ristretto255.NewGeneratorElement().Bytes()
	from = common.HexToAddress("0x1001")
	// Keep balance high to avoid benchmark loops becoming balance-bound.
	balance = new(big.Int).Lsh(big.NewInt(1), 220)
	return from, pub, balance
}

func benchBlockContext(block uint64, coinbase common.Address) vm.BlockContext {
	return vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		Coinbase:    coinbase,
		BlockNumber: new(big.Int).SetUint64(block),
		GasLimit:    30_000_000,
	}
}

func benchApplyUNOShield(b *testing.B, wire []byte) {
	b.Helper()

	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}
	coinbase := common.HexToAddress("0xC0FFEE")
	to := params.PrivacyRouterAddress

	db := rawdb.NewMemoryDatabase()
	st, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
	if err != nil {
		b.Fatalf("create state: %v", err)
	}
	from, pub, balance := benchUNOSenderState()
	accountsigner.Set(st, from, accountsigner.SignerTypeElgamal, hexutil.Encode(pub))
	st.SetBalance(from, balance)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg := types.NewMessage(
			from, &to, uint64(i), big.NewInt(0), 2_000_000,
			big.NewInt(0), big.NewInt(0), big.NewInt(0),
			wire, nil, false,
		)
		gp := new(GasPool).AddGas(msg.Gas())
		_, _ = ApplyMessage(benchBlockContext(1, coinbase), cfg, msg, gp, st)
	}
}

// BenchmarkUNOShieldInvalidProofShape measures the cheap-reject path where
// proof bundle shape is invalid before any heavy verification path runs.
func BenchmarkUNOShieldInvalidProofShape(b *testing.B) {
	wire := benchUNOShieldWire(1, coreuno.ShieldProofSize-1)
	benchApplyUNOShield(b, wire)
}

// BenchmarkUNOShieldInvalidProofVerifyPath measures the path where proof shape
// is valid and verification is invoked (invalid proof bytes).
func BenchmarkUNOShieldInvalidProofVerifyPath(b *testing.B) {
	wire := benchUNOShieldWire(1, coreuno.ShieldProofSize)
	benchApplyUNOShield(b, wire)
}
