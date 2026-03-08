package slashindicator

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/tos-network/gtos/accounts/abi"
	"github.com/tos-network/gtos/common"
	coretypes "github.com/tos-network/gtos/core/types"
	vmtypes "github.com/tos-network/gtos/core/vmtypes"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

type slashIndicatorVoteData struct {
	ChainID          *big.Int    `abi:"chainId"`
	Number           *big.Int    `abi:"number"`
	Hash             common.Hash `abi:"hash"`
	ValidatorSetHash common.Hash `abi:"validatorSetHash"`
	Sig              []byte      `abi:"sig"`
}

type slashIndicatorFinalityEvidence struct {
	VoteA        slashIndicatorVoteData `abi:"voteA"`
	VoteB        slashIndicatorVoteData `abi:"voteB"`
	SignerPubKey []byte                 `abi:"signerPubKey"`
}

var slashIndicatorABI = mustParseSlashIndicatorABI()

func mustParseSlashIndicatorABI() abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(`[
		{
			"inputs": [
				{
					"components": [
						{
							"components": [
								{"internalType":"uint256","name":"chainId","type":"uint256"},
								{"internalType":"uint256","name":"number","type":"uint256"},
								{"internalType":"bytes32","name":"hash","type":"bytes32"},
								{"internalType":"bytes32","name":"validatorSetHash","type":"bytes32"},
								{"internalType":"bytes","name":"sig","type":"bytes"}
							],
							"internalType":"struct GTOSSlashIndicator.CheckpointVoteData",
							"name":"voteA",
							"type":"tuple"
						},
						{
							"components": [
								{"internalType":"uint256","name":"chainId","type":"uint256"},
								{"internalType":"uint256","name":"number","type":"uint256"},
								{"internalType":"bytes32","name":"hash","type":"bytes32"},
								{"internalType":"bytes32","name":"validatorSetHash","type":"bytes32"},
								{"internalType":"bytes","name":"sig","type":"bytes"}
							],
							"internalType":"struct GTOSSlashIndicator.CheckpointVoteData",
							"name":"voteB",
							"type":"tuple"
						},
						{"internalType":"bytes","name":"signerPubKey","type":"bytes"}
					],
					"internalType":"struct GTOSSlashIndicator.FinalityEvidence",
					"name":"evidence",
					"type":"tuple"
				}
			],
			"name": "submitFinalityViolationEvidence",
			"outputs": [],
			"stateMutability": "nonpayable",
			"type": "function"
		}
	]`))
	if err != nil {
		panic(err)
	}
	return parsed
}

func slashIndicatorEvidenceFromCanonical(evidence *coretypes.MaliciousVoteEvidence) (*slashIndicatorFinalityEvidence, error) {
	if evidence == nil {
		return nil, fmt.Errorf("dpos: nil malicious vote evidence")
	}
	if err := evidence.Validate(); err != nil {
		return nil, err
	}
	pub, err := hex.DecodeString(strings.TrimPrefix(evidence.SignerPubKey, "0x"))
	if err != nil {
		return nil, fmt.Errorf("dpos: invalid signer pubkey: %w", err)
	}
	first := slashIndicatorVoteData{
		ChainID:          new(big.Int).Set(evidence.First.Vote.ChainID),
		Number:           new(big.Int).SetUint64(evidence.First.Vote.Number),
		Hash:             evidence.First.Vote.Hash,
		ValidatorSetHash: evidence.First.Vote.ValidatorSetHash,
		Sig:              append([]byte(nil), evidence.First.Signature[:]...),
	}
	second := slashIndicatorVoteData{
		ChainID:          new(big.Int).Set(evidence.Second.Vote.ChainID),
		Number:           new(big.Int).SetUint64(evidence.Second.Vote.Number),
		Hash:             evidence.Second.Vote.Hash,
		ValidatorSetHash: evidence.Second.Vote.ValidatorSetHash,
		Sig:              append([]byte(nil), evidence.Second.Signature[:]...),
	}
	return &slashIndicatorFinalityEvidence{VoteA: first, VoteB: second, SignerPubKey: pub}, nil
}

func canonicalEvidenceFromSlashIndicator(evidence *slashIndicatorFinalityEvidence) (*coretypes.MaliciousVoteEvidence, error) {
	if evidence == nil {
		return nil, fmt.Errorf("dpos: nil slash-indicator evidence")
	}
	voteA, err := slashIndicatorEnvelopeToCanonical(evidence.VoteA, evidence.SignerPubKey)
	if err != nil {
		return nil, err
	}
	voteB, err := slashIndicatorEnvelopeToCanonical(evidence.VoteB, evidence.SignerPubKey)
	if err != nil {
		return nil, err
	}
	return coretypes.NewMaliciousVoteEvidence(voteA, voteB, "ed25519", evidence.SignerPubKey)
}

func slashIndicatorEnvelopeToCanonical(v slashIndicatorVoteData, pub []byte) (*coretypes.CheckpointVoteEnvelope, error) {
	if v.ChainID == nil || v.Number == nil {
		return nil, fmt.Errorf("dpos: slash-indicator vote missing chainId/number")
	}
	if len(v.Sig) != len([64]byte{}) {
		return nil, fmt.Errorf("dpos: invalid vote signature length %d", len(v.Sig))
	}
	derived := common.BytesToAddress(crypto.Keccak256(pub))
	var sig [64]byte
	copy(sig[:], v.Sig)
	return &coretypes.CheckpointVoteEnvelope{
		Vote: coretypes.CheckpointVote{
			ChainID:          new(big.Int).Set(v.ChainID),
			Number:           v.Number.Uint64(),
			Hash:             v.Hash,
			ValidatorSetHash: v.ValidatorSetHash,
		},
		Signer:    derived,
		Signature: sig,
	}, nil
}

func PackSubmitFinalityViolationEvidence(evidence *coretypes.MaliciousVoteEvidence) ([]byte, error) {
	payload, err := slashIndicatorEvidenceFromCanonical(evidence)
	if err != nil {
		return nil, err
	}
	return slashIndicatorABI.Pack("submitFinalityViolationEvidence", *payload)
}

func DecodeSubmitFinalityViolationEvidence(input []byte) (*coretypes.MaliciousVoteEvidence, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("dpos: slash-indicator calldata too short")
	}
	method, err := slashIndicatorABI.MethodById(input[:4])
	if err != nil {
		return nil, err
	}
	if method.Name != "submitFinalityViolationEvidence" {
		return nil, fmt.Errorf("dpos: unsupported slash-indicator method %s", method.Name)
	}
	values, err := method.Inputs.Unpack(input[4:])
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Evidence slashIndicatorFinalityEvidence
	}
	if err := method.Inputs.Copy(&decoded, values); err != nil {
		return nil, err
	}
	return canonicalEvidenceFromSlashIndicator(&decoded.Evidence)
}

func Execute(msg sysaction.Msg, db vmtypes.StateDB, blockNumber *big.Int, chainConfig *params.ChainConfig) (uint64, error) {
	if msg == nil || db == nil || chainConfig == nil || chainConfig.ChainID == nil {
		return params.SysActionGas, fmt.Errorf("dpos: missing slash-indicator execution context")
	}
	evidence, err := DecodeSubmitFinalityViolationEvidence(msg.Data())
	if err != nil {
		return params.SysActionGas, err
	}
	if err := evidence.Validate(); err != nil {
		return params.SysActionGas, err
	}
	if evidence.ChainID == nil || evidence.ChainID.Cmp(chainConfig.ChainID) != 0 {
		return params.SysActionGas, fmt.Errorf("dpos: malicious vote evidence chain ID mismatch")
	}
	hash := evidence.Hash()
	if HasSubmittedMaliciousVoteEvidence(db, hash) {
		return params.SysActionGas, fmt.Errorf("dpos: malicious vote evidence already submitted: %s", hash.Hex())
	}
	offenseKey := MaliciousVoteOffenseKey(evidence.Signer, evidence.Number)
	if HasRecordedMaliciousVoteOffense(db, offenseKey) {
		return params.SysActionGas, fmt.Errorf("dpos: malicious vote offense already submitted: %s", offenseKey.Hex())
	}
	height := uint64(0)
	if blockNumber != nil {
		height = blockNumber.Uint64()
	}
	appendMaliciousVoteEvidenceRecord(db, hash, offenseKey, evidence.Number, evidence.Signer, msg.From(), height)
	return params.SysActionGas, nil
}
