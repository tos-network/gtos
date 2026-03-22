package verifyregistry

import (
	"errors"

	"github.com/tos-network/gtos/common"
)

type VerifierStatus uint8

const (
	VerifierActive  VerifierStatus = 0
	VerifierRevoked VerifierStatus = 1
)

type VerificationStatus uint8

const (
	VerificationActive  VerificationStatus = 0
	VerificationRevoked VerificationStatus = 1
	VerificationExpired VerificationStatus = 2
)

const (
	VerifierTypeZK          uint16 = 1
	VerifierTypeOracle      uint16 = 2
	VerifierTypeAttestation uint16 = 3
	VerifierTypeReceipt     uint16 = 4
	VerifierTypeConsensus   uint16 = 5
	VerifierTypeTLSNotary   uint16 = 6
	VerifierTypeCommittee   uint16 = 7
)

type VerifierRecord struct {
	Name         string
	VerifierType uint16
	Controller   common.Address
	VerifierAddr common.Address
	PolicyRef    [32]byte
	Version      uint32
	Status       VerifierStatus
	CreatedAt    uint64
	UpdatedAt    uint64
	UpdatedBy    common.Address
	StatusRef    [32]byte
}

type SubjectVerificationRecord struct {
	Subject    common.Address
	ProofType  string
	VerifiedAt uint64
	ExpiryMS   uint64
	Status     VerificationStatus
	UpdatedAt  uint64
	UpdatedBy  common.Address
	StatusRef  [32]byte
}

var (
	ErrVerifierExists             = errors.New("verifyregistry: verifier already registered")
	ErrVerifierNotFound           = errors.New("verifyregistry: verifier not found")
	ErrVerifierAlreadyRevoked     = errors.New("verifyregistry: verifier already revoked")
	ErrVerifierInactive           = errors.New("verifyregistry: verifier inactive")
	ErrInvalidVerifier            = errors.New("verifyregistry: invalid verifier payload")
	ErrInvalidVerification        = errors.New("verifyregistry: invalid verification payload")
	ErrVerificationNotFound       = errors.New("verifyregistry: verification not found")
	ErrVerificationAlreadyRevoked = errors.New("verifyregistry: verification already revoked")
	ErrUnauthorizedVerifier       = errors.New("verifyregistry: sender is not verifier controller")
)

func (s VerificationStatus) String() string {
	switch s {
	case VerificationRevoked:
		return "revoked"
	case VerificationExpired:
		return "expired"
	default:
		return "active"
	}
}

func VerifierTypeName(verifierType uint16) string {
	switch verifierType {
	case VerifierTypeZK:
		return "zk_proof"
	case VerifierTypeOracle:
		return "oracle_attestation"
	case VerifierTypeAttestation:
		return "attestation"
	case VerifierTypeReceipt:
		return "runtime_receipt"
	case VerifierTypeConsensus:
		return "consensus_verification"
	case VerifierTypeTLSNotary:
		return "tlsnotary_attestation"
	case VerifierTypeCommittee:
		return "committee_consensus"
	default:
		return "custom"
	}
}

func ProofClassName(proofType string, verifierType uint16) string {
	switch verifierType {
	case VerifierTypeTLSNotary:
		return "tlsnotary_attestation"
	case VerifierTypeReceipt:
		return "runtime_receipt"
	case VerifierTypeCommittee, VerifierTypeConsensus:
		return "committee_consensus"
	case VerifierTypeOracle:
		return "oracle_attestation"
	case VerifierTypeAttestation:
		return "attestation"
	case VerifierTypeZK:
		return "zk_proof"
	}
	switch proofType {
	case "tlsnotary", "tls_notary":
		return "tlsnotary_attestation"
	case "receipt", "runtime_receipt", "settlement_receipt":
		return "runtime_receipt"
	case "consensus", "committee", "m_of_n_consensus":
		return "committee_consensus"
	case "attestation":
		return "attestation"
	case "oracle":
		return "oracle_attestation"
	default:
		return VerifierTypeName(verifierType)
	}
}
