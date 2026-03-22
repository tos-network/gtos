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
}

type SubjectVerificationRecord struct {
	Subject    common.Address
	ProofType  string
	VerifiedAt uint64
	ExpiryMS   uint64
	Status     VerificationStatus
	UpdatedAt  uint64
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
