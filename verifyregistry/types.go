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
)

type VerifierRecord struct {
	Name         string
	VerifierType uint16
	VerifierAddr common.Address
	PolicyRef    [32]byte
	Version      uint32
	Status       VerifierStatus
}

type SubjectVerificationRecord struct {
	Subject    common.Address
	ProofType  string
	VerifiedAt uint64
	ExpiryMS   uint64
	Status     VerificationStatus
}

var (
	ErrVerifierExists       = errors.New("verifyregistry: verifier already registered")
	ErrVerifierNotFound     = errors.New("verifyregistry: verifier not found")
	ErrInvalidVerifier      = errors.New("verifyregistry: invalid verifier payload")
	ErrInvalidVerification  = errors.New("verifyregistry: invalid verification payload")
	ErrUnauthorizedVerifier = errors.New("verifyregistry: sender is not verifier controller")
)
