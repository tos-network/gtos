package kyc

import "errors"

// KycStatus is the on-chain status byte for a KYC record.
type KycStatus uint8

const (
	KycNone      KycStatus = 0 // never set
	KycActive    KycStatus = 1 // valid and active
	KycSuspended KycStatus = 2 // suspended by committee
)

// Valid cumulative KYC levels (2^n − 1 pattern).
const (
	KycLevelAnonymous uint16 = 0
	KycLevelBasic     uint16 = 7
	KycLevelIdentity  uint16 = 31
	KycLevelAddress   uint16 = 63
	KycLevelFunds     uint16 = 255
	KycLevelEDD       uint16 = 2047
	KycLevelInstitute uint16 = 8191
	KycLevelAudit     uint16 = 16383
	KycLevelRegulated uint16 = 32767
)

var (
	ErrKYCNotCommittee     = errors.New("kyc: caller is not an authorized committee member")
	ErrKYCInvalidLevel     = errors.New("kyc: level is not a valid cumulative value")
	ErrKYCNotActive        = errors.New("kyc: account has no active KYC record")
	ErrKYCAlreadySuspended = errors.New("kyc: account is already suspended")
)

// IsValidLevel returns true if level is one of the nine defined cumulative values.
func IsValidLevel(level uint16) bool {
	switch level {
	case 0, 7, 31, 63, 255, 2047, 8191, 16383, 32767:
		return true
	}
	return false
}

// TierOf returns the tier number (0–8) for a valid cumulative level.
func TierOf(level uint16) uint8 {
	switch level {
	case 7:
		return 1
	case 31:
		return 2
	case 63:
		return 3
	case 255:
		return 4
	case 2047:
		return 5
	case 8191:
		return 6
	case 16383:
		return 7
	case 32767:
		return 8
	}
	return 0
}
