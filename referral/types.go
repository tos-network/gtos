package referral

import "errors"

var (
	ErrReferralAlreadyBound  = errors.New("referral: already bound to a referrer")
	ErrReferralSelf          = errors.New("referral: cannot refer yourself")
	ErrReferralCircular      = errors.New("referral: would create a circular reference")
	ErrReferralInvalidLevels = errors.New("referral: levels must be 1–20")
)
