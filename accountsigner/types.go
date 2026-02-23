package accountsigner

import "errors"

const (
	// MaxSignerTypeLen caps signerType bytes accepted by account_set_signer.
	MaxSignerTypeLen = 64
	// MaxSignerValueLen caps signerValue bytes accepted by account_set_signer.
	MaxSignerValueLen = 1024
)

// SetSignerPayload is the system-action payload for ACCOUNT_SET_SIGNER.
type SetSignerPayload struct {
	SignerType  string `json:"signerType"`
	SignerValue string `json:"signerValue"`
}

var (
	ErrInvalidPayload = errors.New("accountsigner: invalid signer payload")
	ErrNonZeroValue   = errors.New("accountsigner: account_set_signer does not accept value")
)
