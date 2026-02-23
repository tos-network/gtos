// Package sysaction implements the GTOS system action protocol.
//
// System actions are special transactions sent to params.SystemActionAddress.
// Their tx.Data field is a JSON-encoded SysAction message. The TVM is never
// invoked; instead the state processor calls sysaction.Execute() which
// dispatches to the appropriate handler.
package sysaction

import "encoding/json"

// ActionKind identifies the type of system action.
type ActionKind string

const (
	// Validator lifecycle (DPoS)
	ActionValidatorRegister ActionKind = "VALIDATOR_REGISTER"
	ActionValidatorWithdraw ActionKind = "VALIDATOR_WITHDRAW"
	// Account signer metadata update.
	ActionAccountSetSigner ActionKind = "ACCOUNT_SET_SIGNER"
)

// SysAction is the top-level envelope stored in tx.Data for system action txs.
type SysAction struct {
	Action  ActionKind      `json:"action"`
	Payload json.RawMessage `json:"payload,omitempty"`
}
