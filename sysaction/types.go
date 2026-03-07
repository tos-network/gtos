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
	ActionValidatorRegister         ActionKind = "VALIDATOR_REGISTER"
	ActionValidatorWithdraw         ActionKind = "VALIDATOR_WITHDRAW"
	ActionValidatorEnterMaintenance ActionKind = "VALIDATOR_ENTER_MAINTENANCE"
	ActionValidatorExitMaintenance  ActionKind = "VALIDATOR_EXIT_MAINTENANCE"
	// Account signer metadata update.
	ActionAccountSetSigner ActionKind = "ACCOUNT_SET_SIGNER"

	// Agent lifecycle.
	ActionAgentRegister      ActionKind = "AGENT_REGISTER"
	ActionAgentUpdateProfile ActionKind = "AGENT_UPDATE_PROFILE"
	ActionAgentIncreaseStake ActionKind = "AGENT_INCREASE_STAKE"
	ActionAgentDecreaseStake ActionKind = "AGENT_DECREASE_STAKE"
	ActionAgentSuspend       ActionKind = "AGENT_SUSPEND"
	ActionAgentUnsuspend     ActionKind = "AGENT_UNSUSPEND"

	// Capability management.
	ActionCapabilityRegister ActionKind = "CAPABILITY_REGISTER"
	ActionCapabilityGrant    ActionKind = "CAPABILITY_GRANT"
	ActionCapabilityRevoke   ActionKind = "CAPABILITY_REVOKE"

	// Delegation nonce tracking.
	ActionDelegationMarkUsed ActionKind = "DELEGATION_MARK_USED"
	ActionDelegationRevoke   ActionKind = "DELEGATION_REVOKE"

	// Reputation scoring.
	ActionReputationAuthorizeScorer ActionKind = "REPUTATION_AUTHORIZE_SCORER"
	ActionReputationRecordScore     ActionKind = "REPUTATION_RECORD_SCORE"

	// KYC lifecycle.
	ActionKYCSet     ActionKind = "KYC_SET"
	ActionKYCSuspend ActionKind = "KYC_SUSPEND"

	// TNS (TOS Name Service).
	ActionTNSRegister ActionKind = "TNS_REGISTER"

	// Referral relationship.
	ActionReferralBind ActionKind = "REFERRAL_BIND"

	// Scheduled tasks.
	ActionTaskSchedule ActionKind = "TASK_SCHEDULE"
	ActionTaskCancel   ActionKind = "TASK_CANCEL"
)

// SysAction is the top-level envelope stored in tx.Data for system action txs.
type SysAction struct {
	Action  ActionKind      `json:"action"`
	Payload json.RawMessage `json:"payload,omitempty"`
}
