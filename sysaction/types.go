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

	// Group lifecycle.
	ActionGroupRegister    ActionKind = "GROUP_REGISTER"
	ActionGroupStateCommit ActionKind = "GROUP_STATE_COMMIT"

	// Lease-contract lifecycle.
	ActionLeaseDeploy ActionKind = "LEASE_DEPLOY"
	ActionLeaseRenew  ActionKind = "LEASE_RENEW"
	ActionLeaseClose  ActionKind = "LEASE_CLOSE"

	// Gateway relay lifecycle.
	ActionGatewayRegister   ActionKind = "GATEWAY_REGISTER"
	ActionGatewayUpdate     ActionKind = "GATEWAY_UPDATE"
	ActionGatewayDeregister ActionKind = "GATEWAY_DEREGISTER"

	// Settlement callbacks and async fulfillment.
	ActionSettlementRegisterCallback ActionKind = "SETTLEMENT_REGISTER_CALLBACK"
	ActionSettlementExecuteCallback  ActionKind = "SETTLEMENT_EXECUTE_CALLBACK"
	ActionSettlementFulfillAsync     ActionKind = "SETTLEMENT_FULFILL_ASYNC"

	// Policy wallet primitives.
	ActionPolicySetSpendCaps      ActionKind = "POLICY_SET_SPEND_CAPS"
	ActionPolicySetAllowlist      ActionKind = "POLICY_SET_ALLOWLIST"
	ActionPolicySetTerminalPolicy ActionKind = "POLICY_SET_TERMINAL_POLICY"
	ActionPolicyAuthorizeDelegate ActionKind = "POLICY_AUTHORIZE_DELEGATE"
	ActionPolicyRevokeDelegate    ActionKind = "POLICY_REVOKE_DELEGATE"
	ActionPolicySetGuardian       ActionKind = "POLICY_SET_GUARDIAN"
	ActionPolicyInitiateRecovery  ActionKind = "POLICY_INITIATE_RECOVERY"
	ActionPolicyCancelRecovery    ActionKind = "POLICY_CANCEL_RECOVERY"
	ActionPolicyCompleteRecovery  ActionKind = "POLICY_COMPLETE_RECOVERY"
	ActionPolicySuspend           ActionKind = "POLICY_SUSPEND"
	ActionPolicyUnsuspend         ActionKind = "POLICY_UNSUSPEND"
	ActionPolicySetAuditorKey     ActionKind = "POLICY_SET_AUDITOR_KEY"

	// Protocol registry lifecycle.
	ActionRegistryRegisterCap         ActionKind = "REGISTRY_REGISTER_CAP"
	ActionRegistryDeprecateCap        ActionKind = "REGISTRY_DEPRECATE_CAP"
	ActionRegistryRevokeCap           ActionKind = "REGISTRY_REVOKE_CAP"
	ActionRegistryGrantDelegation     ActionKind = "REGISTRY_GRANT_DELEGATION"
	ActionRegistryRevokeDelegation    ActionKind = "REGISTRY_REVOKE_DELEGATION"
	ActionRegistryRegisterVerifier    ActionKind = "REGISTRY_REGISTER_VERIFIER"
	ActionRegistryDeactivateVerifier  ActionKind = "REGISTRY_DEACTIVATE_VERIFIER"
	ActionRegistryAttestVerification  ActionKind = "REGISTRY_ATTEST_VERIFICATION"
	ActionRegistryRevokeVerification  ActionKind = "REGISTRY_REVOKE_VERIFICATION"
	ActionRegistryRegisterPayPolicy   ActionKind = "REGISTRY_REGISTER_PAY_POLICY"
	ActionRegistryDeactivatePayPolicy ActionKind = "REGISTRY_DEACTIVATE_PAY_POLICY"

	// Package publishing registry lifecycle.
	ActionPackageRegisterPublisher  ActionKind = "PACKAGE_REGISTER_PUBLISHER"
	ActionPackageSetPublisherStatus ActionKind = "PACKAGE_SET_PUBLISHER_STATUS"
	ActionPackagePublish            ActionKind = "PACKAGE_PUBLISH"
	ActionPackageDeprecate          ActionKind = "PACKAGE_DEPRECATE"
	ActionPackageRevoke             ActionKind = "PACKAGE_REVOKE"
)

// SysAction is the top-level envelope stored in tx.Data for system action txs.
type SysAction struct {
	Action  ActionKind      `json:"action"`
	Payload json.RawMessage `json:"payload,omitempty"`
}
