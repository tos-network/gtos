package boundary

// SchemaVersion for boundary package compatibility.
const SchemaVersion = "0.1.0"

// TerminalClass identifies the type of entry point.
type TerminalClass string

const (
	TerminalApp   TerminalClass = "app"
	TerminalCard  TerminalClass = "card"
	TerminalPOS   TerminalClass = "pos"
	TerminalVoice TerminalClass = "voice"
	TerminalKiosk TerminalClass = "kiosk"
	TerminalRobot TerminalClass = "robot"
	TerminalAPI   TerminalClass = "api"
)

// TrustTier represents the trust level of a terminal or session.
type TrustTier uint8

const (
	TrustTierUntrusted TrustTier = 0
	TrustTierLow       TrustTier = 1
	TrustTierMedium    TrustTier = 2
	TrustTierHigh      TrustTier = 3
	TrustTierFull      TrustTier = 4
)

// AgentRole identifies the role an agent plays in an action.
type AgentRole string

const (
	RoleRequester    AgentRole = "requester"
	RoleActor        AgentRole = "actor"
	RoleProvider     AgentRole = "provider"
	RoleSponsor      AgentRole = "sponsor"
	RoleSigner       AgentRole = "signer"
	RoleGateway      AgentRole = "gateway"
	RoleOracle       AgentRole = "oracle"
	RoleCounterparty AgentRole = "counterparty"
	RoleGuardian     AgentRole = "guardian"
)
