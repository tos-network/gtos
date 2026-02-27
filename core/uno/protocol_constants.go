package uno

// Protocol-level frozen constants for UNO v1.
//
// Any change to these values is consensus/signing-impacting and must be treated
// as a protocol upgrade.
const (
	ProtocolPayloadPrefix = "GTOSUNO1"

	ActionIDShield   uint8 = 0x02
	ActionIDTransfer uint8 = 0x03
	ActionIDUnshield uint8 = 0x04

	TranscriptContextVersion byte = 1
	TranscriptNativeAssetTag byte = 0

	TranscriptLabelChainContext = "chain-ctx"
	TranscriptDomainShieldV1    = "uno-shield-v1"
	TranscriptDomainTransferV1  = "uno-transfer-v1"
	TranscriptDomainUnshieldV1  = "uno-unshield-v1"
	TranscriptDomainSeparator   = "|"
)

var (
	// FrozenPayloadFieldOrder maps each UNO action to its canonical payload
	// field ordering as encoded in the action body.
	FrozenPayloadFieldOrder = map[uint8][]string{
		ActionIDShield:   {"amount", "new_sender_ciphertext", "proof_bundle", "encrypted_memo"},
		ActionIDTransfer: {"to", "new_sender_ciphertext", "receiver_delta_ciphertext", "proof_bundle", "encrypted_memo"},
		ActionIDUnshield: {"to", "amount", "new_sender_ciphertext", "proof_bundle", "encrypted_memo"},
	}
)
