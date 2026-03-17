package sysaction

import (
	"errors"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	vmtypes "github.com/tos-network/gtos/core/vmtypes"
)

// Sentinel errors for oracle and proof verification hooks.
var (
	ErrOracleNotRegistered = errors.New("sysaction: oracle address not registered")
	ErrOracleDataStale     = errors.New("sysaction: oracle data exceeds max age")
	ErrOracleDataMismatch  = errors.New("sysaction: oracle data hash mismatch")
	ErrProofInvalidType    = errors.New("sysaction: unknown proof type")
	ErrProofDataEmpty      = errors.New("sysaction: proof data is empty")
	ErrProofRootMismatch   = errors.New("sysaction: proof root mismatch")
)

// OracleHook allows contracts to request oracle data verification.
type OracleHook struct {
	OracleAddress common.Address `json:"oracle_address"`
	DataKey       string         `json:"data_key"`
	ExpectedHash  common.Hash    `json:"expected_hash,omitempty"`
	MaxAge        uint64         `json:"max_age"` // max seconds since last update
	CallbackData  []byte         `json:"callback_data,omitempty"`
}

// ProofVerificationHook allows verification of external proofs.
type ProofVerificationHook struct {
	ProofType    string         `json:"proof_type"` // "receipt", "signature", "merkle", "zk"
	ProofData    []byte         `json:"proof_data"`
	ExpectedRoot common.Hash    `json:"expected_root,omitempty"`
	VerifierAddr common.Address `json:"verifier_address,omitempty"`
}

// oracleSlot returns a storage slot for oracle data keyed by address and data key.
func oracleSlot(oracle common.Address, field string) common.Hash {
	key := make([]byte, 0, common.AddressLength+1+len("oracle")+1+len(field))
	key = append(key, oracle.Bytes()...)
	key = append(key, 0x00)
	key = append(key, []byte("oracle")...)
	key = append(key, 0x00)
	key = append(key, []byte(field)...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// oracleDataSlot returns a storage slot for oracle data keyed by address and data key.
func oracleDataSlot(oracle common.Address, dataKey string) common.Hash {
	key := make([]byte, 0, common.AddressLength+1+len("oracleData")+1+len(dataKey))
	key = append(key, oracle.Bytes()...)
	key = append(key, 0x00)
	key = append(key, []byte("oracleData")...)
	key = append(key, 0x00)
	key = append(key, []byte(dataKey)...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// oracleTimestampSlot returns a storage slot for the last update timestamp of an oracle data key.
func oracleTimestampSlot(oracle common.Address, dataKey string) common.Hash {
	key := make([]byte, 0, common.AddressLength+1+len("oracleTs")+1+len(dataKey))
	key = append(key, oracle.Bytes()...)
	key = append(key, 0x00)
	key = append(key, []byte("oracleTs")...)
	key = append(key, 0x00)
	key = append(key, []byte(dataKey)...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// ValidateOracleHook checks that oracle data is fresh and matches expectations.
// It reads oracle registration, data hash, and timestamp from state, then
// verifies age and hash constraints.
func ValidateOracleHook(state vmtypes.StateDB, hook *OracleHook, blockTimestamp uint64) (bool, error) {
	// Check oracle is registered (has a non-zero registration slot).
	regSlot := oracleSlot(hook.OracleAddress, "registered")
	regVal := state.GetState(hook.OracleAddress, regSlot)
	if regVal[31] == 0 {
		return false, ErrOracleNotRegistered
	}

	// Read the stored data hash for the requested key.
	dataHash := state.GetState(hook.OracleAddress, oracleDataSlot(hook.OracleAddress, hook.DataKey))

	// Read the timestamp of the last update.
	tsRaw := state.GetState(hook.OracleAddress, oracleTimestampSlot(hook.OracleAddress, hook.DataKey))
	lastUpdate := tsRaw.Big().Uint64()

	// Check data freshness.
	if hook.MaxAge > 0 && blockTimestamp > lastUpdate+hook.MaxAge {
		return false, ErrOracleDataStale
	}

	// Check expected hash if provided.
	if hook.ExpectedHash != (common.Hash{}) && dataHash != hook.ExpectedHash {
		return false, ErrOracleDataMismatch
	}

	return true, nil
}

// ValidateProofHook performs basic verification of an external proof.
// For "receipt" and "signature" proofs, it checks data hash against ExpectedRoot.
// For "merkle" proofs, it verifies the keccak256 of proof data matches ExpectedRoot.
// For "zk" proofs, it performs a basic non-empty check (full ZK verification
// would be delegated to a verifier contract).
func ValidateProofHook(hook *ProofVerificationHook) (bool, error) {
	if len(hook.ProofData) == 0 {
		return false, ErrProofDataEmpty
	}

	switch hook.ProofType {
	case "receipt", "signature":
		// Verify hash of proof data matches expected root.
		dataHash := crypto.Keccak256Hash(hook.ProofData)
		if hook.ExpectedRoot != (common.Hash{}) && dataHash != hook.ExpectedRoot {
			return false, ErrProofRootMismatch
		}
		return true, nil

	case "merkle":
		// Verify keccak256 of proof data matches expected root.
		dataHash := crypto.Keccak256Hash(hook.ProofData)
		if hook.ExpectedRoot != (common.Hash{}) && dataHash != hook.ExpectedRoot {
			return false, ErrProofRootMismatch
		}
		return true, nil

	case "zk":
		// ZK proof verification is a placeholder; full verification would
		// be delegated to VerifierAddr. Here we just check non-empty data.
		return true, nil

	default:
		return false, ErrProofInvalidType
	}
}
