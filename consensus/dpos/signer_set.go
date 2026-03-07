package dpos

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/rlp"
)

// ValidatorSigner holds the signer metadata for one validator at a checkpoint pre-state.
// Validators are ordered ascending by Address (raw byte order) for deterministic bitmap indexing.
type ValidatorSigner struct {
	Address    common.Address
	SignerType string // canonical signer type (e.g. "ed25519")
	SignerPub  []byte // canonical public key bytes
}

// accountSignerState is the minimal state interface required to read and write account
// signer metadata. Both GetState and SetState are required to satisfy accountsigner.stateDB.
type accountSignerState interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)
}

// loadSignerSet loads and returns the ordered ValidatorSigner list for the checkpoint
// pre-state. Every active validator in the snapshot must have valid ed25519 signer
// metadata; an error is returned if any validator fails this check.
func loadSignerSet(snap *Snapshot, state accountSignerState) ([]ValidatorSigner, error) {
	if snap == nil {
		return nil, errors.New("dpos: nil snapshot for checkpoint signer set")
	}
	if len(snap.Validators) == 0 {
		return nil, errors.New("dpos: empty validator set in snapshot")
	}

	signers := make([]ValidatorSigner, 0, len(snap.Validators))
	for _, addr := range snap.Validators {
		signerType, signerValue, ok := accountsigner.Get(state, addr)
		if !ok {
			return nil, fmt.Errorf("dpos: validator %s has no signer metadata", addr.Hex())
		}
		normalizedType, normalizedPub, _, err := accountsigner.NormalizeSigner(signerType, signerValue)
		if err != nil {
			return nil, fmt.Errorf("dpos: validator %s signer normalize error: %w", addr.Hex(), err)
		}
		if normalizedType != accountsigner.SignerTypeEd25519 {
			return nil, fmt.Errorf("dpos: checkpoint finality v1 requires ed25519, validator %s has %s",
				addr.Hex(), normalizedType)
		}
		derived, err := accountsigner.AddressFromSigner(normalizedType, normalizedPub)
		if err != nil {
			return nil, fmt.Errorf("dpos: validator %s signer address derivation error: %w", addr.Hex(), err)
		}
		if derived != addr {
			return nil, fmt.Errorf("dpos: validator %s signer pubkey maps to %s (mismatch)",
				addr.Hex(), derived.Hex())
		}
		signers = append(signers, ValidatorSigner{
			Address:    addr,
			SignerType: normalizedType,
			SignerPub:  normalizedPub,
		})
	}

	// Sort ascending by address raw byte order (deterministic bitmap indexing).
	sort.Slice(signers, func(i, j int) bool {
		return bytes.Compare(signers[i].Address[:], signers[j].Address[:]) < 0
	})
	return signers, nil
}

// computeValidatorSetHash computes keccak256(RLP([{address, signerType, signerPub}, ...]))
// over the ordered signer set. The signers slice must already be sorted ascending by address.
// This hash binds checkpoint votes to both validator addresses and their consensus public keys.
func computeValidatorSetHash(signers []ValidatorSigner) common.Hash {
	type record struct {
		Address    []byte
		SignerType string
		SignerPub  []byte
	}
	records := make([]record, len(signers))
	for i, s := range signers {
		records[i] = record{
			Address:    s.Address.Bytes(),
			SignerType: s.SignerType,
			SignerPub:  s.SignerPub,
		}
	}
	encoded, _ := rlp.EncodeToBytes(records)
	return crypto.Keccak256Hash(encoded)
}
