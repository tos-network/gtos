package verifyregistry

import (
	"encoding/binary"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

type stateDB interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)
}

func (r SubjectVerificationRecord) EffectiveStatus(nowMS uint64) VerificationStatus {
	switch r.Status {
	case VerificationRevoked:
		return VerificationRevoked
	default:
		if r.ExpiryMS > 0 && nowMS >= r.ExpiryMS {
			return VerificationExpired
		}
		return VerificationActive
	}
}

func verifierSlot(name string) common.Hash {
	key := append([]byte("vr\x00reg\x00"), []byte(name)...)
	return common.BytesToHash(crypto.Keccak256(key))
}

func verificationSlot(subject common.Address, proofType string) common.Hash {
	key := make([]byte, 0, len("vr\x00sub\x00")+common.AddressLength+len(proofType))
	key = append(key, "vr\x00sub\x00"...)
	key = append(key, subject.Bytes()...)
	key = append(key, []byte(proofType)...)
	return common.BytesToHash(crypto.Keccak256(key))
}

func slotOffset(base common.Hash, off uint64) common.Hash {
	n := base.Big()
	n.Add(n, new(big.Int).SetUint64(off))
	return common.BigToHash(n)
}

// Verifier layout:
// 0: verifierType(u16)|version(u32)|status(u8)
// 1: verifierAddr
// 2: policyRef
func ReadVerifier(db stateDB, name string) VerifierRecord {
	base := verifierSlot(name)
	packed := db.GetState(params.VerificationRegistryAddress, base)
	if packed == (common.Hash{}) {
		return VerifierRecord{}
	}
	rec := VerifierRecord{Name: name}
	rec.VerifierType = binary.BigEndian.Uint16(packed[0:2])
	rec.Version = binary.BigEndian.Uint32(packed[2:6])
	rec.Status = VerifierStatus(packed[6])
	addrRaw := db.GetState(params.VerificationRegistryAddress, slotOffset(base, 1))
	rec.VerifierAddr = common.BytesToAddress(addrRaw[:])
	policyRaw := db.GetState(params.VerificationRegistryAddress, slotOffset(base, 2))
	copy(rec.PolicyRef[:], policyRaw[:])
	return rec
}

func WriteVerifier(db stateDB, rec VerifierRecord) {
	base := verifierSlot(rec.Name)
	var packed common.Hash
	binary.BigEndian.PutUint16(packed[0:2], rec.VerifierType)
	binary.BigEndian.PutUint32(packed[2:6], rec.Version)
	packed[6] = byte(rec.Status)
	db.SetState(params.VerificationRegistryAddress, base, packed)
	var addr common.Hash
	copy(addr[:], rec.VerifierAddr.Bytes())
	db.SetState(params.VerificationRegistryAddress, slotOffset(base, 1), addr)
	db.SetState(params.VerificationRegistryAddress, slotOffset(base, 2), common.Hash(rec.PolicyRef))
}

// Subject verification layout:
// 0: verifiedAt(u64)|expiryMS(u64)|status(u8)
func ReadSubjectVerification(db stateDB, subject common.Address, proofType string) SubjectVerificationRecord {
	base := verificationSlot(subject, proofType)
	packed := db.GetState(params.VerificationRegistryAddress, base)
	if packed == (common.Hash{}) {
		return SubjectVerificationRecord{}
	}
	return SubjectVerificationRecord{
		Subject:    subject,
		ProofType:  proofType,
		VerifiedAt: binary.BigEndian.Uint64(packed[0:8]),
		ExpiryMS:   binary.BigEndian.Uint64(packed[8:16]),
		Status:     VerificationStatus(packed[16]),
	}
}

func WriteSubjectVerification(db stateDB, rec SubjectVerificationRecord) {
	base := verificationSlot(rec.Subject, rec.ProofType)
	var packed common.Hash
	binary.BigEndian.PutUint64(packed[0:8], rec.VerifiedAt)
	binary.BigEndian.PutUint64(packed[8:16], rec.ExpiryMS)
	packed[16] = byte(rec.Status)
	db.SetState(params.VerificationRegistryAddress, base, packed)
}
