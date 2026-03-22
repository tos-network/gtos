package paypolicy

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

func policySlot(policyID [32]byte) common.Hash {
	key := append([]byte("pay\x00policy\x00"), policyID[:]...)
	return common.BytesToHash(crypto.Keccak256(key))
}

func ownerAssetSlot(owner common.Address, asset string) common.Hash {
	key := append([]byte("pay\x00owner\x00"), owner.Bytes()...)
	key = append(key, []byte(asset)...)
	return common.BytesToHash(crypto.Keccak256(key))
}

func slotOffset(base common.Hash, off uint64) common.Hash {
	n := base.Big()
	n.Add(n, new(big.Int).SetUint64(off))
	return common.BigToHash(n)
}

func writeAsset(db stateDB, base common.Hash, asset string) {
	var val common.Hash
	if len(asset) > 31 {
		asset = asset[:31]
	}
	val[0] = byte(len(asset))
	copy(val[1:], []byte(asset))
	db.SetState(params.PayPolicyRegistryAddress, slotOffset(base, 1), val)
}

func readAsset(db stateDB, base common.Hash) string {
	raw := db.GetState(params.PayPolicyRegistryAddress, slotOffset(base, 1))
	n := int(raw[0])
	if n == 0 || n > 31 {
		return ""
	}
	return string(raw[1 : 1+n])
}

// Layout:
// 0: owner
// 1: asset short string
// 2: max amount
// 3: rules ref
// 4: kind(u16) | status(u8)
func ReadPolicy(db stateDB, policyID [32]byte) PolicyRecord {
	base := policySlot(policyID)
	raw := db.GetState(params.PayPolicyRegistryAddress, base)
	if raw == (common.Hash{}) {
		return PolicyRecord{}
	}
	rec := PolicyRecord{PolicyID: policyID}
	rec.Owner = common.BytesToAddress(raw[:])
	rec.Asset = readAsset(db, base)
	rec.MaxAmount = db.GetState(params.PayPolicyRegistryAddress, slotOffset(base, 2)).Big()
	rules := db.GetState(params.PayPolicyRegistryAddress, slotOffset(base, 3))
	copy(rec.RulesRef[:], rules[:])
	head := db.GetState(params.PayPolicyRegistryAddress, slotOffset(base, 4))
	rec.Kind = binary.BigEndian.Uint16(head[29:31])
	rec.Status = PolicyStatus(head[31])
	return rec
}

func WritePolicy(db stateDB, rec PolicyRecord) {
	base := policySlot(rec.PolicyID)
	var owner common.Hash
	copy(owner[common.HashLength-common.AddressLength:], rec.Owner.Bytes())
	db.SetState(params.PayPolicyRegistryAddress, base, owner)
	writeAsset(db, base, rec.Asset)
	if rec.MaxAmount == nil {
		rec.MaxAmount = new(big.Int)
	}
	db.SetState(params.PayPolicyRegistryAddress, slotOffset(base, 2), common.BigToHash(rec.MaxAmount))
	db.SetState(params.PayPolicyRegistryAddress, slotOffset(base, 3), common.Hash(rec.RulesRef))
	var head common.Hash
	binary.BigEndian.PutUint16(head[29:31], rec.Kind)
	head[31] = byte(rec.Status)
	db.SetState(params.PayPolicyRegistryAddress, slotOffset(base, 4), head)
	db.SetState(params.PayPolicyRegistryAddress, ownerAssetSlot(rec.Owner, rec.Asset), common.Hash(rec.PolicyID))
}

func ReadPolicyByOwnerAsset(db stateDB, owner common.Address, asset string) PolicyRecord {
	idHash := db.GetState(params.PayPolicyRegistryAddress, ownerAssetSlot(owner, asset))
	if idHash == (common.Hash{}) {
		return PolicyRecord{}
	}
	var policyID [32]byte
	copy(policyID[:], idHash[:])
	return ReadPolicy(db, policyID)
}
