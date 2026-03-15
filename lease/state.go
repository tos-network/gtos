package lease

import (
	"encoding/binary"
	"math"
	"math/big"

	"github.com/tos-network/gtos/common"
	vmtypes "github.com/tos-network/gtos/core/vmtypes"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

func leaseSlot(addr common.Address, field string) common.Hash {
	key := make([]byte, 0, common.AddressLength+1+len(field))
	key = append(key, addr.Bytes()...)
	key = append(key, 0x00)
	key = append(key, field...)
	return common.BytesToHash(crypto.Keccak256(key))
}

func epochCountSlot(epoch uint64) common.Hash {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], epoch)
	return common.BytesToHash(crypto.Keccak256(append([]byte("lease\x00expiry_count\x00"), buf[:]...)))
}

func epochEntrySlot(epoch uint64, seq uint64) common.Hash {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[:8], epoch)
	binary.BigEndian.PutUint64(buf[8:], seq)
	return common.BytesToHash(crypto.Keccak256(append([]byte("lease\x00expiry_entry\x00"), buf[:]...)))
}

func epochCursorSlot(epoch uint64) common.Hash {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], epoch)
	return common.BytesToHash(crypto.Keccak256(append([]byte("lease\x00expiry_cursor\x00"), buf[:]...)))
}

func pruneHeadEpochSlot() common.Hash {
	return common.BytesToHash(crypto.Keccak256([]byte("lease\x00prune_head_epoch")))
}

func tombstoneSlot(addr common.Address, field string) common.Hash {
	key := make([]byte, 0, common.AddressLength+1+len(field))
	key = append(key, []byte("lease\x00tombstone\x00")...)
	key = append(key, addr.Bytes()...)
	key = append(key, 0x00)
	key = append(key, field...)
	return common.BytesToHash(crypto.Keccak256(key))
}

func readUint64(db vmtypes.StateDB, slot common.Hash) uint64 {
	raw := db.GetState(params.LeaseRegistryAddress, slot)
	return binary.BigEndian.Uint64(raw[24:])
}

func writeUint64(db vmtypes.StateDB, slot common.Hash, v uint64) {
	var raw common.Hash
	binary.BigEndian.PutUint64(raw[24:], v)
	db.SetState(params.LeaseRegistryAddress, slot, raw)
}

func writeBig(db vmtypes.StateDB, slot common.Hash, v *big.Int) {
	if v == nil {
		db.SetState(params.LeaseRegistryAddress, slot, common.Hash{})
		return
	}
	db.SetState(params.LeaseRegistryAddress, slot, common.BigToHash(v))
}

func readBig(db vmtypes.StateDB, slot common.Hash) *big.Int {
	return db.GetState(params.LeaseRegistryAddress, slot).Big()
}

func writeAddress(db vmtypes.StateDB, slot common.Hash, addr common.Address) {
	var raw common.Hash
	copy(raw[:], addr[:])
	db.SetState(params.LeaseRegistryAddress, slot, raw)
}

func readAddress(db vmtypes.StateDB, slot common.Hash) common.Address {
	return common.BytesToAddress(db.GetState(params.LeaseRegistryAddress, slot).Bytes())
}

// ReadMeta loads the metadata for a lease contract.
func ReadMeta(db vmtypes.StateDB, addr common.Address) (Meta, bool) {
	if db.GetState(params.LeaseRegistryAddress, leaseSlot(addr, "mode")) == (common.Hash{}) {
		return Meta{}, false
	}
	meta := Meta{
		LeaseOwner:          readAddress(db, leaseSlot(addr, "lease_owner")),
		CreatedAtBlock:      readUint64(db, leaseSlot(addr, "created_at_block")),
		ExpireAtBlock:       readUint64(db, leaseSlot(addr, "expire_at_block")),
		GraceUntilBlock:     readUint64(db, leaseSlot(addr, "grace_until_block")),
		CodeBytes:           readUint64(db, leaseSlot(addr, "code_bytes")),
		DepositWei:          readBig(db, leaseSlot(addr, "deposit_wei")),
		ScheduledPruneEpoch: readUint64(db, leaseSlot(addr, "scheduled_prune_epoch")),
		ScheduledPruneSeq:   readUint64(db, leaseSlot(addr, "scheduled_prune_seq")),
	}
	return meta, true
}

// WriteMeta persists the metadata for a lease contract.
func WriteMeta(db vmtypes.StateDB, addr common.Address, meta Meta) {
	var mode common.Hash
	mode[31] = 1
	db.SetState(params.LeaseRegistryAddress, leaseSlot(addr, "mode"), mode)
	writeAddress(db, leaseSlot(addr, "lease_owner"), meta.LeaseOwner)
	writeUint64(db, leaseSlot(addr, "created_at_block"), meta.CreatedAtBlock)
	writeUint64(db, leaseSlot(addr, "expire_at_block"), meta.ExpireAtBlock)
	writeUint64(db, leaseSlot(addr, "grace_until_block"), meta.GraceUntilBlock)
	writeUint64(db, leaseSlot(addr, "code_bytes"), meta.CodeBytes)
	writeBig(db, leaseSlot(addr, "deposit_wei"), meta.DepositWei)
	writeUint64(db, leaseSlot(addr, "scheduled_prune_epoch"), meta.ScheduledPruneEpoch)
	writeUint64(db, leaseSlot(addr, "scheduled_prune_seq"), meta.ScheduledPruneSeq)
}

// ClearMeta removes lease metadata for a pruned contract.
func ClearMeta(db vmtypes.StateDB, addr common.Address) {
	for _, field := range []string{
		"mode",
		"lease_owner",
		"created_at_block",
		"expire_at_block",
		"grace_until_block",
		"code_bytes",
		"deposit_wei",
		"scheduled_prune_epoch",
		"scheduled_prune_seq",
	} {
		db.SetState(params.LeaseRegistryAddress, leaseSlot(addr, field), common.Hash{})
	}
}

// PruneEligibleBlock returns the first block at which the lease becomes prunable.
func PruneEligibleBlock(meta Meta, chainConfig *params.ChainConfig) uint64 {
	epochLength := EpochLength(chainConfig)
	if meta.ScheduledPruneEpoch == 0 || epochLength == 0 {
		return 0
	}
	if meta.ScheduledPruneEpoch > math.MaxUint64/epochLength {
		return math.MaxUint64
	}
	return meta.ScheduledPruneEpoch * epochLength
}

// EffectiveStatus derives the runtime lifecycle state at the given block.
func EffectiveStatus(meta Meta, blockNumber uint64, chainConfig *params.ChainConfig) Status {
	if pruneAt := PruneEligibleBlock(meta, chainConfig); pruneAt != 0 && blockNumber >= pruneAt && blockNumber >= meta.GraceUntilBlock {
		return StatusPrunable
	}
	if blockNumber < meta.ExpireAtBlock {
		return StatusActive
	}
	if blockNumber < meta.GraceUntilBlock {
		return StatusFrozen
	}
	return StatusExpired
}

// CheckCallable rejects calls to frozen, expired, or tombstoned lease contracts.
func CheckCallable(db vmtypes.StateDB, addr common.Address, blockNumber uint64, chainConfig *params.ChainConfig) error {
	if HasTombstone(db, addr) {
		return ErrLeaseTombstoned
	}
	meta, ok := ReadMeta(db, addr)
	if !ok {
		return nil
	}
	switch EffectiveStatus(meta, blockNumber, chainConfig) {
	case StatusActive:
		return nil
	case StatusFrozen:
		return ErrLeaseFrozen
	default:
		return ErrLeaseExpired
	}
}

// RejectTombstoned rejects any interaction that would resurrect a pruned address.
func RejectTombstoned(db vmtypes.StateDB, addr common.Address) error {
	if HasTombstone(db, addr) {
		return ErrLeaseTombstoned
	}
	return nil
}

// HasTombstone reports whether the address has been permanently pruned.
func HasTombstone(db vmtypes.StateDB, addr common.Address) bool {
	raw := db.GetState(params.LeaseRegistryAddress, tombstoneSlot(addr, "marker"))
	return raw[31] == 1
}

// ReadTombstone loads the tombstone for a pruned lease address.
func ReadTombstone(db vmtypes.StateDB, addr common.Address) (Tombstone, bool) {
	if !HasTombstone(db, addr) {
		return Tombstone{}, false
	}
	return Tombstone{
		LastCodeHash:   db.GetState(params.LeaseRegistryAddress, tombstoneSlot(addr, "code_hash")),
		ExpiredAtBlock: readUint64(db, tombstoneSlot(addr, "expired_at_block")),
	}, true
}

// WriteTombstone persists a permanent non-reuse marker for a pruned address.
func WriteTombstone(db vmtypes.StateDB, addr common.Address, tombstone Tombstone) {
	var marker common.Hash
	marker[31] = 1
	db.SetState(params.LeaseRegistryAddress, tombstoneSlot(addr, "marker"), marker)
	db.SetState(params.LeaseRegistryAddress, tombstoneSlot(addr, "code_hash"), tombstone.LastCodeHash)
	writeUint64(db, tombstoneSlot(addr, "expired_at_block"), tombstone.ExpiredAtBlock)
}

// AppendPruneCandidate adds a contract address to the deterministic prune queue.
func AppendPruneCandidate(db vmtypes.StateDB, epoch uint64, addr common.Address) uint64 {
	count := readUint64(db, epochCountSlot(epoch))
	writeAddress(db, epochEntrySlot(epoch, count), addr)
	writeUint64(db, epochCountSlot(epoch), count+1)
	return count
}

// ReadPruneEntryCount returns the number of addresses scheduled for an epoch.
func ReadPruneEntryCount(db vmtypes.StateDB, epoch uint64) uint64 {
	return readUint64(db, epochCountSlot(epoch))
}

// ReadPruneCursor returns the next unprocessed index for an epoch queue.
func ReadPruneCursor(db vmtypes.StateDB, epoch uint64) uint64 {
	return readUint64(db, epochCursorSlot(epoch))
}

// WritePruneCursor persists the next unprocessed index for an epoch queue.
func WritePruneCursor(db vmtypes.StateDB, epoch uint64, cursor uint64) {
	writeUint64(db, epochCursorSlot(epoch), cursor)
}

// ReadPruneHeadEpoch returns the earliest epoch that may still have pending work.
func ReadPruneHeadEpoch(db vmtypes.StateDB) uint64 {
	return readUint64(db, pruneHeadEpochSlot())
}

// WritePruneHeadEpoch persists the earliest epoch that may still have pending work.
func WritePruneHeadEpoch(db vmtypes.StateDB, epoch uint64) {
	writeUint64(db, pruneHeadEpochSlot(), epoch)
}

// ReadPruneEntry returns the address stored at the given epoch/seq position.
func ReadPruneEntry(db vmtypes.StateDB, epoch uint64, seq uint64) common.Address {
	return readAddress(db, epochEntrySlot(epoch, seq))
}

// ClearPruneEpoch resets the queue length after a deterministic sweep.
func ClearPruneEpoch(db vmtypes.StateDB, epoch uint64) {
	db.SetState(params.LeaseRegistryAddress, epochCountSlot(epoch), common.Hash{})
	db.SetState(params.LeaseRegistryAddress, epochCursorSlot(epoch), common.Hash{})
}

// ScheduleMeta appends the current lease metadata to the prune queue and records its cursor.
func ScheduleMeta(db vmtypes.StateDB, addr common.Address, meta *Meta, chainConfig *params.ChainConfig) {
	epoch := PruneEpoch(meta.GraceUntilBlock, EpochLength(chainConfig))
	seq := AppendPruneCandidate(db, epoch, addr)
	meta.ScheduledPruneEpoch = epoch
	meta.ScheduledPruneSeq = seq
	head := ReadPruneHeadEpoch(db)
	if head == 0 || epoch < head {
		WritePruneHeadEpoch(db, epoch)
	}
}

// Activate creates and persists a fresh lease metadata entry.
func Activate(db vmtypes.StateDB, addr common.Address, owner common.Address, createdAt uint64, leaseBlocks uint64, codeBytes uint64, deposit *big.Int, chainConfig *params.ChainConfig) (Meta, error) {
	meta, err := NewMeta(owner, createdAt, leaseBlocks, codeBytes, deposit, chainConfig)
	if err != nil {
		return Meta{}, err
	}
	ScheduleMeta(db, addr, &meta, chainConfig)
	WriteMeta(db, addr, meta)
	return meta, nil
}
