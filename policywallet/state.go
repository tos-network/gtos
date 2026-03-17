package policywallet

import (
	"encoding/binary"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

// stateDB is the minimal storage interface required by this package.
// Avoids an import cycle with core/vm (which imports this package).
type stateDB interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)
}

// registry is a shorthand for the PolicyWalletRegistryAddress.
var registry = params.PolicyWalletRegistryAddress

// ---------- Slot helpers ----------

// walletSlot returns a storage slot for a per-wallet scalar field.
// Key = keccak256(addr[20] || 0x00 || field).
func walletSlot(addr common.Address, field string) common.Hash {
	key := make([]byte, 0, common.AddressLength+1+len(field))
	key = append(key, addr.Bytes()...)
	key = append(key, 0x00)
	key = append(key, field...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// walletMapSlot returns a storage slot for a per-wallet mapping field.
// Key = keccak256(addr[20] || 0x00 || field || 0x00 || mapKey).
func walletMapSlot(addr common.Address, field string, mapKey []byte) common.Hash {
	key := make([]byte, 0, common.AddressLength+1+len(field)+1+len(mapKey))
	key = append(key, addr.Bytes()...)
	key = append(key, 0x00)
	key = append(key, field...)
	key = append(key, 0x00)
	key = append(key, mapKey...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// ---------- Owner ----------

// ReadOwner returns the wallet owner address. Zero means not initialised.
func ReadOwner(db stateDB, wallet common.Address) common.Address {
	raw := db.GetState(registry, walletSlot(wallet, "owner"))
	return common.BytesToAddress(raw[:])
}

// WriteOwner writes the wallet owner address.
func WriteOwner(db stateDB, wallet common.Address, owner common.Address) {
	var val common.Hash
	copy(val[common.HashLength-common.AddressLength:], owner.Bytes())
	db.SetState(registry, walletSlot(wallet, "owner"), val)
}

// ---------- Guardian ----------

// ReadGuardian returns the guardian address for wallet.
func ReadGuardian(db stateDB, wallet common.Address) common.Address {
	raw := db.GetState(registry, walletSlot(wallet, "guardian"))
	return common.BytesToAddress(raw[:])
}

// WriteGuardian writes the guardian address for wallet.
func WriteGuardian(db stateDB, wallet common.Address, guardian common.Address) {
	var val common.Hash
	copy(val[common.HashLength-common.AddressLength:], guardian.Bytes())
	db.SetState(registry, walletSlot(wallet, "guardian"), val)
}

// ---------- Suspension ----------

// ReadSuspended returns true if the wallet is suspended.
func ReadSuspended(db stateDB, wallet common.Address) bool {
	raw := db.GetState(registry, walletSlot(wallet, "suspended"))
	return raw[31] != 0
}

// WriteSuspended writes the suspended flag for wallet.
func WriteSuspended(db stateDB, wallet common.Address, suspended bool) {
	var val common.Hash
	if suspended {
		val[31] = 1
	}
	db.SetState(registry, walletSlot(wallet, "suspended"), val)
}

// ---------- Spend caps ----------

// ReadDailyLimit returns the daily spend limit.
func ReadDailyLimit(db stateDB, wallet common.Address) *big.Int {
	raw := db.GetState(registry, walletSlot(wallet, "dailyLimit"))
	return raw.Big()
}

// WriteDailyLimit writes the daily spend limit.
func WriteDailyLimit(db stateDB, wallet common.Address, limit *big.Int) {
	db.SetState(registry, walletSlot(wallet, "dailyLimit"), common.BigToHash(limit))
}

// ReadSingleTxLimit returns the single-transaction spend limit.
func ReadSingleTxLimit(db stateDB, wallet common.Address) *big.Int {
	raw := db.GetState(registry, walletSlot(wallet, "singleTxLimit"))
	return raw.Big()
}

// WriteSingleTxLimit writes the single-transaction spend limit.
func WriteSingleTxLimit(db stateDB, wallet common.Address, limit *big.Int) {
	db.SetState(registry, walletSlot(wallet, "singleTxLimit"), common.BigToHash(limit))
}

// ReadDailySpent returns the amount spent today.
func ReadDailySpent(db stateDB, wallet common.Address) *big.Int {
	raw := db.GetState(registry, walletSlot(wallet, "dailySpent"))
	return raw.Big()
}

// WriteDailySpent writes the daily spent accumulator.
func WriteDailySpent(db stateDB, wallet common.Address, spent *big.Int) {
	db.SetState(registry, walletSlot(wallet, "dailySpent"), common.BigToHash(spent))
}

// ReadSpendDay returns the block number when the daily spend counter was last reset.
func ReadSpendDay(db stateDB, wallet common.Address) uint64 {
	raw := db.GetState(registry, walletSlot(wallet, "spendDay"))
	return raw.Big().Uint64()
}

// WriteSpendDay writes the current spend-day block number.
func WriteSpendDay(db stateDB, wallet common.Address, blockNum uint64) {
	var val common.Hash
	binary.BigEndian.PutUint64(val[24:], blockNum)
	db.SetState(registry, walletSlot(wallet, "spendDay"), val)
}

// ---------- Allowlist ----------

// ReadAllowlisted returns true if target is on wallet's allowlist.
func ReadAllowlisted(db stateDB, wallet common.Address, target common.Address) bool {
	raw := db.GetState(registry, walletMapSlot(wallet, "allowlist", target.Bytes()))
	return raw[31] != 0
}

// WriteAllowlisted sets the allowlist entry for target.
func WriteAllowlisted(db stateDB, wallet common.Address, target common.Address, allowed bool) {
	var val common.Hash
	if allowed {
		val[31] = 1
	}
	db.SetState(registry, walletMapSlot(wallet, "allowlist", target.Bytes()), val)
}

// ---------- Terminal policies ----------

// terminalSlot returns a sub-slot for a terminal-class field.
func terminalFieldSlot(wallet common.Address, class uint8, field string) common.Hash {
	mapKey := append([]byte{class}, []byte(field)...)
	return walletMapSlot(wallet, "terminal", mapKey)
}

// ReadTerminalPolicy returns the TerminalPolicy for a given class.
func ReadTerminalPolicy(db stateDB, wallet common.Address, class uint8) TerminalPolicy {
	maxSingle := db.GetState(registry, terminalFieldSlot(wallet, class, "maxSingle"))
	maxDaily := db.GetState(registry, terminalFieldSlot(wallet, class, "maxDaily"))
	meta := db.GetState(registry, terminalFieldSlot(wallet, class, "meta"))
	return TerminalPolicy{
		MaxSingleValue: maxSingle.Big(),
		MaxDailyValue:  maxDaily.Big(),
		MinTrustTier:   meta[30],
		Enabled:        meta[31] != 0,
	}
}

// WriteTerminalPolicy writes the TerminalPolicy for a given class.
func WriteTerminalPolicy(db stateDB, wallet common.Address, class uint8, tp TerminalPolicy) {
	db.SetState(registry, terminalFieldSlot(wallet, class, "maxSingle"), common.BigToHash(tp.MaxSingleValue))
	db.SetState(registry, terminalFieldSlot(wallet, class, "maxDaily"), common.BigToHash(tp.MaxDailyValue))
	var meta common.Hash
	meta[30] = tp.MinTrustTier
	if tp.Enabled {
		meta[31] = 1
	}
	db.SetState(registry, terminalFieldSlot(wallet, class, "meta"), meta)
}

// ---------- Delegate authorisations ----------

// delegateFieldSlot returns a sub-slot for a delegate's field.
func delegateFieldSlot(wallet common.Address, delegate common.Address, field string) common.Hash {
	mapKey := append(delegate.Bytes(), []byte(field)...)
	return walletMapSlot(wallet, "delegate", mapKey)
}

// ReadDelegateAuth returns the DelegateAuth for delegate on wallet.
func ReadDelegateAuth(db stateDB, wallet common.Address, delegate common.Address) DelegateAuth {
	allowance := db.GetState(registry, delegateFieldSlot(wallet, delegate, "allowance"))
	meta := db.GetState(registry, delegateFieldSlot(wallet, delegate, "meta"))
	expiry := binary.BigEndian.Uint64(meta[16:24])
	active := meta[31] != 0
	return DelegateAuth{
		Delegate:  delegate,
		Allowance: allowance.Big(),
		Expiry:    expiry,
		Active:    active,
	}
}

// WriteDelegateAuth writes the DelegateAuth for delegate on wallet.
func WriteDelegateAuth(db stateDB, wallet common.Address, da DelegateAuth) {
	db.SetState(registry, delegateFieldSlot(wallet, da.Delegate, "allowance"), common.BigToHash(da.Allowance))
	var meta common.Hash
	binary.BigEndian.PutUint64(meta[16:24], da.Expiry)
	if da.Active {
		meta[31] = 1
	}
	db.SetState(registry, delegateFieldSlot(wallet, da.Delegate, "meta"), meta)
}

// ---------- Recovery state ----------

// ReadRecoveryState returns the recovery state for wallet.
func ReadRecoveryState(db stateDB, wallet common.Address) RecoveryState {
	flags := db.GetState(registry, walletSlot(wallet, "recoveryFlags"))
	newOwnerRaw := db.GetState(registry, walletSlot(wallet, "recoveryNewOwner"))
	timing := db.GetState(registry, walletSlot(wallet, "recoveryTiming"))
	guardianRaw := db.GetState(registry, walletSlot(wallet, "recoveryGuardian"))

	return RecoveryState{
		Active:      flags[31] != 0,
		Guardian:    common.BytesToAddress(guardianRaw[:]),
		NewOwner:    common.BytesToAddress(newOwnerRaw[:]),
		InitiatedAt: binary.BigEndian.Uint64(timing[16:24]),
		Timelock:    binary.BigEndian.Uint64(timing[24:32]),
	}
}

// WriteRecoveryState writes the recovery state for wallet.
func WriteRecoveryState(db stateDB, wallet common.Address, rs RecoveryState) {
	var flags common.Hash
	if rs.Active {
		flags[31] = 1
	}
	db.SetState(registry, walletSlot(wallet, "recoveryFlags"), flags)

	var newOwner common.Hash
	copy(newOwner[common.HashLength-common.AddressLength:], rs.NewOwner.Bytes())
	db.SetState(registry, walletSlot(wallet, "recoveryNewOwner"), newOwner)

	var timing common.Hash
	binary.BigEndian.PutUint64(timing[16:24], rs.InitiatedAt)
	binary.BigEndian.PutUint64(timing[24:32], rs.Timelock)
	db.SetState(registry, walletSlot(wallet, "recoveryTiming"), timing)

	var guardian common.Hash
	copy(guardian[common.HashLength-common.AddressLength:], rs.Guardian.Bytes())
	db.SetState(registry, walletSlot(wallet, "recoveryGuardian"), guardian)
}
