package lease

import (
	"fmt"
	"math"
	"math/big"

	"github.com/tos-network/gtos/common"
	vmtypes "github.com/tos-network/gtos/core/vmtypes"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

var emptyCodeHash = crypto.Keccak256Hash(nil)

// EpochLength returns the effective DPoS epoch length for lease scheduling.
func EpochLength(chainConfig *params.ChainConfig) uint64 {
	if chainConfig != nil && chainConfig.DPoS != nil && chainConfig.DPoS.Epoch > 0 {
		return chainConfig.DPoS.Epoch
	}
	return params.DPoSEpochLength
}

// GraceBlocks returns the effective grace window for lease contracts.
func GraceBlocks(chainConfig *params.ChainConfig) uint64 {
	return params.LeaseGraceBlocks
}

// ValidateLeaseBlocks enforces the supported lease duration range.
func ValidateLeaseBlocks(leaseBlocks uint64) error {
	if leaseBlocks < params.LeaseMinBlocks || leaseBlocks > params.LeaseMaxBlocks {
		return ErrLeaseInvalidBlocks
	}
	return nil
}

// RequireExplicitOwner validates the in-VM lease owner rule.
func RequireExplicitOwner(db vmtypes.StateDB, owner common.Address) error {
	if owner == (common.Address{}) {
		return ErrLeaseOwnerRequired
	}
	return RequireRenewCapableOwner(db, owner)
}

// RequireRenewCapableOwner rejects code-bearing owners in v1.
func RequireRenewCapableOwner(db vmtypes.StateDB, owner common.Address) error {
	if owner == (common.Address{}) {
		return ErrLeaseOwnerRequired
	}
	if db == nil {
		return nil
	}
	codeHash := db.GetCodeHash(owner)
	if codeHash != (common.Hash{}) && codeHash != emptyCodeHash {
		return ErrLeaseOwnerMustBeEOA
	}
	return nil
}

// NativeDeployGas computes the separate gas schedule for LEASE_DEPLOY.
func NativeDeployGas(codeBytes uint64) (uint64, error) {
	return addScaledGas(params.LeaseDeployBaseGas, params.LeaseDeployByteGas, codeBytes)
}

// CreateXGas computes the separate gas schedule for tos.createx.
func CreateXGas(codeBytes uint64) (uint64, error) {
	return addScaledGas(params.LeaseCreateXBaseGas, params.LeaseCreateXByteGas, codeBytes)
}

// Create2XGas computes the separate gas schedule for tos.create2x.
func Create2XGas(codeBytes uint64) (uint64, error) {
	return addScaledGas(params.LeaseCreate2XBaseGas, params.LeaseCreate2XByteGas, codeBytes)
}

func addScaledGas(base uint64, perByte uint64, codeBytes uint64) (uint64, error) {
	if codeBytes != 0 && perByte > math.MaxUint64/codeBytes {
		return 0, fmt.Errorf("lease: gas overflows")
	}
	byteGas := perByte * codeBytes
	if base > math.MaxUint64-byteGas {
		return 0, fmt.Errorf("lease: gas overflows")
	}
	return base + byteGas, nil
}

// DepositFor returns the locked lease deposit in wei.
func DepositFor(codeBytes uint64, leaseBlocks uint64) (*big.Int, error) {
	if err := ValidateLeaseBlocks(leaseBlocks); err != nil {
		return nil, err
	}
	if codeBytes == 0 {
		return new(big.Int), nil
	}
	numerator := new(big.Int).SetUint64(codeBytes)
	numerator.Mul(numerator, new(big.Int).SetUint64(params.LeaseDepositReferenceByteGas))
	numerator.Mul(numerator, new(big.Int).SetUint64(leaseBlocks))

	referenceBlocks := new(big.Int).SetUint64(params.LeaseReferenceBlocks)
	depositGas := new(big.Int).Quo(numerator, referenceBlocks)
	if depositGas.Sign() == 0 {
		depositGas.SetUint64(1)
	}
	return depositGas.Mul(depositGas, big.NewInt(params.TxPriceWei)), nil
}

// RefundFor returns the refundable portion of the remaining deposit.
func RefundFor(deposit *big.Int) *big.Int {
	if deposit == nil || deposit.Sign() == 0 {
		return new(big.Int)
	}
	refund := new(big.Int).Set(deposit)
	refund.Mul(refund, new(big.Int).SetUint64(params.LeaseRefundNumerator))
	refund.Quo(refund, new(big.Int).SetUint64(params.LeaseRefundDenominator))
	return refund
}

// NewMeta constructs a new active lease metadata record.
func NewMeta(owner common.Address, createdAt uint64, leaseBlocks uint64, codeBytes uint64, deposit *big.Int, chainConfig *params.ChainConfig) (Meta, error) {
	if err := ValidateLeaseBlocks(leaseBlocks); err != nil {
		return Meta{}, err
	}
	graceBlocks := GraceBlocks(chainConfig)
	if createdAt > math.MaxUint64-leaseBlocks {
		return Meta{}, fmt.Errorf("lease: expiry overflows")
	}
	expireAt := createdAt + leaseBlocks
	if expireAt > math.MaxUint64-graceBlocks {
		return Meta{}, fmt.Errorf("lease: grace window overflows")
	}
	meta := Meta{
		LeaseOwner:      owner,
		CreatedAtBlock:  createdAt,
		ExpireAtBlock:   expireAt,
		GraceUntilBlock: expireAt + graceBlocks,
		CodeBytes:       codeBytes,
		DepositWei:      new(big.Int),
	}
	if deposit != nil {
		meta.DepositWei = new(big.Int).Set(deposit)
	}
	return meta, nil
}

// RenewMeta extends a lease from max(currentBlock, expireAt) by deltaBlocks.
func RenewMeta(meta Meta, currentBlock uint64, deltaBlocks uint64, chainConfig *params.ChainConfig) (Meta, error) {
	if err := ValidateLeaseBlocks(deltaBlocks); err != nil {
		return Meta{}, err
	}
	base := meta.ExpireAtBlock
	if currentBlock > base {
		base = currentBlock
	}
	if base > math.MaxUint64-deltaBlocks {
		return Meta{}, fmt.Errorf("lease: renewal overflows")
	}
	graceBlocks := GraceBlocks(chainConfig)
	meta.ExpireAtBlock = base + deltaBlocks
	if meta.ExpireAtBlock > math.MaxUint64-graceBlocks {
		return Meta{}, fmt.Errorf("lease: renewal grace window overflows")
	}
	meta.GraceUntilBlock = meta.ExpireAtBlock + graceBlocks
	return meta, nil
}

// CloseMeta immediately expires a lease and clears its refundable deposit.
func CloseMeta(meta Meta, currentBlock uint64) Meta {
	meta.ExpireAtBlock = currentBlock
	meta.GraceUntilBlock = currentBlock
	meta.DepositWei = new(big.Int)
	return meta
}

// PruneEpoch returns the epoch number on whose boundary the lease becomes prunable.
func PruneEpoch(graceUntilBlock uint64, epochLength uint64) uint64 {
	if epochLength == 0 {
		epochLength = params.DPoSEpochLength
	}
	return graceUntilBlock/epochLength + 1
}
