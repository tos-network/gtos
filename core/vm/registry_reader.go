package vm

import vmtypes "github.com/tos-network/gtos/core/vmtypes"

// RegistryReader is a type alias re-exported from core/vmtypes for
// convenience within the vm package.
type RegistryReader = vmtypes.RegistryReader

// Registry record status constants.
// These mirror the canonical values that the registry package will use.
const (
	RegistryStatusActive     uint8 = 0
	RegistryStatusDeprecated uint8 = 1
	RegistryStatusRevoked    uint8 = 2
)
