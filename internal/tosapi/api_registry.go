package tosapi

import "context"

// ---------------------------------------------------------------------------
// Protocol Registry RPC types
//
// v1 skeleton — response types for the protocol registry query RPCs defined
// in docs/GTOS_PROTOCOL_REGISTRIES.md.  The methods return nil when the
// underlying registry state packages are not yet wired up.
// ---------------------------------------------------------------------------

// CapabilityInfo describes a single capability record from the protocol
// Capability Registry.
type CapabilityInfo struct {
	Name     string `json:"name"`
	BitIndex uint64 `json:"bit_index"`
	Category uint64 `json:"category"`
	Version  uint64 `json:"version"`
	Status   string `json:"status"` // "active", "deprecated", "revoked"
}

// DelegationInfo describes a single delegation record from the protocol
// Delegation Registry.
type DelegationInfo struct {
	Principal     string `json:"principal"`
	Delegate      string `json:"delegate"`
	ScopeRef      string `json:"scope_ref"`
	CapabilityRef string `json:"capability_ref"`
	ExpiryMS      uint64 `json:"expiry_ms"`
	Status        string `json:"status"`
}

// PackageInfo describes a single package record from the protocol
// Package Registry.
type PackageInfo struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	PackageHash   string `json:"package_hash"`
	PublisherID   string `json:"publisher_id"`
	Channel       string `json:"channel"`
	Status        string `json:"status"`
	ContractCount uint64 `json:"contract_count"`
}

// PublisherInfo describes a single publisher record from the protocol
// Publisher Registry.
type PublisherInfo struct {
	PublisherID string `json:"publisher_id"`
	Controller  string `json:"controller"`
	MetadataRef string `json:"metadata_ref"`
	Status      string `json:"status"`
}

// ---------------------------------------------------------------------------
// RPC methods — v1 skeleton
//
// These methods are intended to read from StateDB via registry state
// functions once those are implemented.  For v1 they return nil to indicate
// "no record found" rather than erroring, so callers can safely probe
// without depending on registry state being present.
// ---------------------------------------------------------------------------

// TolGetCapability returns the capability record for the given canonical
// name, or nil if no record exists.
//
// v1 skeleton: always returns nil (registry state not yet wired).
func (s *TOSAPI) TolGetCapability(_ context.Context, _ string) (*CapabilityInfo, error) {
	// TODO: read from StateDB via capability registry state functions.
	return nil, nil
}

// TolGetDelegation returns the delegation record for the given
// (principal, delegate, scopeRef) triple, or nil if no record exists.
//
// v1 skeleton: always returns nil (registry state not yet wired).
func (s *TOSAPI) TolGetDelegation(_ context.Context, _, _, _ string) (*DelegationInfo, error) {
	// TODO: read from StateDB via delegation registry state functions.
	return nil, nil
}

// TolGetPackage returns the package record for the given name and version,
// or nil if no record exists.
//
// v1 skeleton: always returns nil (registry state not yet wired).
func (s *TOSAPI) TolGetPackage(_ context.Context, _, _ string) (*PackageInfo, error) {
	// TODO: read from StateDB via package registry state functions.
	return nil, nil
}

// TolGetPublisher returns the publisher record for the given publisher ID,
// or nil if no record exists.
//
// v1 skeleton: always returns nil (registry state not yet wired).
func (s *TOSAPI) TolGetPublisher(_ context.Context, _ string) (*PublisherInfo, error) {
	// TODO: read from StateDB via publisher registry state functions.
	return nil, nil
}
