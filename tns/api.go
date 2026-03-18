package tns

import (
	"github.com/tos-network/gtos/common"
)

// TNSResolveResult is the JSON-friendly result for Resolve.
type TNSResolveResult struct {
	Name     string         `json:"name"`
	NameHash common.Hash    `json:"name_hash"`
	Address  common.Address `json:"address"`
	Found    bool           `json:"found"`
}

// TNSReverseResult is the JSON-friendly result for Reverse.
type TNSReverseResult struct {
	Address  common.Address `json:"address"`
	NameHash common.Hash    `json:"name_hash"`
	Found    bool           `json:"found"`
}

// PublicTNSAPI provides RPC methods for querying TNS state.
type PublicTNSAPI struct {
	stateReader func() stateDB
}

// NewPublicTNSAPI creates a new TNS API instance.
func NewPublicTNSAPI(stateReader func() stateDB) *PublicTNSAPI {
	return &PublicTNSAPI{stateReader: stateReader}
}

// Resolve resolves a TNS name to an address.
// RPC: tns_resolve
func (api *PublicTNSAPI) Resolve(name string) (*TNSResolveResult, error) {
	db := api.stateReader()
	nameHash := HashName(name)
	addr := Resolve(db, nameHash)
	return &TNSResolveResult{
		Name:     name,
		NameHash: nameHash,
		Address:  addr,
		Found:    addr != (common.Address{}),
	}, nil
}

// Reverse resolves an address to its registered TNS name hash.
// RPC: tns_reverse
func (api *PublicTNSAPI) Reverse(address common.Address) (*TNSReverseResult, error) {
	db := api.stateReader()
	nameHash := Reverse(db, address)
	return &TNSReverseResult{
		Address:  address,
		NameHash: nameHash,
		Found:    nameHash != (common.Hash{}),
	}, nil
}
