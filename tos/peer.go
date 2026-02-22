package tos

import (
	"math/big"

	"github.com/tos-network/gtos/tos/protocols/snap"
	"github.com/tos-network/gtos/tos/protocols/tos"
)

// tosPeerInfo represents a short summary of the `tos` sub-protocol metadata known
// about a connected peer.
type tosPeerInfo struct {
	Version    uint     `json:"version"`    // TOS protocol version negotiated
	Difficulty *big.Int `json:"difficulty"` // Total difficulty of the peer's blockchain
	Head       string   `json:"head"`       // Hex hash of the peer's best owned block
}

// tosPeer is a wrapper around tos.Peer to maintain a few extra metadata.
type tosPeer struct {
	*tos.Peer
	snapExt *snapPeer // Satellite `snap` connection
}

// info gathers and returns some `tos` protocol metadata known about a peer.
func (p *tosPeer) info() *tosPeerInfo {
	hash, td := p.Head()

	return &tosPeerInfo{
		Version:    p.Version(),
		Difficulty: td,
		Head:       hash.Hex(),
	}
}

// snapPeerInfo represents a short summary of the `snap` sub-protocol metadata known
// about a connected peer.
type snapPeerInfo struct {
	Version uint `json:"version"` // Snapshot protocol version negotiated
}

// snapPeer is a wrapper around snap.Peer to maintain a few extra metadata.
type snapPeer struct {
	*snap.Peer
}

// info gathers and returns some `snap` protocol metadata known about a peer.
func (p *snapPeer) info() *snapPeerInfo {
	return &snapPeerInfo{
		Version: p.Version(),
	}
}
