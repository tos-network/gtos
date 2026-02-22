package tos

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/tos-network/gtos/p2p"
	"github.com/tos-network/gtos/p2p/enode"
	"github.com/tos-network/gtos/tos/downloader"
	"github.com/tos-network/gtos/tos/protocols/snap"
	"github.com/tos-network/gtos/tos/protocols/tos"
)

// Tests that snap sync is disabled after a successful sync cycle.
func TestSnapSyncDisabling66(t *testing.T) { testSnapSyncDisabling(t, tos.TOS66, snap.SNAP1) }
func TestSnapSyncDisabling67(t *testing.T) { testSnapSyncDisabling(t, tos.TOS67, snap.SNAP1) }

// Tests that snap sync gets disabled as soon as a real block is successfully
// imported into the blockchain.
func testSnapSyncDisabling(t *testing.T, tosVer uint, snapVer uint) {
	t.Parallel()

	// Create an empty handler and ensure it's in snap sync mode
	empty := newTestHandler()
	if atomic.LoadUint32(&empty.handler.snapSync) == 0 {
		t.Fatalf("snap sync disabled on pristine blockchain")
	}
	defer empty.close()

	// Create a full handler and ensure snap sync ends up disabled
	full := newTestHandlerWithBlocks(1024)
	if atomic.LoadUint32(&full.handler.snapSync) == 1 {
		t.Fatalf("snap sync not disabled on non-empty blockchain")
	}
	defer full.close()

	// Sync up the two handlers via both `tos` and `snap`
	caps := []p2p.Cap{{Name: "tos", Version: tosVer}, {Name: "snap", Version: snapVer}}

	emptyPipeTos, fullPipeTos := p2p.MsgPipe()
	defer emptyPipeTos.Close()
	defer fullPipeTos.Close()

	emptyPeerTos := tos.NewPeer(tosVer, p2p.NewPeer(enode.ID{1}, "", caps), emptyPipeTos, empty.txpool)
	fullPeerTos := tos.NewPeer(tosVer, p2p.NewPeer(enode.ID{2}, "", caps), fullPipeTos, full.txpool)
	defer emptyPeerTos.Close()
	defer fullPeerTos.Close()

	go empty.handler.runTosPeer(emptyPeerTos, func(peer *tos.Peer) error {
		return tos.Handle((*tosHandler)(empty.handler), peer)
	})
	go full.handler.runTosPeer(fullPeerTos, func(peer *tos.Peer) error {
		return tos.Handle((*tosHandler)(full.handler), peer)
	})

	emptyPipeSnap, fullPipeSnap := p2p.MsgPipe()
	defer emptyPipeSnap.Close()
	defer fullPipeSnap.Close()

	emptyPeerSnap := snap.NewPeer(snapVer, p2p.NewPeer(enode.ID{1}, "", caps), emptyPipeSnap)
	fullPeerSnap := snap.NewPeer(snapVer, p2p.NewPeer(enode.ID{2}, "", caps), fullPipeSnap)

	go empty.handler.runSnapExtension(emptyPeerSnap, func(peer *snap.Peer) error {
		return snap.Handle((*snapHandler)(empty.handler), peer)
	})
	go full.handler.runSnapExtension(fullPeerSnap, func(peer *snap.Peer) error {
		return snap.Handle((*snapHandler)(full.handler), peer)
	})
	// Wait a bit for the above handlers to start
	time.Sleep(250 * time.Millisecond)

	// Check that snap sync was disabled
	op := peerToSyncOp(downloader.SnapSync, empty.handler.peers.peerWithHighestTD())
	if err := empty.handler.doSync(op); err != nil {
		t.Fatal("sync failed:", err)
	}
	if atomic.LoadUint32(&empty.handler.snapSync) == 1 {
		t.Fatalf("snap sync not disabled after successful synchronisation")
	}
}
