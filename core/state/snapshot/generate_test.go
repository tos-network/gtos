// Copyright 2020 The go-ehtereum Authors
// Copyright 2023 Terminos Network
// This file is part of the tos library.
//
// The tos library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The tos library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the tos library. If not, see <http://www.gnu.org/licenses/>.

package snapshot

import (
	"math/big"
	"testing"
	"time"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/ethdb/memorydb"
	"github.com/tos-network/gtos/rlp"
	"github.com/tos-network/gtos/trie"
)

// Tests that snapshot generation errors out correctly in case of a missing trie
// node in the account trie.
func TestGenerateCorruptAccountTrie(t *testing.T) {
	// We can't use statedb to make a test trie (circular dependency), so make
	// a fake one manually. We're going with a small account trie of 3 accounts,
	// without any storage slots to keep the test smaller.
	var (
		diskdb = memorydb.New()
		triedb = trie.NewDatabase(diskdb)
	)
	tr, _ := trie.NewSecure(common.Hash{}, triedb)
	acc := &Account{Balance: big.NewInt(1), Root: emptyRoot.Bytes(), CodeHash: emptyCode.Bytes(), ByteCodeHash: emptyCode.Bytes()}
	val, _ := rlp.EncodeToBytes(acc)
	tr.Update([]byte("acc-1"), val) // 0xc7a30f39aff471c95d8a837497ad0e49b65be475cc0953540f80cfcdbdcd9074

	acc = &Account{Balance: big.NewInt(2), Root: emptyRoot.Bytes(), CodeHash: emptyCode.Bytes(), ByteCodeHash: emptyCode.Bytes()}
	val, _ = rlp.EncodeToBytes(acc)
	tr.Update([]byte("acc-2"), val) // 0x65145f923027566669a1ae5ccac66f945b55ff6eaeb17d2ea8e048b7d381f2d7

	acc = &Account{Balance: big.NewInt(3), Root: emptyRoot.Bytes(), CodeHash: emptyCode.Bytes(), ByteCodeHash: emptyCode.Bytes()}
	val, _ = rlp.EncodeToBytes(acc)
	tr.Update([]byte("acc-3"), val) // 0x19ead688e907b0fab07176120dceec244a72aff2f0aa51e8b827584e378772f4
	tr.Commit(nil)                  // Root: 0xa04693ea110a31037fb5ee814308a6f1d76bdab0b11676bdf4541d2de55ba978

	// Delete an account trie leaf and ensure the generator chokes
	triedb.Commit(common.HexToHash("0xa04693ea110a31037fb5ee814308a6f1d76bdab0b11676bdf4541d2de55ba978"), false, nil)
	diskdb.Delete(common.HexToHash("0x65145f923027566669a1ae5ccac66f945b55ff6eaeb17d2ea8e048b7d381f2d7").Bytes())

	snap := generateSnapshot(diskdb, triedb, 16, common.HexToHash("0xa04693ea110a31037fb5ee814308a6f1d76bdab0b11676bdf4541d2de55ba978"), nil)
	select {
	case <-snap.genPending:
		// Snapshot generation succeeded
		t.Errorf("Snapshot generated against corrupt account trie")

	case <-time.After(250 * time.Millisecond):
		// Not generated fast enough, hopefully blocked inside on missing trie node fail
	}
	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}
