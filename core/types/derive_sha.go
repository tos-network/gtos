// Copyright 2014 The go-ehtereum Authors
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

package types

import (
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/rlp"
)

type DerivableList interface {
	Len() int
	GetRlp(i int) []byte
}

// Hasher is the tool used to calculate the hash of derivable list.
type Hasher interface {
	Reset()
	Update([]byte, []byte)
	Hash() common.Hash
}

func DeriveSha(list DerivableList, hasher Hasher) common.Hash {
	hasher.Reset()

	// StackTrie requires values to be inserted in increasing
	// hash order, which is not the order that `list` provides
	// hashes in. This insertion sequence ensures that the
	// order is correct.

	var buf []byte
	for i := 1; i < list.Len() && i <= 0x7f; i++ {
		buf = rlp.AppendUint64(buf[:0], uint64(i))
		hasher.Update(buf, list.GetRlp(i))
	}
	if list.Len() > 0 {
		buf = rlp.AppendUint64(buf[:0], 0)
		hasher.Update(buf, list.GetRlp(0))
	}
	for i := 0x80; i < list.Len(); i++ {
		buf = rlp.AppendUint64(buf[:0], uint64(i))
		hasher.Update(buf, list.GetRlp(i))
	}
	return hasher.Hash()
}
