// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

// These are the multipliers for tos denominations.
// Example: To get the tomi value of an amount in 'gtomi', use
//
//	new(big.Int).Mul(value, big.NewInt(params.Gtomi))
const (
	Tomi  = 1
	Gtomi = 1e9
	TOS   = 1e18

	// Backward-compatible aliases.
	Wei  = Tomi
	GWei = Gtomi
)
