// Copyright 2014 The go-ethereum Authors
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

package vm

import "fmt"

// OpCode is an EVM opcode (stub, kept for compatibility with remaining assembler code).
type OpCode byte

func (op OpCode) String() string {
	return fmt.Sprintf("OpCode(%d)", int(op))
}

// IsPush returns true if op is a PUSH opcode.
func (op OpCode) IsPush() bool {
	return op >= PUSH1 && op <= PUSH32
}

// Common opcodes kept for core/asm compatibility.
const (
	STOP       OpCode = 0x0
	ADD        OpCode = 0x1
	PUSH1      OpCode = 0x60
	PUSH4      OpCode = 0x63
	PUSH32     OpCode = 0x7f
	JUMPDEST   OpCode = 0x5b
)

// StringToOp returns the opcode corresponding to the given string (stub).
func StringToOp(str string) OpCode {
	return STOP
}

// ValidEip returns whether the given EIP is valid/supported (stub, always false).
func ValidEip(eipNum int) bool {
	return false
}
