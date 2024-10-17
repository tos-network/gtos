package stores

import (
	"github.com/tos-network/gtos/core/vm/gvm/instructions/base"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

func NewStore(d bool) *Store {
	return &Store{d: d}
}

// xstore: Store XXX into local variable
type Store struct {
	base.Index8Instruction
	d bool // long or double
}

func (instr *Store) Execute(frame *rtda.Frame) {
	frame.Store(instr.Index, instr.d)
}
