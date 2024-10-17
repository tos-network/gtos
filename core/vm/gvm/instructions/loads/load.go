package loads

import (
	"github.com/tos-network/gtos/core/vm/gvm/instructions/base"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

func NewLoad(d bool) *Load {
	return &Load{d: d}
}

// xload: Load XXX from local variable
type Load struct {
	base.Index8Instruction
	d bool // long or double
}

func (instr *Load) Execute(frame *rtda.Frame) {
	frame.Load(instr.Index, instr.d)
}
