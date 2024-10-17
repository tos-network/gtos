package constants

import (
	"github.com/tos-network/gtos/core/vm/gvm/instructions/base"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

// Do nothing
type NOP struct{ base.NoOperandsInstruction }

func (instr *NOP) Execute(frame *rtda.Frame) {
	// really do nothing
}
