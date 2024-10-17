package stack

import (
	"github.com/tos-network/gtos/core/vm/gvm/instructions/base"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

// Pop the top operand stack value
type Pop struct{ base.NoOperandsInstruction }

func (instr *Pop) Execute(frame *rtda.Frame) {
	frame.Pop()
}

// Pop the top one or two operand stack values
type Pop2 struct{ base.NoOperandsInstruction }

func (instr *Pop2) Execute(frame *rtda.Frame) {
	frame.Pop()
	frame.Pop()
}
