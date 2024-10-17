package stack

import (
	"github.com/tos-network/gtos/core/vm/gvm/instructions/base"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

// Swap the top two operand stack values
type Swap struct{ base.NoOperandsInstruction }

func (instr *Swap) Execute(frame *rtda.Frame) {
	val1 := frame.Pop()
	val2 := frame.Pop()
	frame.Push(val1)
	frame.Push(val2)
}
