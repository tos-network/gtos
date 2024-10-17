package references

import (
	"github.com/tos-network/gtos/core/vm/gvm/instructions/base"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

// Get length of array
type ArrayLength struct{ base.NoOperandsInstruction }

func (instr *ArrayLength) Execute(frame *rtda.Frame) {
	arrRef := frame.PopRef()

	if arrRef == nil {
		frame.Thread.ThrowNPE()
		return
	}

	arrLen := arrRef.ArrayLength()
	frame.PushInt(arrLen)
}
