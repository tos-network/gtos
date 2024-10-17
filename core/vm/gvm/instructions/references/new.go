package references

import (
	"github.com/tos-network/gtos/core/vm/gvm/instructions/base"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
	"github.com/tos-network/gtos/core/vm/gvm/rtda/heap"
)

// Create new object
type New struct {
	base.Index16Instruction
	class *heap.Class
}

func (instr *New) Execute(frame *rtda.Frame) {
	if instr.class == nil {
		cp := frame.GetConstantPool()
		kClass := cp.GetConstantClass(instr.Index)
		instr.class = kClass.GetClass()
	}

	// init class
	if instr.class.InitializationNotStarted() {
		frame.RevertNextPC() // undo new
		frame.Thread.InitClass(instr.class)
		return
	}

	ref := instr.class.NewObj()
	frame.PushRef(ref)
}
