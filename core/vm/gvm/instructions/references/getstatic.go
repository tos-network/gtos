package references

import (
	"github.com/tos-network/gtos/core/vm/gvm/instructions/base"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
	"github.com/tos-network/gtos/core/vm/gvm/rtda/heap"
)

// Get static field from class
type GetStatic struct {
	base.Index16Instruction
	field *heap.Field
}

func (instr *GetStatic) Execute(frame *rtda.Frame) {
	if instr.field == nil {
		cp := frame.GetConstantPool()
		kFieldRef := cp.GetConstantFieldRef(instr.Index)
		instr.field = kFieldRef.GetField(true)
	}

	class := instr.field.Class
	if class.InitializationNotStarted() {
		frame.RevertNextPC() // undo getstatic
		frame.Thread.InitClass(class)
		return
	}

	val := instr.field.GetStaticValue()
	frame.PushL(val, instr.field.IsLongOrDouble)
}
