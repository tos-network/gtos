package references

import (
	"github.com/tos-network/gtos/core/vm/gvm/instructions/base"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
	"github.com/tos-network/gtos/core/vm/gvm/rtda/heap"
)

// Set static field in class
type PupStatic struct {
	base.Index16Instruction
	field *heap.Field
}

func (instr *PupStatic) Execute(frame *rtda.Frame) {
	if instr.field == nil {
		cp := frame.GetConstantPool()
		kFieldRef := cp.GetConstantFieldRef(instr.Index)
		instr.field = kFieldRef.GetField(true)
	}

	class := instr.field.Class
	if class.InitializationNotStarted() {
		frame.RevertNextPC()
		frame.Thread.InitClass(class)
		return
	}

	val := frame.PopL(instr.field.IsLongOrDouble)
	instr.field.PutStaticValue(val)
}
