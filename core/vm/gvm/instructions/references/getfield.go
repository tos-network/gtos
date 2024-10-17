package references

import (
	"github.com/tos-network/gtos/core/vm/gvm/instructions/base"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
	"github.com/tos-network/gtos/core/vm/gvm/rtda/heap"
)

// Fetch field from object
type GetField struct {
	base.Index16Instruction
	field *heap.Field
}

func (instr *GetField) Execute(frame *rtda.Frame) {
	if instr.field == nil {
		cp := frame.GetConstantPool()
		kFieldRef := cp.GetConstantFieldRef(instr.Index)
		instr.field = kFieldRef.GetField(false)
	}

	ref := frame.PopRef()
	if ref == nil {
		frame.Thread.ThrowNPE()
		return
	}

	val := instr.field.GetValue(ref)
	frame.PushL(val, instr.field.IsLongOrDouble)
}
