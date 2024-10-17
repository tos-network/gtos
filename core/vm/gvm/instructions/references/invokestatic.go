package references

import (
	"github.com/tos-network/gtos/core/vm/gvm/instructions/base"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
	"github.com/tos-network/gtos/core/vm/gvm/rtda/heap"
)

// Invoke a class (static) method
type InvokeStatic struct {
	base.Index16Instruction
	method *heap.Method
}

func (instr *InvokeStatic) Execute(frame *rtda.Frame) {
	if instr.method == nil {
		cp := frame.GetConstantPool()
		k := cp.GetConstant(instr.Index)
		if kMethodRef, ok := k.(*heap.ConstantMethodRef); ok {
			instr.method = kMethodRef.GetMethod(true)
		} else {
			instr.method = k.(*heap.ConstantInterfaceMethodRef).GetMethod(true)
		}
	}

	// init class
	class := instr.method.Class
	if class.InitializationNotStarted() {
		frame.RevertNextPC()
		frame.Thread.InitClass(class)
		return
	}

	frame.Thread.InvokeMethod(instr.method)
}
