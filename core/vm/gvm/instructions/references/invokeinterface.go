package references

import (
	"github.com/tos-network/gtos/core/vm/gvm/instructions/base"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
	"github.com/tos-network/gtos/core/vm/gvm/rtda/heap"
)

// Invoke interface method
type InvokeInterface struct {
	index uint
	// count uint8
	// zero uint8

	// optimization
	kMethodRef   *heap.ConstantInterfaceMethodRef
	argSlotCount uint
}

func (instr *InvokeInterface) FetchOperands(reader *base.CodeReader) {
	instr.index = uint(reader.ReadUint16())
	reader.ReadUint8() // count
	reader.ReadUint8() // must be 0
}

func (instr *InvokeInterface) Execute(frame *rtda.Frame) {
	if instr.kMethodRef == nil {
		cp := frame.GetConstantPool()
		instr.kMethodRef = cp.GetConstant(instr.index).(*heap.ConstantInterfaceMethodRef)
		instr.argSlotCount = instr.kMethodRef.ParamSlotCount
	}

	ref := frame.TopRef(instr.argSlotCount)
	if ref == nil {
		return
	}

	method := instr.kMethodRef.FindInterfaceMethod(ref)
	frame.Thread.InvokeMethod(method)
}
