package extended

import (
	"github.com/tos-network/gtos/core/vm/gvm/instructions/base"
	"github.com/tos-network/gtos/core/vm/gvm/instructions/control"
	"github.com/tos-network/gtos/core/vm/gvm/instructions/loads"
	"github.com/tos-network/gtos/core/vm/gvm/instructions/math"
	"github.com/tos-network/gtos/core/vm/gvm/instructions/stores"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

// Extend local variable index by additional bytes
type Wide struct {
	modifiedInstruction base.Instruction
}

func (instr *Wide) FetchOperands(reader *base.CodeReader) {
	opcode := reader.ReadUint8()
	switch opcode {
	case 0x15, 0x17, 0x19:
		inst := loads.NewLoad(false)
		inst.Index = uint(reader.ReadUint16())
		instr.modifiedInstruction = inst
	case 0x16, 0x18:
		inst := loads.NewLoad(true)
		inst.Index = uint(reader.ReadUint16())
		instr.modifiedInstruction = inst
	case 0x36, 0x38, 0x3a:
		inst := stores.NewStore(false)
		inst.Index = uint(reader.ReadUint16())
		instr.modifiedInstruction = inst
	case 0x37, 0x39:
		inst := stores.NewStore(true)
		inst.Index = uint(reader.ReadUint16())
		instr.modifiedInstruction = inst
	case 0xa9:
		inst := &control.RET{}
		inst.Index = uint(reader.ReadUint16())
		instr.modifiedInstruction = inst
	case 0x84:
		inst := &math.IInc{}
		inst.Index = uint(reader.ReadUint16())
		inst.Const = int32(reader.ReadInt16())
		instr.modifiedInstruction = inst
	}
}

func (instr *Wide) Execute(frame *rtda.Frame) {
	instr.modifiedInstruction.Execute(frame)
}
