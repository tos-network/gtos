package references

import (
	"github.com/tos-network/gtos/core/vm/gvm/instructions/base"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

// Enter monitor for object
type MonitorEnter struct{ base.NoOperandsInstruction }

func (instr *MonitorEnter) Execute(frame *rtda.Frame) {
	thread := frame.Thread
	ref := frame.PopRef()
	if ref == nil {
		frame.RevertNextPC()
		thread.ThrowNPE()
	} else {
		ref.Monitor.Enter(thread)
	}
}

// Exit monitor for object
type MonitorExit struct{ base.NoOperandsInstruction }

func (instr *MonitorExit) Execute(frame *rtda.Frame) {
	thread := frame.Thread
	ref := frame.PopRef()
	if ref == nil {
		frame.RevertNextPC()
		thread.ThrowNPE()
	} else {
		ref.Monitor.Exit(thread)
	}
}
