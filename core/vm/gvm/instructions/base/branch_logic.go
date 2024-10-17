package base

import (
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

func Branch(frame *rtda.Frame, offset int) {
	pc := frame.Thread.PC
	frame.NextPC = pc + offset
}
