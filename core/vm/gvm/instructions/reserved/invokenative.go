package reserved

import (
	"fmt"

	"github.com/tos-network/gtos/core/vm/gvm/instructions/base"
	"github.com/tos-network/gtos/core/vm/gvm/native"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

// Invoke native method
type InvokeNative struct{ base.NoOperandsInstruction }

func (instr *InvokeNative) Execute(frame *rtda.Frame) {
	method := frame.Method
	if frame.Thread.VMOptions.VerboseJNI {
		fmt.Printf("invokenative: %s.%s%s\n",
			method.Class.Name, method.Name, method.Descriptor)
	}

	nativeMethod := native.FindNativeMethod(method)
	nativeMethod(frame)
}
