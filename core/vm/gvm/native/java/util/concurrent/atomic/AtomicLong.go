package atomic

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

func init() {
	_al(VMSupportsCS8, "VMSupportsCS8", "()Z")
}

func _al(method native.Method, name, desc string) {
	native.Register("java/util/concurrent/atomic/AtomicLong", name, desc, method)
}

// private static native boolean VMSupportsCS8();
// ()Z
func VMSupportsCS8(frame *rtda.Frame) {
	frame.PushBoolean(false) // todo sync/atomic
}
