package misc

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

func init() {
	_perf(createLong, "createLong", "(Ljava/lang/String;IIJ)Ljava/nio/ByteBuffer;")
}

func _perf(method native.Method, name, desc string) {
	native.Register("sun/misc/Perf", name, desc, method)
}

// public native ByteBuffer createLong(String name, int variability, int units, long value);
// (Ljava/lang/String;IIJ)Ljava/nio/ByteBuffer;
func createLong(frame *rtda.Frame) {
	bbClass := frame.GetClassLoader().LoadClass("java/nio/ByteBuffer")
	if bbClass.InitializationNotStarted() {
		frame.RevertNextPC()
		frame.Thread.InitClass(bbClass)
		return
	}

	frame.PushInt(8)

	allocate := bbClass.GetStaticMethod("allocate", "(I)Ljava/nio/ByteBuffer;")
	frame.Thread.InvokeMethod(allocate)
}
