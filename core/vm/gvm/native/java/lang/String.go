package lang

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

func init() {
	_string(intern, "intern", "()Ljava/lang/String;")
}

func _string(method native.Method, name, desc string) {
	native.Register("java/lang/String", name, desc, method)
}

// public native String intern();
// ()Ljava/lang/String;
func intern(frame *rtda.Frame) {
	jStr := frame.GetThis()

	goStr := jStr.JSToGoStr()
	internedStr := frame.GetRuntime().JSIntern(goStr, jStr)

	frame.PushRef(internedStr)
}
