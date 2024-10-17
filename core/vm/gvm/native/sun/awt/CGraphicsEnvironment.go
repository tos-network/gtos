package awt

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

func init() {
	_cge(cge_initCocoa, "initCocoa", "()V")
	_cge(cge_getMainDisplayID, "getMainDisplayID", "()I")
}

func _cge(method native.Method, name, desc string) {
	native.Register("sun/awt/CGraphicsEnvironment", name, desc, method)
}

func cge_initCocoa(frame *rtda.Frame) {
	//TODO
}

func cge_getMainDisplayID(frame *rtda.Frame) {
	frame.PushInt(1)
}
