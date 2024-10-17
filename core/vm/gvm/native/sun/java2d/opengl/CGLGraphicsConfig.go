package awt

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

func init() {
	_cgl(cgl_initCGL, "initCGL", "()Z")
}

func _cgl(method native.Method, name, desc string) {
	native.Register("sun/java2d/opengl/CGLGraphicsConfig", name, desc, method)
}

func cgl_initCGL(frame *rtda.Frame) {
	//TODO
	frame.PushBoolean(true)
}
