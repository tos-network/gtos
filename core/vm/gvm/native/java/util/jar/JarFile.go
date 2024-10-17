package jar

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

func init() {
	_jf(getMetaInfEntryNames, "getMetaInfEntryNames", "()[Ljava/lang/String;")
}

func _jf(method native.Method, name, desc string) {
	native.Register("java/util/jar/JarFile", name, desc, method)
}

// private native String[] getMetaInfEntryNames();
// ()[Ljava/lang/String;
func getMetaInfEntryNames(frame *rtda.Frame) {
	// todo
	frame.PushNull()
}
