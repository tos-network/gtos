package lang

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

func init() {
	_package(getSystemPackage0, "getSystemPackage0", "(Ljava/lang/String;)Ljava/lang/String;")
}

func _package(method native.Method, name, desc string) {
	native.Register("java/lang/Package", name, desc, method)
}

// private static native String getSystemPackage0(String name);
// (Ljava/lang/String;)Ljava/lang/String;
func getSystemPackage0(frame *rtda.Frame) {
	// vars := frame.
	// name := frame.GetRefVar(0)

	sysPkg := frame.GetClassLoader().JLObjectClass().LoadedFrom.String()
	sysPkgObj := frame.GetRuntime().JSFromGoStr(sysPkg)

	frame.PushRef(sysPkgObj)
}

// private static native String[] getSystemPackages0();
