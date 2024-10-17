package misc

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

func init() {
	_urlcp(getLookupCacheURLs, "getLookupCacheURLs", "(Ljava/lang/ClassLoader;)[Ljava/net/URL;")
}

func _urlcp(method native.Method, name, desc string) {
	native.Register("sun/misc/URLClassPath", name, desc, method)
}

// private static native URL[] getLookupCacheURLs(ClassLoader var0);
// (Ljava/lang/ClassLoader;)[Ljava/net/URL;
func getLookupCacheURLs(frame *rtda.Frame) {
	frame.PushNull()
}
