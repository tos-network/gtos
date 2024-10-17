package io

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

func init() {
	_iaif(iaif_isIPv6Supported, "isIPv6Supported", "()Z")
}

func _iaif(method native.Method, name, desc string) {
	native.Register("java/net/InetAddressImplFactory", name, desc, method)
}

//static native boolean isIPv6Supported();
// ()Z
func iaif_isIPv6Supported(frame *rtda.Frame) {
	frame.PushBoolean(true)
}
