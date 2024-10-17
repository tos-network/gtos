package io

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

func init() {
	_i4a(i4a_init, "init", "()V")
}

func _i4a(method native.Method, name, desc string) {
	native.Register("java/net/Inet4Address", name, desc, method)
}

func i4a_init(frame *rtda.Frame) {

}
