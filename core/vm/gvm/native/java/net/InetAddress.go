package io

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

func init() {
	_ia(ia_init, "init", "()V")
}

func _ia(method native.Method, name, desc string) {
	native.Register("java/net/InetAddress", name, desc, method)
}

func ia_init(frame *rtda.Frame) {

}
