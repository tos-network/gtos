package ch

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
)

func init() {
}

func _ssci(method native.Method, name, desc string) {
	native.Register("sun/nio/ch/ServerSocketChannelImpl", name, desc, method)
}
