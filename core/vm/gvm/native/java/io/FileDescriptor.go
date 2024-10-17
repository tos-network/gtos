package io

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

func init() {
	_fd(set, "set", "(I)J")
}

func _fd(method native.Method, name, desc string) {
	native.Register("java/io/FileDescriptor", name, desc, method)
}

func set(frame *rtda.Frame) {
	frame.PushLong(0)
}
