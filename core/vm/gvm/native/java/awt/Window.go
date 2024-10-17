package awt

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
)

func _window(method native.Method, name, desc string) {
	native.Register("java/awt/Window", name, desc, method)
}
