package awt

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
)

func init() {
}

func _font(method native.Method, name, desc string) {
	native.Register("java/awt/Font", name, desc, method)
}
