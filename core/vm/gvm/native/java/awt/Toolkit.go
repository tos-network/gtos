package awt

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
)

func init() {
}

func _tk(method native.Method, name, desc string) {
	native.Register("java/awt/Toolkit", name, desc, method)
}
