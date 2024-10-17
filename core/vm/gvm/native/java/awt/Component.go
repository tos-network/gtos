package awt

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
)

func init() {
}

func _comp(method native.Method, name, desc string) {
	native.Register("java/awt/Component", name, desc, method)
}
