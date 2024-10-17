package awt

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
)

func init() {
}

func _container(method native.Method, name, desc string) {
	native.Register("java/awt/Container", name, desc, method)
}
