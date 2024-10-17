package awt

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
)

func init() {
}

func _cursor(method native.Method, name, desc string) {
	native.Register("java/awt/Cursor", name, desc, method)
}
