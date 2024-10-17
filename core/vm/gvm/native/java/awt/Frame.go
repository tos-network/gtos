package awt

import (
	"github.com/tos-network/gtos/core/vm/gvm/native"
)

func _frame(method native.Method, name, desc string) {
	native.Register("java/awt/Frame", name, desc, method)
}
