package heap

import "github.com/tos-network/gtos/core/vm/gvm/utils"

// java.lang.String -> go string
func (obj *Object) JSToGoStr() string {
	charArr := obj.GetFieldValue("value", "[C").Ref
	return utils.UTF16ToUTF8(charArr.GetChars())
}
