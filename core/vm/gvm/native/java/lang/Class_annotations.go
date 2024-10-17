package lang

import (
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
	"github.com/tos-network/gtos/core/vm/gvm/utils"
)

func init() {
	_class(getRawAnnotations, "getRawAnnotations", "()[B")
}

// native byte[] getRawAnnotations();
// ()[B
func getRawAnnotations(frame *rtda.Frame) {
	this := frame.GetThis()

	class := this.GetGoClass()
	goBytes := class.AnnotationData
	if goBytes != nil {
		jBytes := utils.CastBytesToInt8s(goBytes)
		byteArr := frame.GetRuntime().NewByteArray(jBytes)
		frame.PushRef(byteArr)
		return
	}

	frame.PushRef(nil)
}

// native byte[] getRawTypeAnnotations();
// ()[B
func getRawTypeAnnotations(frame *rtda.Frame) {
	// todo
}
