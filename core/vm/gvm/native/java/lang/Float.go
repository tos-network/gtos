package lang

import (
	"math"

	"github.com/tos-network/gtos/core/vm/gvm/native"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
)

func init() {
	_float(floatToRawIntBits, "floatToRawIntBits", "(F)I")
	_float(intBitsToFloat, "intBitsToFloat", "(I)F")
}

func _float(method native.Method, name, desc string) {
	native.Register("java/lang/Float", name, desc, method)
}

// public static native int floatToRawIntBits(float value);
// (F)I
func floatToRawIntBits(frame *rtda.Frame) {
	value := frame.GetFloatVar(0)
	bits := math.Float32bits(value)

	frame.PushInt(int32(bits)) // todo
}

// public static native float intBitsToFloat(int bits);
// (I)F
func intBitsToFloat(frame *rtda.Frame) {
	bits := frame.GetIntVar(0)
	value := math.Float32frombits(uint32(bits))

	frame.PushFloat(value)
}
