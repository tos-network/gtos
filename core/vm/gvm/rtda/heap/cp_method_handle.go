package heap

import (
	"github.com/tos-network/gtos/core/vm/gvm/classfile"
)

type ConstantMethodHandle struct {
	referenceKind  uint8
	referenceIndex uint16
}

func newConstantMethodHandle(mhInfo classfile.ConstantMethodHandleInfo) *ConstantMethodHandle {
	return &ConstantMethodHandle{
		referenceKind:  mhInfo.ReferenceKind,
		referenceIndex: mhInfo.ReferenceIndex,
	}
}
