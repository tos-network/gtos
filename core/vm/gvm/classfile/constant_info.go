package classfile

import (
	"fmt"
)

// Constant pool tags
const (
	ConstantUtf8               = 1  // Java 1.0.2
	ConstantInteger            = 3  // Java 1.0.2
	ConstantFloat              = 4  // Java 1.0.2
	ConstantLong               = 5  // Java 1.0.2
	ConstantDouble             = 6  // Java 1.0.2
	ConstantClass              = 7  // Java 1.0.2
	ConstantString             = 8  // Java 1.0.2
	ConstantFieldRef           = 9  // Java 1.0.2
	ConstantMethodRef          = 10 // Java 1.0.2
	ConstantInterfaceMethodRef = 11 // Java 1.0.2
	ConstantNameAndType        = 12 // Java 1.0.2
	ConstantMethodHandle       = 15 // Java 7
	ConstantMethodType         = 16 // Java 7
	ConstantInvokeDynamic      = 18 // Java 7
	ConstantModule             = 19 // Java 9
	ConstantPackage            = 20 // Java 9
	ConstantDynamic            = 17 // Java 11
)

/*
	cp_info {
	    u1 tag;
	    u1 info[];
	}
*/
type ConstantInfo interface{}

func readConstantInfo(reader *ClassReader) (ConstantInfo, error) {
	tag := reader.ReadUint8()
	switch tag {
	case ConstantInteger:
		return readConstantIntegerInfo(reader), nil
	case ConstantFloat:
		return readConstantFloatInfo(reader), nil
	case ConstantLong:
		return readConstantLongInfo(reader), nil
	case ConstantDouble:
		return readConstantDoubleInfo(reader), nil
	case ConstantUtf8:
		return readConstantUtf8Info(reader), nil
	case ConstantString:
		return readConstantStringInfo(reader), nil
	case ConstantClass:
		return readConstantClassInfo(reader), nil
	case ConstantModule:
		return readConstantModuleInfo(reader), nil
	case ConstantPackage:
		return readConstantPackageInfo(reader), nil
	case ConstantFieldRef:
		return readConstantFieldRefInfo(reader), nil
	case ConstantMethodRef:
		return readConstantMethodRefInfo(reader), nil
	case ConstantInterfaceMethodRef:
		return readConstantInterfaceMethodRefInfo(reader), nil
	case ConstantNameAndType:
		return readConstantNameAndTypeInfo(reader), nil
	case ConstantMethodType:
		return readConstantMethodTypeInfo(reader), nil
	case ConstantMethodHandle:
		return readConstantMethodHandleInfo(reader), nil
	case ConstantInvokeDynamic:
		return readConstantInvokeDynamicInfo(reader), nil
	default:
		return nil, fmt.Errorf("invalid constant pool tag: %d", tag) // Return an error
	}
}
