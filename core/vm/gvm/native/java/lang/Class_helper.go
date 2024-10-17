package lang

import (
	"github.com/tos-network/gtos/core/vm/gvm/rtda/heap"
	"github.com/tos-network/gtos/core/vm/gvm/utils"
)

func getParameterTypeArr(rt *heap.Runtime, method *heap.Method) *heap.Object {
	paramTypes := method.GetParameterTypes()
	paramCount := len(paramTypes)

	classClass := rt.BootLoader().JLClassClass()
	classArr := classClass.NewArray(uint(paramCount))

	if paramCount > 0 {
		classObjs := classArr.GetRefs()
		for i, paramType := range paramTypes {
			classObjs[i] = paramType.JClass
		}
	}

	return classArr
}

func getReturnType(method *heap.Method) *heap.Object {
	goReturnType := method.GetReturnType()
	return goReturnType.JClass
}

func getExceptionTypeArr(rt *heap.Runtime, method *heap.Method) *heap.Object {
	exTypes := method.GetExceptionTypes()
	exCount := len(exTypes)

	classClass := rt.BootLoader().JLClassClass()
	classArr := classClass.NewArray(uint(exCount))

	if exCount > 0 {
		classObjs := classArr.GetRefs()
		for i, exType := range exTypes {
			classObjs[i] = exType.JClass
		}
	}

	return classArr
}

func getAnnotationByteArr(rt *heap.Runtime, goBytes []byte) *heap.Object {
	if goBytes != nil {
		jBytes := utils.CastBytesToInt8s(goBytes)
		return rt.NewByteArray(jBytes)
	}
	return nil
}

func getSignatureStr(rt *heap.Runtime, signature string) *heap.Object {
	if signature != "" {
		return rt.JSFromGoStr(signature)
	}
	return nil
}
