//go:build !amd64 || !gc || purego
// +build !amd64 !gc purego

package field

func feMul(v, x, y *Element) { feMulGeneric(v, x, y) }

func feSquare(v, x *Element) { feSquareGeneric(v, x) }
