//go:build !arm64 || !gc || purego
// +build !arm64 !gc purego

package field

func (v *Element) carryPropagate() *Element {
	return v.carryPropagateGeneric()
}
