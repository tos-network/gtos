//go:build nacl || js || !cgo
// +build nacl js !cgo

package rlp

import "reflect"

// byteArrayBytes returns a slice of the byte array v.
func byteArrayBytes(v reflect.Value, length int) []byte {
	return v.Slice(0, length).Bytes()
}
