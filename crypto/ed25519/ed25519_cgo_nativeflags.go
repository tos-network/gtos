//go:build cgo && ed25519c && ed25519native

package ed25519

/*
#cgo amd64 CFLAGS: -march=native -mtune=native
*/
import "C"
