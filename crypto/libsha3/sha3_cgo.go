//go:build cgo && ed25519c

package libsha3

/*
#cgo CFLAGS: -std=gnu17
#cgo CFLAGS: -I${SRCDIR}
#cgo CFLAGS: -I${SRCDIR}/../ed25519/libed25519
#cgo CFLAGS: -I${SRCDIR}/../ed25519/libed25519/include
*/
import "C"
