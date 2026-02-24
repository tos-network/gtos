//go:build !(cgo && ed25519c && ed25519native)

package ed25519

// NativeAccelerated reports whether this build uses the native ed25519 backend.
func NativeAccelerated() bool {
	return false
}
