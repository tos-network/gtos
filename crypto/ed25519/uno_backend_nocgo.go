//go:build !(cgo && ed25519c)

package ed25519

// UNOBackendEnabled reports whether UNO native backend is linked in this build.
func UNOBackendEnabled() bool {
	return false
}
