//go:build !(cgo && ed25519c)

package ed25519

// PrivBackendEnabled reports whether Priv native backend is linked in this build.
func PrivBackendEnabled() bool {
	return true
}
