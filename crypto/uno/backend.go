package uno

import "github.com/tos-network/gtos/crypto/ed25519"

// BackendEnabled reports whether UNO native crypto backend is available.
func BackendEnabled() bool {
	return ed25519.UNOBackendEnabled()
}
