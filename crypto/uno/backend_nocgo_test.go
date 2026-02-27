//go:build !(cgo && ed25519c)

package uno

import "testing"

func TestBackendDisabledWithoutCgo(t *testing.T) {
	if BackendEnabled() {
		t.Fatal("expected UNO backend disabled without cgo build")
	}
}
