//go:build !(cgo && ed25519c)

package priv

import "testing"

func TestBackendDisabledWithoutCgo(t *testing.T) {
	if !BackendEnabled() {
		t.Fatal("expected priv backend enabled in pure-Go build")
	}
}
