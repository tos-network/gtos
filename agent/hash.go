package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// HashManifest returns the canonical hex-encoded SHA-256 hash of a ToolManifest.
// Signature fields (Sig, SigAlg) are zeroed before hashing so the hash is
// stable across re-signings.
func HashManifest(m ToolManifest) string {
	m.Sig = ""
	m.SigAlg = ""
	b, _ := json.Marshal(m)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
