package boundary

import (
	"fmt"
	"strconv"
	"strings"
)

// NegotiationResult describes whether two systems are compatible.
type NegotiationResult struct {
	Compatible    bool   `json:"compatible"`
	LocalVersion  string `json:"local_version"`
	RemoteVersion string `json:"remote_version"`
	Message       string `json:"message,omitempty"`
}

// Negotiate checks if a remote schema version is compatible with the local
// boundary schema version. Two versions are compatible when they share the
// same major.minor numbers (patch differences are tolerated).
func Negotiate(remoteVersion string) NegotiationResult {
	local := SchemaVersion
	if IsCompatible(local, remoteVersion) {
		return NegotiationResult{
			Compatible:    true,
			LocalVersion:  local,
			RemoteVersion: remoteVersion,
			Message:       fmt.Sprintf("schema versions compatible: local=%s remote=%s", local, remoteVersion),
		}
	}
	return NegotiationResult{
		Compatible:    false,
		LocalVersion:  local,
		RemoteVersion: remoteVersion,
		Message:       fmt.Sprintf("schema version mismatch: local=%s remote=%s (major.minor must match)", local, remoteVersion),
	}
}

// ParseVersion extracts major, minor, and patch from a semver string
// such as "0.1.0" or "1.2.3".
func ParseVersion(v string) (major, minor, patch int, err error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, 0, 0, fmt.Errorf("empty version string")
	}

	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("invalid semver %q: expected 3 parts, got %d", v, len(parts))
	}

	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid major version %q: %w", parts[0], err)
	}

	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid minor version %q: %w", parts[1], err)
	}

	patch, err = strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid patch version %q: %w", parts[2], err)
	}

	if major < 0 || minor < 0 || patch < 0 {
		return 0, 0, 0, fmt.Errorf("version components must be non-negative")
	}

	return major, minor, patch, nil
}

// IsCompatible checks whether two semver strings are compatible.
// Compatibility requires the same major and minor numbers; patch
// differences are acceptable.
func IsCompatible(local, remote string) bool {
	lMajor, lMinor, _, lErr := ParseVersion(local)
	rMajor, rMinor, _, rErr := ParseVersion(remote)
	if lErr != nil || rErr != nil {
		return false
	}
	return lMajor == rMajor && lMinor == rMinor
}
