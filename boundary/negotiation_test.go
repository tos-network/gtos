package boundary

import (
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input               string
		major, minor, patch int
		wantErr             bool
	}{
		{"0.1.0", 0, 1, 0, false},
		{"1.2.3", 1, 2, 3, false},
		{"10.20.30", 10, 20, 30, false},
		{"0.0.0", 0, 0, 0, false},
		{"", 0, 0, 0, true},
		{"1.2", 0, 0, 0, true},
		{"1.2.3.4", 0, 0, 0, true},
		{"abc.1.0", 0, 0, 0, true},
		{"1.abc.0", 0, 0, 0, true},
		{"1.2.abc", 0, 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			major, minor, patch, err := ParseVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}
			if major != tt.major || minor != tt.minor || patch != tt.patch {
				t.Fatalf("ParseVersion(%q) = %d.%d.%d, want %d.%d.%d",
					tt.input, major, minor, patch, tt.major, tt.minor, tt.patch)
			}
		})
	}
}

func TestIsCompatible(t *testing.T) {
	tests := []struct {
		local, remote string
		want          bool
	}{
		{"0.1.0", "0.1.0", true},
		{"0.1.0", "0.1.1", true},   // patch difference OK
		{"0.1.0", "0.1.99", true},  // large patch difference OK
		{"0.1.0", "0.2.0", false},  // minor mismatch
		{"0.1.0", "1.1.0", false},  // major mismatch
		{"1.0.0", "2.0.0", false},  // major mismatch
		{"1.2.3", "1.2.0", true},   // same major.minor
		{"invalid", "0.1.0", false}, // invalid local
		{"0.1.0", "invalid", false}, // invalid remote
		{"", "", false},             // empty strings
	}

	for _, tt := range tests {
		t.Run(tt.local+"_vs_"+tt.remote, func(t *testing.T) {
			got := IsCompatible(tt.local, tt.remote)
			if got != tt.want {
				t.Fatalf("IsCompatible(%q, %q) = %v, want %v", tt.local, tt.remote, got, tt.want)
			}
		})
	}
}

func TestNegotiate(t *testing.T) {
	// Compatible case: same major.minor as SchemaVersion ("0.1.0")
	result := Negotiate("0.1.5")
	if !result.Compatible {
		t.Fatalf("expected compatible for remote=0.1.5, got incompatible: %s", result.Message)
	}
	if result.LocalVersion != SchemaVersion {
		t.Fatalf("expected local version %q, got %q", SchemaVersion, result.LocalVersion)
	}
	if result.RemoteVersion != "0.1.5" {
		t.Fatalf("expected remote version 0.1.5, got %q", result.RemoteVersion)
	}

	// Exact match
	result = Negotiate("0.1.0")
	if !result.Compatible {
		t.Fatalf("expected compatible for exact match, got incompatible: %s", result.Message)
	}

	// Incompatible case: different minor version
	result = Negotiate("0.2.0")
	if result.Compatible {
		t.Fatalf("expected incompatible for remote=0.2.0, got compatible")
	}
	if result.Message == "" {
		t.Fatal("expected non-empty message for incompatible result")
	}

	// Incompatible case: different major version
	result = Negotiate("1.1.0")
	if result.Compatible {
		t.Fatalf("expected incompatible for remote=1.1.0, got compatible")
	}

	// Incompatible case: invalid version string
	result = Negotiate("garbage")
	if result.Compatible {
		t.Fatalf("expected incompatible for invalid version, got compatible")
	}
}

func TestNegotiateLocalVersion(t *testing.T) {
	// Verify Negotiate always reports the current SchemaVersion as local.
	r := Negotiate("0.1.0")
	if r.LocalVersion != SchemaVersion {
		t.Fatalf("Negotiate local version = %q, want %q", r.LocalVersion, SchemaVersion)
	}
}
