//go:build tools
// +build tools

package tools

import (
	// Tool imports for go:generate.
	_ "github.com/fjl/gencodec"
	_ "github.com/golang/protobuf/protoc-gen-go"
	_ "golang.org/x/tools/cmd/stringer"

	// Tool imports for mobile build.
	_ "golang.org/x/mobile/cmd/gobind"
	_ "golang.org/x/mobile/cmd/gomobile"
)
