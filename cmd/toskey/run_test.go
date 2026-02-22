package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/docker/docker/pkg/reexec"
	"github.com/tos-network/gtos/internal/cmdtest"
)

type testTOSkey struct {
	*cmdtest.TestCmd
}

// spawns toskey with the given command line args.
func runTOSkey(t *testing.T, args ...string) *testTOSkey {
	tt := new(testTOSkey)
	tt.TestCmd = cmdtest.NewTestCmd(t, tt)
	tt.Run("toskey-test", args...)
	return tt
}

func TestMain(m *testing.M) {
	// Run the app if we've been exec'd as "toskey-test" in runTOSkey.
	reexec.Register("toskey-test", func() {
		if err := app.Run(os.Args); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	})
	// check if we have been reexec'd
	if reexec.Init() {
		return
	}
	os.Exit(m.Run())
}
