package main

import (
	"crypto/rand"
	"math/big"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tos-network/gtos/params"
)

const (
	ipcAPIs  = "admin:1.0 debug:1.0 dpos:1.0 miner:1.0 net:1.0 personal:1.0 rpc:1.0 tos:1.0 txpool:1.0 web3:1.0"
	httpAPIs = "net:1.0 rpc:1.0 tos:1.0 web3:1.0"
)

// spawns gtos with the given command line args, using a set of flags to minimise
// memory and disk IO. If the args don't set --datadir, the
// child g gets a temporary data directory.
func runMinimalGTOS(t *testing.T, args ...string) *testgeth {
	// --networkid=1337 to avoid cache bump
	// --syncmode=full to avoid allocating fast sync bloom
	allArgs := []string{"--networkid", "1337", "--authrpc.port", "0", "--syncmode=full", "--port", "0",
		"--nat", "none", "--nodiscover", "--maxpeers", "0", "--cache", "64",
		"--datadir.minfreedisk", "0"}
	return runGeth(t, append(allArgs, args...)...)
}

// Tests that a node embedded within a console can be started up properly and
// then terminated by closing the input stream.
func TestConsoleWelcome(t *testing.T) {
	coinbase := "0x969b0a11b8a56bacf1ac18f219e7e376e7c213b7e7e7e46cc70a5dd086daff2a"

	// Start a gtos console, make sure it's cleaned up and terminate the console
	gtos := runMinimalGTOS(t, "--miner.coinbase", coinbase, "console")

	// Gather all the infos the welcome message needs to contain
	gtos.SetTemplateFunc("goos", func() string { return runtime.GOOS })
	gtos.SetTemplateFunc("goarch", func() string { return runtime.GOARCH })
	gtos.SetTemplateFunc("gover", runtime.Version)
	gtos.SetTemplateFunc("gtosver", func() string { return params.VersionWithCommit("", "") })
	gtos.SetTemplateFunc("niltime", func() string {
		return time.Unix(0, 0).Format("Mon Jan 02 2006 15:04:05 GMT-0700 (MST)")
	})
	gtos.SetTemplateFunc("apis", func() string { return ipcAPIs })

	// Verify the actual welcome message to the required template
	gtos.Expect(`
Welcome to the GTOS JavaScript console!

instance: GTOS/v{{gtosver}}/{{goos}}-{{goarch}}/{{gover}}
coinbase: {{.Coinbase}}
at block: 0 ({{niltime}})
 datadir: {{.Datadir}}
 modules: {{apis}}

To exit, press ctrl-d or type exit
> {{.InputLine "exit"}}
`)
	gtos.ExpectExit()
}

// Tests that a console can be attached to a running node via various means.
func TestAttachWelcome(t *testing.T) {
	var (
		ipc      string
		httpPort string
		wsPort   string
	)
	// Configure the instance for IPC attachment
	if runtime.GOOS == "windows" {
		ipc = `\\.\pipe\gtos` + strconv.Itoa(trulyRandInt(100000, 999999))
	} else {
		ipc = filepath.Join(t.TempDir(), "gtos.ipc")
	}
	// And HTTP + WS attachment
	p := trulyRandInt(1024, 65533) // Yeah, sometimes this will fail, sorry :P
	httpPort = strconv.Itoa(p)
	wsPort = strconv.Itoa(p + 1)
	gtos := runMinimalGTOS(t, "--miner.coinbase", "0x969b0a11b8a56bacf1ac18f219e7e376e7c213b7e7e7e46cc70a5dd086daff2a",
		"--ipcpath", ipc,
		"--http", "--http.port", httpPort,
		"--ws", "--ws.port", wsPort)
	t.Run("ipc", func(t *testing.T) {
		waitForEndpoint(t, ipc, 3*time.Second)
		testAttachWelcome(t, gtos, "ipc:"+ipc, ipcAPIs)
	})
	t.Run("http", func(t *testing.T) {
		endpoint := "http://127.0.0.1:" + httpPort
		waitForEndpoint(t, endpoint, 3*time.Second)
		testAttachWelcome(t, gtos, endpoint, httpAPIs)
	})
	t.Run("ws", func(t *testing.T) {
		endpoint := "ws://127.0.0.1:" + wsPort
		waitForEndpoint(t, endpoint, 3*time.Second)
		testAttachWelcome(t, gtos, endpoint, httpAPIs)
	})
	gtos.ExpectExit()
}

func testAttachWelcome(t *testing.T, gtos *testgeth, endpoint, apis string) {
	// Attach to a running gtos note and terminate immediately
	attach := runGeth(t, "attach", endpoint)
	defer attach.ExpectExit()
	attach.CloseStdin()

	// Gather all the infos the welcome message needs to contain
	attach.SetTemplateFunc("goos", func() string { return runtime.GOOS })
	attach.SetTemplateFunc("goarch", func() string { return runtime.GOARCH })
	attach.SetTemplateFunc("gover", runtime.Version)
	attach.SetTemplateFunc("gtosver", func() string { return params.VersionWithCommit("", "") })
	attach.SetTemplateFunc("coinbase", func() string { return gtos.Coinbase })
	attach.SetTemplateFunc("niltime", func() string {
		return time.Unix(0, 0).Format("Mon Jan 02 2006 15:04:05 GMT-0700 (MST)")
	})
	attach.SetTemplateFunc("ipc", func() bool { return strings.HasPrefix(endpoint, "ipc") })
	attach.SetTemplateFunc("datadir", func() string { return gtos.Datadir })
	attach.SetTemplateFunc("apis", func() string { return apis })

	// Verify the actual welcome message to the required template
	attach.Expect(`
Welcome to the GTOS JavaScript console!

instance: GTOS/v{{gtosver}}/{{goos}}-{{goarch}}/{{gover}}
coinbase: {{coinbase}}
at block: 0 ({{niltime}}){{if ipc}}
 datadir: {{datadir}}{{end}}
 modules: {{apis}}

To exit, press ctrl-d or type exit
> {{.InputLine "exit" }}
`)
	attach.ExpectExit()
}

// trulyRandInt generates a crypto random integer used by the console tests to
// not clash network ports with other tests running concurrently.
func trulyRandInt(lo, hi int) int {
	num, _ := rand.Int(rand.Reader, big.NewInt(int64(hi-lo)))
	return int(num.Int64()) + lo
}
