package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/tos-network/gtos/params"
	"github.com/urfave/cli/v2"
)

var (
	VersionCheckUrlFlag = &cli.StringFlag{
		Name:  "check.url",
		Usage: "URL to use when checking vulnerabilities",
		Value: "https://gtos.tos.org/docs/vulnerabilities/vulnerabilities.json",
	}
	VersionCheckVersionFlag = &cli.StringFlag{
		Name:  "check.version",
		Usage: "Version to check",
		Value: fmt.Sprintf("GTOS/v%v/%v-%v/%v",
			params.VersionWithCommit(gitCommit, gitDate),
			runtime.GOOS, runtime.GOARCH, runtime.Version()),
	}
	versionCommand = &cli.Command{
		Action:    version,
		Name:      "version",
		Usage:     "Print version numbers",
		ArgsUsage: " ",
		Description: `
The output of this command is supposed to be machine-readable.
`,
	}
	versionCheckCommand = &cli.Command{
		Action: versionCheck,
		Flags: []cli.Flag{
			VersionCheckUrlFlag,
			VersionCheckVersionFlag,
		},
		Name:      "version-check",
		Usage:     "Checks (online) for known GTOS security vulnerabilities",
		ArgsUsage: "<versionstring (optional)>",
		Description: `
The version-check command fetches vulnerability-information from https://gtos.tos.org/docs/vulnerabilities/vulnerabilities.json,
and displays information about any security vulnerabilities that affect the currently executing version.
`,
	}
	licenseCommand = &cli.Command{
		Action:    license,
		Name:      "license",
		Usage:     "Display license information",
		ArgsUsage: " ",
	}
)

func version(ctx *cli.Context) error {
	fmt.Println(strings.Title(clientIdentifier))
	fmt.Println("Version:", params.VersionWithMeta)
	if gitCommit != "" {
		fmt.Println("Git Commit:", gitCommit)
	}
	if gitDate != "" {
		fmt.Println("Git Commit Date:", gitDate)
	}
	fmt.Println("Architecture:", runtime.GOARCH)
	fmt.Println("Go Version:", runtime.Version())
	fmt.Println("Operating System:", runtime.GOOS)
	fmt.Printf("GOPATH=%s\n", os.Getenv("GOPATH"))
	fmt.Printf("GOROOT=%s\n", runtime.GOROOT())
	return nil
}

func license(_ *cli.Context) error {
	fmt.Println(`GTOS licensing summary

- Default repository license: GNU LGPL-3.0 (see LICENSE)
- cmd/ command applications include GPL-3.0-governed components (see COPYING)
- Some embedded third-party subdirectories carry their own license files

See LICENSES.md for directory-level mapping and NOTICE for origin/attribution.`)
	return nil
}
