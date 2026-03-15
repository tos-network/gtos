package main

import (
	"fmt"
	"time"

	"github.com/tos-network/gtos/crypto/priv/ecdlptable"
	"github.com/urfave/cli/v2"
)

var commandPrivGenerateTable = &cli.Command{
	Name:      "priv-generate-table",
	Usage:     "generate a precomputed BSGS table for fast discrete-log decryption",
	ArgsUsage: "<output-file>",
	Description: `
Generates a precomputed Baby-Step Giant-Step table and writes it to a binary
file.  The table accelerates balance decryption by replacing the per-query
O(sqrt(N)) computation with a single lookup.

The --l1 flag controls table size and decode range per giant step:
  L1=13  →    4 K entries, ~45 KB   (for testing)
  L1=22  →    2 M entries, ~21 MB   (medium: covers ~4B with ~1K giant steps)
  L1=26  →   33 M entries, ~350 MB  (high: covers ~4.5e15 with ~67M giant steps)

Use with: toskey priv-balance --table <file> <keyfile>
`,
	Flags: []cli.Flag{
		&cli.UintFlag{
			Name:  "l1",
			Usage: "table L1 parameter (baby-step count = 2^(L1-1))",
			Value: uint(ecdlptable.L1High),
		},
	},
	Action: func(ctx *cli.Context) error {
		outPath := ctx.Args().First()
		if outPath == "" {
			return fmt.Errorf("missing output file argument")
		}
		l1 := ctx.Uint("l1")
		if l1 == 0 || l1 > 32 {
			return fmt.Errorf("--l1 must be in [1, 32]")
		}

		babyCount := uint64(1) << (l1 - 1)
		fmt.Printf("Generating BSGS table: L1=%d, baby entries=%d\n", l1, babyCount)

		start := time.Now()
		lastReport := start
		table, err := ecdlptable.Generate(l1, func(pct float64) {
			now := time.Now()
			if now.Sub(lastReport) >= 2*time.Second || pct >= 1.0 {
				elapsed := now.Sub(start)
				fmt.Printf("  %.1f%% (%s elapsed)\n", pct*100, elapsed.Round(time.Second))
				lastReport = now
			}
		})
		if err != nil {
			return fmt.Errorf("table generation failed: %w", err)
		}

		elapsed := time.Since(start)
		fmt.Printf("Generation complete in %s\n", elapsed.Round(time.Second))

		fmt.Printf("Writing table to %s ...\n", outPath)
		if err := table.Save(outPath); err != nil {
			return fmt.Errorf("failed to save table: %w", err)
		}
		fmt.Println("Done.")
		return nil
	},
}
