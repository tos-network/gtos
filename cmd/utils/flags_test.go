// Copyright 2019 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// Package utils contains internal helper functions for go-tos commands.
package utils

import (
	"flag"
	"reflect"
	"testing"

	"github.com/tos-network/gtos/params"
	"github.com/urfave/cli/v2"
)

func Test_SplitTagsFlag(t *testing.T) {
	tests := []struct {
		name string
		args string
		want map[string]string
	}{
		{
			"2 tags case",
			"host=localhost,bzzkey=123",
			map[string]string{
				"host":   "localhost",
				"bzzkey": "123",
			},
		},
		{
			"1 tag case",
			"host=localhost123",
			map[string]string{
				"host": "localhost123",
			},
		},
		{
			"empty case",
			"",
			map[string]string{},
		},
		{
			"garbage",
			"smth=smthelse=123",
			map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SplitTagsFlag(tt.args); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitTagsFlag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveDeveloperPeriodMs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want uint64
	}{
		{name: "default periodms", args: nil, want: params.DPoSBlockPeriodMs},
		{name: "legacy seconds flag", args: []string{"--dev.period=2"}, want: 2000},
		{name: "periodms flag", args: []string{"--dev.periodms=750"}, want: 750},
		{name: "periodms overrides seconds", args: []string{"--dev.period=2", "--dev.periodms=650"}, want: 650},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := cli.NewApp()
			app.Flags = []cli.Flag{DeveloperPeriodFlag, DeveloperPeriodMsFlag}

			set := flag.NewFlagSet("test", flag.ContinueOnError)
			for _, f := range app.Flags {
				if err := f.Apply(set); err != nil {
					t.Fatalf("apply flag: %v", err)
				}
			}
			if err := set.Parse(tt.args); err != nil {
				t.Fatalf("parse flags: %v", err)
			}
			ctx := cli.NewContext(app, set, nil)
			if got := resolveDeveloperPeriodMs(ctx); got != tt.want {
				t.Fatalf("resolveDeveloperPeriodMs() = %d, want %d", got, tt.want)
			}
		})
	}
}
