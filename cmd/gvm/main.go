// Copyright 2024 Terminos Network
// This file is part of tos.
//
// tos is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// tos is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with tos. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/pprof"
	"strings"

	"github.com/tos-network/gtos/core/vm/gvm/classpath"
	"github.com/tos-network/gtos/core/vm/gvm/cpu"
	_ "github.com/tos-network/gtos/core/vm/gvm/native/all"
	"github.com/tos-network/gtos/core/vm/gvm/rtda"
	"github.com/tos-network/gtos/core/vm/gvm/rtda/heap"
	"github.com/tos-network/gtos/core/vm/gvm/utils"
)

const usage = `
Usage: {gvm} [options] class [args...]`

var (
	versionFlag bool
	helpFlag    bool
)

func main() {
	opts, args := parseOptions()
	if helpFlag || opts.MainClass == "" {
		printUsage()
	} else if versionFlag {
		printVersion()
	} else {
		startGVM(opts, args)
	}
}

func parseOptions() (*utils.Options, []string) {
	options := &utils.Options{}
	flag.BoolVar(&versionFlag, "version", false, "Displays version information and exit.")
	flag.BoolVar(&helpFlag, "help", false, "Displays usage information and exit.")
	flag.BoolVar(&helpFlag, "h", false, "Displays usage information and exit.")
	flag.BoolVar(&helpFlag, "?", false, "Displays usage information and exit.")
	flag.StringVar(&options.Xss, "Xss", "", "Sets the thread stack size.")
	flag.StringVar(&options.ClassPath, "classpath", "", "Specifies a list of directories, JAR files, and ZIP archives to search for class files.")
	flag.StringVar(&options.ClassPath, "cp", "", "Specifies a list of directories, JAR files, and ZIP archives to search for class files.")
	flag.BoolVar(&options.VerboseClass, "verbose:class", false, "Displays information about each class loaded.")
	flag.BoolVar(&options.VerboseJNI, "verbose:jni", false, "Displays information about the use of native methods and other Java Native Interface (JNI) activity.")
	flag.StringVar(&options.Xjre, "Xjre", "", "Specifies JRE path.")
	flag.BoolVar(&options.XUseJavaHome, "XuseJavaHome", false, "Uses JAVA_HOME to find JRE path.")
	flag.BoolVar(&options.XDebugInstr, "Xdebug:instr", false, "Displays executed instructions.")
	flag.StringVar(&options.XCPUProfile, "Xprofile:cpu", "", "")
	flag.Parse()

	args := flag.Args()
	options.Init()

	if len(args) > 0 {
		options.MainClass = args[0]
		args = args[1:]
	}

	return options, args
}

func printUsage() {
	fmt.Println(strings.ReplaceAll(strings.TrimSpace(usage), "{gvm}", os.Args[0]))
	flag.PrintDefaults()
}

func printVersion() {
	fmt.Println("gvm 0.1.8.0")
}

func startGVM(opts *utils.Options, args []string) {
	if opts.XCPUProfile != "" {
		f, err := os.Create(opts.XCPUProfile)
		if err != nil {
			panic(err)
		}
		_ = pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	mainThread := createMainThread(opts, args)
	cpu.Loop(mainThread)
	cpu.KeepAlive()
}

func createMainThread(opts *utils.Options, args []string) *rtda.Thread {
	cp := classpath.Parse(opts)
	rt := heap.NewRuntime(cp, opts.VerboseClass)

	mainClass := utils.DotToSlash(opts.MainClass)
	bootArgs := []heap.Slot{heap.NewHackSlot(mainClass), heap.NewHackSlot(args)}
	mainThread := rtda.NewThread(nil, opts, rt)
	mainThread.InvokeMethodWithShim(rtda.ShimBootstrapMethod, bootArgs)
	return mainThread
}
