package classpath

import (
	"path/filepath"
	"strings"

	"github.com/tos-network/gtos/core/vm/gvm/utils"
)

type ClassPath struct {
	entries []Entry
}

func Parse(opts *utils.Options) *ClassPath {
	cp := &ClassPath{}
	cp.parseBootAndExtClassPath(opts.AbsJavaHome)
	cp.parseUserClassPath(opts.ClassPath)
	return cp
}

func (cp *ClassPath) parseBootAndExtClassPath(absJavaHome string) {
	// jre/lib/*
	jreLibPath := filepath.Join(absJavaHome, "lib", "*")
	if sp, err := spreadWildcardEntry(jreLibPath); err == nil {
		cp.entries = append(cp.entries, sp...)
	}

	// jre/lib/ext/*
	jreExtPath := filepath.Join(absJavaHome, "lib", "ext", "*")
	if sp, err := spreadWildcardEntry(jreExtPath); err == nil {
		cp.entries = append(cp.entries, sp...)
	}
}

func (cp *ClassPath) parseUserClassPath(cpOption string) {
	if cpOption == "" {
		cpOption = "."
	}
	if p, err := parsePath(cpOption); err == nil {
		cp.entries = append(cp.entries, p...)
	}
}

// className: fully/qualified/ClassName
func (cp *ClassPath) ReadClass(className string) (Entry, []byte) {
	className = className + ".class"
	for _, entry := range cp.entries {
		if data, err := entry.readClass(className); err == nil {
			return entry, data
		}
	}
	return nil, nil
}

func IsBootClassPath(entry Entry, absJreLib string) bool {
	if entry == nil {
		return true
	}
	return strings.HasPrefix(entry.String(), absJreLib)
}
