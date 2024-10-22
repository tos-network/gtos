package classpath

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/tos-network/gtos/core/vm/gvm/utils"
)

type Entry interface {
	// className: fully/qualified/ClassName.class
	readClass(className string) ([]byte, error)
	String() string
}

func parsePath(path string) ([]Entry, error) {
	switch {
	case strings.IndexByte(path, os.PathListSeparator) >= 0:
		return splitPath(path), nil
	case strings.HasSuffix(path, "*"):
		return spreadWildcardEntry(path)
	case utils.IsJarFile(path) || utils.IsZipFile(path):
		zipEntry, err := newZipEntry(path)
		if err != nil {
			return nil, err
		}
		return []Entry{zipEntry}, nil
	default:
		dirEntry, err := newDirEntry(path)
		if err != nil {
			return nil, err
		}
		return []Entry{dirEntry}, nil
	}
}

func splitPath(pathList string) []Entry {
	list := make([]Entry, 0, 4)
	for _, path := range strings.Split(pathList, string(os.PathListSeparator)) {
		if p, err := parsePath(path); err == nil {
			list = append(list, p...)
		}
	}

	return list
}

func spreadWildcardEntry(path string) ([]Entry, error) {
	baseDir := path[:len(path)-1] // remove *
	files, err := os.ReadDir(baseDir)
	if err != nil {
		return nil, err
	}

	list := make([]Entry, 0, 4)
	for _, file := range files {
		if utils.IsJarFile(file.Name()) {
			filename := filepath.Join(baseDir, file.Name())
			zipEntry, err := newZipEntry(filename)
			if err == nil {
				list = append(list, zipEntry)
			}
		}
	}

	return list, nil
}
