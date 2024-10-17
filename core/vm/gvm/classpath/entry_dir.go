package classpath

import (
	"github.com/tos-network/gtos/core/vm/gvm/utils"
)

type DirEntry struct {
	dir *utils.Dir
}

func newDirEntry(path string) *DirEntry {
	if dir, err := utils.NewDir(path); err != nil {
		panic(err) // TODO
	} else {
		return &DirEntry{dir: dir}
	}
}

func (entry *DirEntry) readClass(className string) ([]byte, error) {
	return entry.dir.ReadFile(className)
}

func (entry *DirEntry) String() string {
	return entry.dir.AbsPath()
}
