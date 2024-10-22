package classpath

import (
	"github.com/tos-network/gtos/core/vm/gvm/utils"
)

type DirEntry struct {
	dir *utils.Dir
}

func newDirEntry(path string) (*DirEntry, error) {
	if dir, err := utils.NewDir(path); err != nil {
		return nil, err
	} else {
		return &DirEntry{dir: dir}, nil
	}
}

func (entry *DirEntry) readClass(className string) ([]byte, error) {
	return entry.dir.ReadFile(className)
}

func (entry *DirEntry) String() string {
	return entry.dir.AbsPath()
}
