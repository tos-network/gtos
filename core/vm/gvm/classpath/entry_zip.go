package classpath

import "github.com/tos-network/gtos/core/vm/gvm/utils"

type ZipEntry struct {
	zipFile *utils.ZipFile
}

func newZipEntry(path string) (*ZipEntry, error) {
	if zipFile, err := utils.NewZipFile(path); err != nil {
		return nil, err
	} else {
		return &ZipEntry{zipFile: zipFile}, nil
	}
}

func (entry *ZipEntry) readClass(className string) ([]byte, error) {
	// TODO: close ZipFile
	if !entry.zipFile.IsOpen() {
		if err := entry.zipFile.Open(); err != nil {
			return nil, err
		}
	}

	return entry.zipFile.ReadFile(className)
}

func (entry *ZipEntry) String() string {
	return entry.zipFile.AbsPath()
}
