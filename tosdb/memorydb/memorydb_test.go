package memorydb

import (
	"testing"

	"github.com/tos-network/gtos/tosdb"
	"github.com/tos-network/gtos/tosdb/dbtest"
)

func TestMemoryDB(t *testing.T) {
	t.Run("DatabaseSuite", func(t *testing.T) {
		dbtest.TestDatabaseSuite(t, func() tosdb.KeyValueStore {
			return New()
		})
	})
}
