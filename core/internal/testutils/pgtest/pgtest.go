package pgtest

import (
	"database/sql"
	"os"
	"testing"

	uuid "github.com/satori/go.uuid"
	"github.com/scylladb/go-reflectx"
	"github.com/smartcontractkit/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/smartcontractkit/chainlink/core/logger"
)

func NewGormDB(t *testing.T) *gorm.DB {
	sqlDB := NewSqlDB(t)
	return GormDBFromSql(t, sqlDB)
}

func GormDBFromSql(t *testing.T, db *sql.DB) *gorm.DB {
	logAllQueries := os.Getenv("LOG_SQL") == "true"
	newLogger := logger.NewGormWrapper(logger.TestLogger(t), logAllQueries, 0)
	gormDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
		DSN:  uuid.NewV4().String(),
	}), &gorm.Config{Logger: newLogger})

	require.NoError(t, err)

	// Incantation to fix https://github.com/go-gorm/gorm/issues/4586
	gormDB = gormDB.Omit(clause.Associations).Session(&gorm.Session{})

	return gormDB
}

func NewSqlDB(t *testing.T) *sql.DB {
	db, err := sql.Open("txdb", uuid.NewV4().String())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, db.Close()) })

	require.NoError(t, err)

	return db
}

func NewSqlxDB(t *testing.T) *sqlx.DB {
	db, err := sqlx.Open("txdb", uuid.NewV4().String())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, db.Close()) })

	db.MapperFunc(reflectx.CamelToSnakeASCII)

	return db
}
