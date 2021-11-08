package pgtest

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

// txdb is a simplified version of https://github.com/DATA-DOG/go-txdb
// The original lib has various problems and is harder to understand because it tries to be more general
// This version is very tightly focused and should be easier to reason about and less likely to have subtle bugs/races

func init() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		panic("you must provide a DATABASE_URL environment variable")
	}

	parsed, err := url.Parse(dbURL)
	if err != nil {
		panic(err)
	}
	if parsed.Path == "" {
		msg := fmt.Sprintf("invalid DATABASE_URL: `%s`. You must set DATABASE_URL env var to point to your test database. Note that the test database MUST end in `_test` to differentiate from a possible production DB. HINT: Try DATABASE_URL=postgresql://postgres@localhost:5432/chainlink_test?sslmode=disable", parsed.String())
		panic(msg)
	}
	if !strings.HasSuffix(parsed.Path, "_test") {
		msg := fmt.Sprintf("cannot run tests against database named `%s`. Note that the test database MUST end in `_test` to differentiate from a possible production DB. HINT: Try DATABASE_URL=postgresql://postgres@localhost:5432/chainlink_test?sslmode=disable", parsed.Path[1:])
		panic(msg)
	}
	// NOTE: That this will cause transaction BEGIN/ROLLBACK to effectively be
	// a no-op, this should have no negative impact on normal test operation.
	// If you MUST test BEGIN/ROLLBACK behaviour, you will have to configure your
	// store to use the raw DialectPostgres dialect and setup a one-use database.
	// See BootstrapThrowawayORM() as a convenience function to help you do this.
	// https://app.clubhouse.io/chainlinklabs/story/8781/remove-dependency-on-gorm
	sql.Register("txdb", &txDriver{
		dbURL: dbURL,
		conns: make(map[string]*conn),
	})
	sqlx.BindDriver("txdb", sqlx.DOLLAR)
}

// Originally we used go-txdb but it has bugs

var _ driver.Conn = &conn{}

// txDriver is an sql driver which runs on single transaction
// when the Close is called, transaction is rolled back
type txDriver struct {
	sync.Mutex
	db      *sql.DB
	conns   map[string]*conn
	options []func(*conn) error

	dbURL string
}

type conn struct {
	sync.Mutex
	tx     *sql.Tx
	closed bool
	remove func() error
}

func (d *txDriver) Open(dsn string) (driver.Conn, error) {
	d.Lock()
	defer d.Unlock()
	// Open real db connection if its the first call
	if d.db == nil {
		db, err := sql.Open("pgx", d.dbURL)
		if err != nil {
			return nil, err
		}
		d.db = db
	}
	if _, exists := d.conns[dsn]; exists {
		return nil, errors.Errorf("already opened database with dsn: %s", dsn)
	}
	tx, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	c := &conn{tx: tx}
	d.conns[dsn] = c
	c.remove = func() error {
		return errors.Wrap(d.deleteConn(dsn), "failed to remove conn")
	}
	return c, nil
}

// deleteConn is called by connection when it is closed
// It also auto-closes the DB when the last checked out connection is closed
func (d *txDriver) deleteConn(dsn string) error {
	d.Lock()
	defer d.Unlock()

	delete(d.conns, dsn)
	if len(d.conns) == 0 && d.db != nil {
		if err := d.db.Close(); err != nil {
			return err
		}
		d.db = nil
	}
	return nil
}

func (c *conn) Begin() (driver.Tx, error) {
	c.Lock()
	defer c.Unlock()
	if c.closed {
		panic("conn is closed")
	}
	// Begin is a noop because the transaction was already opened
	return c.tx, nil
}

// Implement the "ConnBeginTx" interface
func (c *conn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Begin()
}

// Prepare returns a prepared statement, bound to this connection.
func (c *conn) Prepare(query string) (driver.Stmt, error) {
	c.Lock()
	defer c.Unlock()
	if c.closed {
		panic("conn is closed")
	}
	st, err := c.tx.Prepare(query)
	if err != nil {
		return nil, err
	}
	return stmt{st, c}, nil
}

// Implement the "ConnPrepareContext" interface
func (c *conn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	c.Lock()
	defer c.Unlock()
	if c.closed {
		panic("conn is closed")
	}

	st, err := c.tx.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	return &stmt{st, c}, nil
}

// Close invalidates and potentially stops any current
// prepared statements and transactions, marking this
// connection as no longer in use.
//
// Because the sql package maintains a free pool of
// connections and only calls Close when there's a surplus of
// idle connections, it shouldn't be necessary for drivers to
// do their own connection caching.
//
// Drivers must ensure all network calls made by Close
// do not block indefinitely (e.g. apply a timeout).
func (c *conn) Close() (err error) {
	c.Lock()
	defer c.Unlock()

	if c.closed {
		panic("conn already closed")
	}
	c.closed = false

	// Rollback on Close
	if err = c.tx.Rollback(); err != nil {
		err = errors.Wrap(err, "failed to rollback transaction on close")
	}

	// remove dsn from the parent driver map
	if err = c.remove(); err != nil {
		return errors.Wrap(err, "failed to remove conn")
	}

	return nil
}

// pgx returns nil
func (c *conn) CheckNamedValue(nv *driver.NamedValue) error {
	return nil
}

type stmt struct {
	st   *sql.Stmt
	conn *conn
}

func (s stmt) Exec(args []driver.Value) (driver.Result, error) {
	s.conn.Lock()
	defer s.conn.Unlock()
	if s.conn.closed {
		panic("conn is closed")
	}
	return s.st.Exec(mapArgs(args)...)
}

// Implement the "StmtExecContext" interface
func (s *stmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	s.conn.Lock()
	defer s.conn.Unlock()
	if s.conn.closed {
		panic("conn is closed")
	}
	return s.st.ExecContext(ctx, mapNamedArgs(args)...)
}

func mapArgs(args []driver.Value) (res []interface{}) {
	res = make([]interface{}, len(args))
	for i := range args {
		res[i] = args[i]
	}
	return
}

func (s stmt) NumInput() int {
	return -1
}

func (s stmt) Query(args []driver.Value) (driver.Rows, error) {
	s.conn.Lock()
	defer s.conn.Unlock()
	if s.conn.closed {
		panic("conn is closed")
	}
	rows, err := s.st.Query(mapArgs(args)...)
	defer rows.Close()
	if err != nil {
		return nil, err
	}
	return buildRows(rows)
}

// Implement the "StmtQueryContext" interface
func (s *stmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	s.conn.Lock()
	defer s.conn.Unlock()
	if s.conn.closed {
		panic("conn is closed")
	}
	rows, err := s.st.QueryContext(ctx, mapNamedArgs(args)...)
	if err != nil {
		return nil, err
	}
	return buildRows(rows)
}

func (s stmt) Close() error {
	return s.st.Close()
}

func buildRows(r *sql.Rows) (driver.Rows, error) {
	set := &rowSets{}
	rs := &rows{}
	if err := rs.read(r); err != nil {
		return set, err
	}
	set.sets = append(set.sets, rs)
	for r.NextResultSet() {
		rss := &rows{}
		if err := rss.read(r); err != nil {
			return set, err
		}
		set.sets = append(set.sets, rss)
	}
	return set, nil
}

// Implement the "RowsNextResultSet" interface
func (rs *rowSets) HasNextResultSet() bool {
	return rs.pos+1 < len(rs.sets)
}

// Implement the "RowsNextResultSet" interface
func (rs *rowSets) NextResultSet() error {
	if !rs.HasNextResultSet() {
		return io.EOF
	}

	rs.pos++
	return nil
}

type rows struct {
	rows     [][]driver.Value
	pos      int
	cols     []string
	colTypes []*sql.ColumnType
}

func (r *rows) Columns() []string {
	return r.cols
}

func (r *rows) ColumnTypeDatabaseTypeName(index int) string {
	return r.colTypes[index].DatabaseTypeName()
}

func (r *rows) Next(dest []driver.Value) error {
	r.pos++
	if r.pos > len(r.rows) {
		return io.EOF
	}

	for i, val := range r.rows[r.pos-1] {
		dest[i] = *(val.(*interface{}))
	}

	return nil
}

func (r *rows) Close() error {
	return nil
}

func (r *rows) read(rs *sql.Rows) error {
	var err error
	r.cols, err = rs.Columns()
	if err != nil {
		return err
	}

	r.colTypes, err = rs.ColumnTypes()
	if err != nil {
		return err
	}

	for rs.Next() {
		values := make([]interface{}, len(r.cols))
		for i := range values {
			values[i] = new(interface{})
		}
		if err := rs.Scan(values...); err != nil {
			return err
		}
		row := make([]driver.Value, len(r.cols))
		for i, v := range values {
			row[i] = driver.Value(v)
		}
		r.rows = append(r.rows, row)
	}
	return rs.Err()
}

type rowSets struct {
	sets []*rows
	pos  int
}

func (rs *rowSets) Columns() []string {
	return rs.sets[rs.pos].cols
}

func (rs *rowSets) ColumnTypeDatabaseTypeName(index int) string {
	return rs.sets[rs.pos].ColumnTypeDatabaseTypeName(index)
}

func (rs *rowSets) Close() error {
	return nil
}

// advances to next row
func (rs *rowSets) Next(dest []driver.Value) error {
	return rs.sets[rs.pos].Next(dest)
}

func mapNamedArgs(args []driver.NamedValue) (res []interface{}) {
	res = make([]interface{}, len(args))
	for i := range args {
		name := args[i].Name
		if name != "" {
			res[i] = sql.Named(name, args[i].Value)
		} else {
			res[i] = args[i].Value
		}
	}
	return
}
