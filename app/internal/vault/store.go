package vault

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// store keeps only ciphertext plus the minimum header needed to unlock.
type store struct {
	db *sql.DB
}

type rawItem struct {
	id       string
	revision int64
	blob     []byte
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS items (id TEXT PRIMARY KEY, revision INTEGER NOT NULL, blob BLOB NOT NULL);
`

func openStore(path string) (*store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(path) + "?_pragma=busy_timeout(5000)&_pragma=secure_delete(1)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &store{db: db}, nil
}

func (s *store) close() error { return s.db.Close() }

func (s *store) meta(key string) ([]byte, bool, error) {
	var v []byte
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	return v, err == nil, err
}

func setMeta(tx *sql.Tx, key string, value []byte) error {
	_, err := tx.Exec(`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (s *store) items() ([]rawItem, error) {
	rows, err := s.db.Query(`SELECT id, revision, blob FROM items`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rawItem
	for rows.Next() {
		var r rawItem
		if err := rows.Scan(&r.id, &r.revision, &r.blob); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func putItem(tx *sql.Tx, r rawItem) error {
	_, err := tx.Exec(`INSERT INTO items (id, revision, blob) VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET revision = excluded.revision, blob = excluded.blob`, r.id, r.revision, r.blob)
	return err
}

func deleteItem(tx *sql.Tx, id string) error {
	_, err := tx.Exec(`DELETE FROM items WHERE id = ?`, id)
	return err
}

func (s *store) tx(fn func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func deleteMeta(tx *sql.Tx, key string) error {
	_, err := tx.Exec(`DELETE FROM meta WHERE key = ?`, key)
	return err
}
