package vault

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func init() {
	// Keep tests fast; production uses DefaultKDF as declared.
	DefaultKDF = KDFParams{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
}

const master = "correct horse battery staple"

func newVault(t *testing.T) (*Vault, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	v, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Create([]byte(master)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	return v, path
}

func login(name, pw string) Item {
	return Item{Type: TypeLogin, Name: name, URL: "https://Example.com/login#frag", Alias: "work", Account: "me@example.com", Password: pw}
}

func reopen(t *testing.T, v *Vault, path string) *Vault {
	t.Helper()
	v.Close()
	v2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v2.Close() })
	return v2
}

func TestCreateSaveReopenUnlock(t *testing.T) {
	v, path := newVault(t)
	saved, err := v.Save(login("Site", "Secret-Pw-123"))
	if err != nil {
		t.Fatal(err)
	}
	if saved.Origin != "https://example.com" || saved.URL != "https://example.com/login" || saved.GrantMin != 30 {
		t.Fatalf("normalize: %+v", saved)
	}
	v2 := reopen(t, v, path)
	if !v2.Initialized() || !v2.Locked() {
		t.Fatal("reopened vault should be initialized and locked")
	}
	if _, err := v2.Items(); !errors.Is(err, ErrLocked) {
		t.Fatalf("items while locked: %v", err)
	}
	if err := v2.Unlock([]byte("wrong password!!")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	if err := v2.Unlock([]byte(master)); err != nil {
		t.Fatal(err)
	}
	got, err := v2.Item(saved.ID)
	if err != nil || got.Password != "Secret-Pw-123" {
		t.Fatalf("got %+v, %v", got, err)
	}
	v2.Lock()
	if _, err := v2.Item(saved.ID); !errors.Is(err, ErrLocked) {
		t.Fatal("lock should forget items")
	}
}

func TestNoPlaintextOnDisk(t *testing.T) {
	v, path := newVault(t)
	secrets := []string{"Plaintext-Password-XYZ", "secret-account@example.org", "My Bank Name", "recovery-code-777"}
	if _, err := v.Save(Item{Type: TypeLogin, Name: secrets[2], URL: "https://bank.example", Alias: "a", Account: secrets[1], Password: secrets[0]}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Save(Item{Type: TypeNote, Name: "codes", Note: secrets[3]}); err != nil {
		t.Fatal(err)
	}
	v.Close()
	for _, f := range []string{path, path + "-journal", path + "-wal"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, s := range append(secrets, master, "bank.example") {
			if bytes.Contains(data, []byte(s)) {
				t.Errorf("%s contains plaintext %q", filepath.Base(f), s)
			}
		}
	}
}

func TestTamperDetected(t *testing.T) {
	v, path := newVault(t)
	a, _ := v.Save(login("A", "pw-a-aaaaaaaa"))
	b, _ := v.Save(login("B", "pw-b-bbbbbbbb"))
	v.Close()

	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	// Swap the two ciphertexts: AAD binds each blob to its item ID, so this must fail.
	var blobA, blobB []byte
	db.QueryRow(`SELECT blob FROM items WHERE id=?`, a.ID).Scan(&blobA)
	db.QueryRow(`SELECT blob FROM items WHERE id=?`, b.ID).Scan(&blobB)
	db.Exec(`UPDATE items SET blob=? WHERE id=?`, blobB, a.ID)
	db.Exec(`UPDATE items SET blob=? WHERE id=?`, blobA, b.ID)
	db.Close()

	v2, _ := Open(path)
	defer v2.Close()
	if err := v2.Unlock([]byte(master)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("swapped blobs: got %v, want ErrCorrupt", err)
	}
}

func TestRevisionRollbackDetected(t *testing.T) {
	v, path := newVault(t)
	it, _ := v.Save(login("A", "old-password-1"))
	v.Close()
	db, _ := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	db.Exec(`UPDATE items SET revision = revision + 1 WHERE id=?`, it.ID)
	db.Close()
	v2, _ := Open(path)
	defer v2.Close()
	if err := v2.Unlock([]byte(master)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("changed revision: got %v", err)
	}
}

func TestHostileKDFRejected(t *testing.T) {
	v, path := newVault(t)
	v.Close()
	db, _ := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	huge, _ := json.Marshal(KDFParams{Time: 1, MemoryKiB: 64 << 20, Threads: 1})
	db.Exec(`UPDATE meta SET value=? WHERE key='kdf'`, huge)
	db.Close()
	v2, _ := Open(path)
	defer v2.Close()
	if err := v2.Unlock([]byte(master)); !errors.Is(err, errBadKDF) {
		t.Fatalf("hostile kdf: %v", err)
	}
}

func TestNewerFormatRefused(t *testing.T) {
	v, path := newVault(t)
	v.Close()
	db, _ := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	db.Exec(`UPDATE meta SET value='2' WHERE key='format'`)
	db.Close()
	if _, err := Open(path); !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("newer format: %v", err)
	}
}

func TestUpdateKeepsSecretWhenBlank(t *testing.T) {
	v, _ := newVault(t)
	it, _ := v.Save(login("A", "keep-me-please"))
	it.Password = ""
	it.Name = "A2"
	up, err := v.Save(it)
	if err != nil {
		t.Fatal(err)
	}
	if up.Password != "keep-me-please" || up.Revision != 2 || up.Name != "A2" {
		t.Fatalf("update: %+v", up)
	}
	note, _ := v.Save(Item{Type: TypeNote, Name: "n", Note: "line1\nline2"})
	note.Note = ""
	note.Type = TypeLogin // type cannot change on update
	up2, err := v.Save(note)
	if err != nil || up2.Note != "line1\nline2" || up2.Type != TypeNote {
		t.Fatalf("note update: %+v %v", up2, err)
	}
}

func TestSecretsNotTrimmed(t *testing.T) {
	v, _ := newVault(t)
	it, err := v.Save(Item{Type: TypePassword, Name: " wifi ", Password: "  spaced pw  "})
	if err != nil {
		t.Fatal(err)
	}
	if it.Password != "  spaced pw  " || it.Name != "wifi" {
		t.Fatalf("got %+v", it)
	}
}

func TestValidation(t *testing.T) {
	v, _ := newVault(t)
	cases := []Item{
		{Type: TypeLogin, Name: "x", URL: "http://example.com", Alias: "a", Account: "b", Password: "p"},
		{Type: TypeLogin, Name: "x", URL: "https://user:pw@example.com", Alias: "a", Account: "b", Password: "p"},
		{Type: TypeLogin, Name: "x", URL: "example.com", Alias: "a", Account: "b", Password: "p"},
		{Type: TypeLogin, Name: "", URL: "https://example.com", Alias: "a", Account: "b", Password: "p"},
		{Type: TypeLogin, Name: "x", URL: "https://example.com", Alias: "a", Account: "b", Password: "p", GrantMin: 7},
		{Type: TypePassword, Name: "x"},
		{Type: TypeNote, Name: "x"},
		{Type: "other", Name: "x", Password: "p"},
	}
	for i, c := range cases {
		if _, err := v.Save(c); err == nil {
			t.Errorf("case %d should be rejected: %+v", i, c)
		}
	}
}

func TestChangeMaster(t *testing.T) {
	v, path := newVault(t)
	it, _ := v.Save(login("A", "pw-123456789"))
	if err := v.ChangeMaster([]byte("bad"), []byte("new master pw!")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("old pw check: %v", err)
	}
	if err := v.ChangeMaster([]byte(master), []byte("new master pw!")); err != nil {
		t.Fatal(err)
	}
	v2 := reopen(t, v, path)
	if err := v2.Unlock([]byte(master)); !errors.Is(err, ErrWrongPassword) {
		t.Fatal("old master should stop working")
	}
	if err := v2.Unlock([]byte("new master pw!")); err != nil {
		t.Fatal(err)
	}
	if got, _ := v2.Item(it.ID); got.Password != "pw-123456789" {
		t.Fatal("items must survive master change")
	}
}

func TestDeleteAndSettings(t *testing.T) {
	v, path := newVault(t)
	it, _ := v.Save(login("A", "pw-123456789"))
	if err := v.Delete(it.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Item(it.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted item still present")
	}
	if s, _ := v.Settings(); s.IdleMinutes != 5 {
		t.Fatalf("default idle: %+v", s)
	}
	v.UpdateSettings(func(s *Settings) { s.IdleMinutes = 15 })
	v2 := reopen(t, v, path)
	v2.Unlock([]byte(master))
	if s, _ := v2.Settings(); s.IdleMinutes != 15 {
		t.Fatalf("settings not persisted: %+v", s)
	}
	items, _ := v2.Items()
	if len(items) != 0 {
		t.Fatal("delete not persisted")
	}
}

func TestCreateTwiceRefused(t *testing.T) {
	v, _ := newVault(t)
	if err := v.Create([]byte("another password")); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatal(err)
	}
}

func TestLoginURLRules(t *testing.T) {
	it := Item{Type: TypeLogin, Name: "School", URL: "https://Portal.example.edu/", LoginURL: " https://ID.example.edu:8443/nidp ", Alias: "a", Account: "u", Password: "p"}
	if err := normalize(&it); err != nil || it.LoginOrigin != "https://id.example.edu:8443" || it.LoginURL != "https://id.example.edu:8443/nidp" {
		t.Fatalf("%+v %v", it, err)
	}
	it.LoginURL = "http://id.example.edu"
	if err := normalize(&it); err == nil {
		t.Fatal("plain http login page accepted")
	}
	it.LoginURL = "https://portal.example.edu/other"
	if err := normalize(&it); err != nil || it.LoginURL != "" || it.LoginOrigin != "" {
		t.Fatalf("same origin should be dropped: %+v %v", it, err)
	}
	pw := Item{Type: TypePassword, Name: "x", LoginURL: "https://a.example", LoginOrigin: "https://a.example", Password: "p"}
	if err := normalize(&pw); err != nil || pw.LoginURL != "" || pw.LoginOrigin != "" {
		t.Fatalf("other types keep no login page: %+v %v", pw, err)
	}
}

func TestLocalHTTPOnly(t *testing.T) {
	for raw, ok := range map[string]bool{
		"http://localhost:3000/login":   true,
		"http://LOCALHOST:5173":         true,
		"http://127.0.0.1:8080/":        true,
		"http://[::1]:4000/":            true,
		"https://example.com":           true,
		"http://example.com":            false,
		"http://localhost.evil.com":     false,
		"http://127.0.0.2:8080":         false,
		"http://192.168.1.10:3000":      false,
		"http://user:pw@localhost:3000": false,
		"ftp://localhost":               false,
	} {
		it := Item{Type: TypeLogin, Name: "Dev", URL: raw, Alias: "a", Account: "u", Password: "p"}
		if err := normalize(&it); (err == nil) != ok {
			t.Errorf("%s: err=%v, want ok=%v", raw, err, ok)
		}
	}
	it := Item{Type: TypeLogin, Name: "Dev", URL: "http://localhost:3000/login", Alias: "a", Account: "u", Password: "p"}
	if normalize(&it); it.Origin != "http://localhost:3000" {
		t.Fatalf("origin %q", it.Origin)
	}
}
