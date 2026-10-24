package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const backupPw = "backup password 123"

func filled(t *testing.T) (*Vault, string) {
	v, path := newVault(t)
	v.Save(login("Site", "Site-Secret-Pw"))
	v.Save(Item{Type: TypePassword, Name: "wifi", Password: "  wifi pw  "})
	v.Save(Item{Type: TypeNote, Name: "codes", Note: "CODE-1\nCODE-2"})
	return v, path
}

func TestBackupRoundTripToNewVault(t *testing.T) {
	v, _ := filled(t)
	if s, _ := v.Settings(); !s.BackupStale() {
		t.Fatal("new vault without backup should be stale")
	}
	file := filepath.Join(t.TempDir(), "b.passpw")
	info, err := v.ExportBackup(file, []byte(backupPw))
	if err != nil {
		t.Fatal(err)
	}
	if info.Count != 3 || info.Logins != 1 || info.Passwords != 1 || info.Notes != 1 {
		t.Fatalf("info %+v", info)
	}
	if s, _ := v.Settings(); s.BackupStale() || s.BackupCount != 3 {
		t.Fatalf("after backup: %+v", s)
	}
	v.Save(Item{Type: TypePassword, Name: "later", Password: "x-123"})
	if s, _ := v.Settings(); !s.BackupStale() {
		t.Fatal("change after backup should make it stale")
	}

	// Restore on "another PC": fresh vault file, different master password.
	b, err := ReadBackup(file, []byte(backupPw))
	if err != nil {
		t.Fatal(err)
	}
	v2, err := Open(filepath.Join(t.TempDir(), "new.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	if err := v2.CreateFromBackup([]byte("another master pw"), b); err != nil {
		t.Fatal(err)
	}
	items, _ := v2.Items()
	got := map[string]string{}
	for _, it := range items {
		got[it.Name] = it.Secret()
	}
	if len(items) != 3 || got["wifi"] != "  wifi pw  " || got["codes"] != "CODE-1\nCODE-2" || got["Site"] != "Site-Secret-Pw" {
		t.Fatalf("restored %v", got)
	}
	if s, _ := v2.Settings(); s.BackupStale() {
		t.Fatal("a vault restored from a backup is covered by that backup")
	}
	v2.Lock()
	if err := v2.Unlock([]byte("another master pw")); err != nil {
		t.Fatal(err)
	}
	if err := v2.CreateFromBackup([]byte("x"), b); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatal("must not restore over an existing vault")
	}
}

func TestBackupFileHasNoPlaintext(t *testing.T) {
	v, _ := filled(t)
	file := filepath.Join(t.TempDir(), "b.passpw")
	if _, err := v.ExportBackup(file, []byte(backupPw)); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(file)
	for _, s := range []string{"Site-Secret-Pw", "wifi pw", "CODE-1", "example.com", "wifi", "codes", backupPw} {
		if bytes.Contains(data, []byte(s)) {
			t.Errorf("backup contains %q", s)
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(file))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %d entries", len(entries))
	}
}

func TestBackupWrongPasswordAndTamper(t *testing.T) {
	v, _ := filled(t)
	file := filepath.Join(t.TempDir(), "b.passpw")
	v.ExportBackup(file, []byte(backupPw))
	if _, err := ReadBackup(file, []byte("wrong password!!")); !errors.Is(err, ErrBackupPassword) {
		t.Fatalf("wrong pw: %v", err)
	}
	var h backupHeader
	raw, _ := os.ReadFile(file)
	json.Unmarshal(raw, &h)

	flip := h
	flip.Data = append([]byte(nil), h.Data...)
	flip.Data[len(flip.Data)/2] ^= 1
	writeJSON(t, file, flip)
	if _, err := ReadBackup(file, []byte(backupPw)); !errors.Is(err, ErrBackupPassword) {
		t.Fatalf("flipped byte: %v", err)
	}

	// Lowering the KDF cost in the header changes the AAD, so it cannot be used to speed up guessing silently.
	weaker := h
	weaker.KDF.Time++
	writeJSON(t, file, weaker)
	if _, err := ReadBackup(file, []byte(backupPw)); !errors.Is(err, ErrBackupPassword) {
		t.Fatalf("edited header: %v", err)
	}

	hostile := h
	hostile.KDF.MemoryKiB = 64 << 20
	writeJSON(t, file, hostile)
	if _, err := ReadBackup(file, []byte(backupPw)); !errors.Is(err, ErrBackupFormat) {
		t.Fatalf("hostile kdf: %v", err)
	}

	newer := h
	newer.Version = 2
	writeJSON(t, file, newer)
	if _, err := ReadBackup(file, []byte(backupPw)); !errors.Is(err, ErrBackupFormat) {
		t.Fatalf("newer version: %v", err)
	}

	os.WriteFile(file, []byte("name,url,username,password\n"), 0o600)
	if _, err := ReadBackup(file, []byte(backupPw)); !errors.Is(err, ErrBackupFormat) {
		t.Fatalf("not a backup: %v", err)
	}
}

func TestBackupFailureLeavesSettingsAlone(t *testing.T) {
	v, _ := filled(t)
	bad := filepath.Join(t.TempDir(), "missing-dir", "b.passpw")
	if _, err := v.ExportBackup(bad, []byte(backupPw)); err == nil {
		t.Fatal("writing into a missing folder should fail")
	}
	if s, _ := v.Settings(); !s.BackupStale() || s.BackupAt != 0 {
		t.Fatal("failed backup must not be recorded")
	}
	if _, err := v.ExportBackup(filepath.Join(t.TempDir(), "b.passpw"), []byte(backupPw)); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if _, err := v.ExportBackup(filepath.Join(t.TempDir(), "c.passpw"), []byte(backupPw)); !errors.Is(err, ErrLocked) {
		t.Fatal("export while locked")
	}
}

func TestReadBackupRejectsInvalidItems(t *testing.T) {
	file := filepath.Join(t.TempDir(), "b.passpw")
	p := backupPayload{Items: []Item{{ID: "a", Type: TypeLogin, Name: "x", URL: "http://insecure", Alias: "a", Account: "b", Password: "p"}}}
	if err := writeBackup(file, []byte(backupPw), p); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBackup(file, []byte(backupPw)); !errors.Is(err, ErrBackupFormat) {
		t.Fatalf("invalid item accepted: %v", err)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "Site-Secret") {
		t.Fatal("sanity")
	}
}
