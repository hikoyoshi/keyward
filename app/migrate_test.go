package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hikoyoshi/keyward/internal/vault"
)

func TestMigrateLegacyVault(t *testing.T) {
	root := t.TempDir()
	oldDir, newDir := filepath.Join(root, "PASS_PW"), filepath.Join(root, "Keyward")
	if err := os.MkdirAll(oldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(filepath.Join(oldDir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Create([]byte("Correct-horse!1")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Save(vault.Item{Type: vault.TypePassword, Name: "Wi-Fi", Password: "wifi-secret"}); err != nil {
		t.Fatal(err)
	}
	v.Close()

	if moved, err := migrateLegacy(oldDir, newDir); err != nil || !moved {
		t.Fatalf("migrate: %v %v", moved, err)
	}
	// The copy opens with the same master password and holds the same items.
	nv, err := vault.Open(filepath.Join(newDir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := nv.Unlock([]byte("Correct-horse!1")); err != nil {
		t.Fatal(err)
	}
	items, err := nv.Items()
	if err != nil || len(items) != 1 || items[0].Password != "wifi-secret" {
		t.Fatalf("items after migrate: %+v %v", items, err)
	}
	if _, err := nv.Save(vault.Item{Type: vault.TypePassword, Name: "New", Password: "x"}); err != nil {
		t.Fatal(err)
	}
	nv.Close()

	// The old vault and a note stay behind; a second start never copies over the new vault.
	if _, err := os.Stat(filepath.Join(oldDir, "vault.db")); err != nil {
		t.Fatal("old vault removed")
	}
	if _, err := os.Stat(filepath.Join(oldDir, legacyNote)); err != nil {
		t.Fatal("no note in the old folder")
	}
	if moved, err := migrateLegacy(oldDir, newDir); err != nil || moved {
		t.Fatalf("second start copied again: %v %v", moved, err)
	}
	nv, _ = vault.Open(filepath.Join(newDir, "vault.db"))
	defer nv.Close()
	nv.Unlock([]byte("Correct-horse!1"))
	if items, _ := nv.Items(); len(items) != 2 {
		t.Fatalf("new vault overwritten: %d items", len(items))
	}
}

func TestMigrateNothingToDo(t *testing.T) {
	root := t.TempDir()
	if moved, err := migrateLegacy(filepath.Join(root, "none"), filepath.Join(root, "Keyward")); err != nil || moved {
		t.Fatalf("%v %v", moved, err)
	}
	if _, err := os.Stat(filepath.Join(root, "Keyward")); err == nil {
		t.Fatal("created a folder for nothing")
	}
}
