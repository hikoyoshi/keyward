package vault

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"errors"
	"testing"
)

// fakeProtector stands in for DPAPI: it checks the entropy and the blob's integrity, nothing more.
type fakeProtector struct{ broken bool }

func (f fakeProtector) Protect(plain, entropy []byte) ([]byte, error) {
	sum := sha256.Sum256(append(append([]byte{}, entropy...), plain...))
	return append(sum[:], plain...), nil
}

func (f fakeProtector) Unprotect(blob, entropy []byte) ([]byte, error) {
	if f.broken || len(blob) < 32 {
		return nil, errors.New("fake dpapi: cannot unprotect")
	}
	plain := blob[32:]
	sum := sha256.Sum256(append(append([]byte{}, entropy...), plain...))
	if !bytes.Equal(sum[:], blob[:32]) {
		return nil, errors.New("fake dpapi: bad blob")
	}
	return append([]byte{}, plain...), nil
}

func TestEmailUnlockAndReset(t *testing.T) {
	v, path := newVault(t)
	if _, err := v.Save(login("Mail", "pw-1")); err != nil {
		t.Fatal(err)
	}
	if v.EmailEnabled() {
		t.Fatal("email enabled on a new vault")
	}
	if err := v.SetEmail(fakeProtector{}, []byte(`{"to":"a@example.com"}`)); err != nil {
		t.Fatal(err)
	}
	v = reopen(t, v, path) // locked again
	if !v.EmailEnabled() {
		t.Fatal("email setting lost")
	}
	if cfg, err := v.EmailConfig(fakeProtector{}); err != nil || string(cfg) != `{"to":"a@example.com"}` {
		t.Fatalf("config while locked: %v %s", err, cfg)
	}
	if err := v.UnlockWithEmail(fakeProtector{broken: true}); err == nil || !v.Locked() {
		t.Fatal("unlocked although DPAPI failed")
	}
	if err := v.UnlockWithEmail(fakeProtector{}); err != nil {
		t.Fatal(err)
	}
	if items, _ := v.Items(); len(items) != 1 || items[0].Password != "pw-1" {
		t.Fatalf("items after email unlock: %+v", items)
	}
	if err := v.SetMaster([]byte("brand new master pw")); err != nil {
		t.Fatal(err)
	}
	v = reopen(t, v, path)
	if err := v.Unlock([]byte(master)); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("old master still works: %v", err)
	}
	if err := v.Unlock([]byte("brand new master pw")); err != nil {
		t.Fatal(err)
	}
	if err := v.ClearEmail(); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if v.EmailEnabled() {
		t.Fatal("still enabled after clear")
	}
	if err := v.UnlockWithEmail(fakeProtector{}); !errors.Is(err, ErrEmailOff) {
		t.Fatalf("email unlock after clear: %v", err)
	}
}

// A blob from another vault (different ID in the entropy) must not open this one.
func TestEmailBlobBoundToVault(t *testing.T) {
	a, _ := newVault(t)
	b, _ := newVault(t)
	if err := a.SetEmail(fakeProtector{}, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	raw, _, _ := a.st.meta("email_dek")
	cfg, _, _ := a.st.meta("email_config")
	if err := b.st.tx(func(tx *sql.Tx) error {
		return errors.Join(setMeta(tx, "email_dek", raw), setMeta(tx, "email_config", cfg))
	}); err != nil {
		t.Fatal(err)
	}
	b.Lock()
	if err := b.UnlockWithEmail(fakeProtector{}); err == nil {
		t.Fatal("foreign email blob unlocked the vault")
	}
}

func TestSetEmailNeedsUnlock(t *testing.T) {
	v, _ := newVault(t)
	v.Lock()
	if err := v.SetEmail(fakeProtector{}, []byte("{}")); !errors.Is(err, ErrLocked) {
		t.Fatalf("got %v", err)
	}
	if err := v.SetMaster([]byte("whatever master")); !errors.Is(err, ErrLocked) {
		t.Fatalf("got %v", err)
	}
}
