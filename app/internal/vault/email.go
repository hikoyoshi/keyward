package vault

import (
	"database/sql"
	"errors"
)

// Email mode keeps a second copy of the data key, protected by the OS for the current Windows user,
// so a verified email code can unlock without the master password. The email settings (SMTP and
// recipient) are protected the same way, so codes can be sent while the vault is locked.
// Both are outside the encrypted settings on purpose and are never copied into backups.

// Protector wraps OS-level protection such as Windows DPAPI. Entropy binds a blob to one use.
type Protector interface {
	Protect(plain, entropy []byte) ([]byte, error)
	Unprotect(blob, entropy []byte) ([]byte, error)
}

var ErrEmailOff = errors.New("vault: email unlock is not enabled")

func emailDEKEntropy(vaultID string) []byte    { return []byte("passpw/email-dek/v1|" + vaultID) }
func emailConfigEntropy(vaultID string) []byte { return []byte("passpw/email-config/v1|" + vaultID) }

// EmailEnabled works while locked.
func (v *Vault) EmailEnabled() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.id == "" {
		return false
	}
	_, ok, err := v.st.meta("email_dek")
	return ok && err == nil
}

// SetEmail stores the OS-protected data key and email settings in one transaction. Needs the vault unlocked.
func (v *Vault) SetEmail(p Protector, config []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return ErrLocked
	}
	wrapped, err := p.Protect(v.dek, emailDEKEntropy(v.id))
	if err != nil {
		return err
	}
	cfg, err := p.Protect(config, emailConfigEntropy(v.id))
	if err != nil {
		return err
	}
	return v.st.tx(func(tx *sql.Tx) error {
		return errors.Join(setMeta(tx, "email_dek", wrapped), setMeta(tx, "email_config", cfg))
	})
}

// ClearEmail removes the email unlock path; core decides who may call it.
func (v *Vault) ClearEmail() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.st.tx(func(tx *sql.Tx) error {
		return errors.Join(deleteMeta(tx, "email_dek"), deleteMeta(tx, "email_config"))
	})
}

// EmailConfig returns the stored email settings; works while locked.
func (v *Vault) EmailConfig(p Protector) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	raw, ok, err := v.st.meta("email_config")
	if err != nil {
		return nil, err
	}
	if !ok || v.id == "" {
		return nil, ErrEmailOff
	}
	return p.Unprotect(raw, emailConfigEntropy(v.id))
}

// UnlockWithEmail opens the vault from the OS-protected data key. The caller must have checked an email code first.
func (v *Vault) UnlockWithEmail(p Protector) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.id == "" {
		return ErrNotInitialized
	}
	raw, ok, err := v.st.meta("email_dek")
	if err != nil {
		return err
	}
	if !ok {
		return ErrEmailOff
	}
	dek, err := p.Unprotect(raw, emailDEKEntropy(v.id))
	if err != nil {
		return err
	}
	if len(dek) != keyLen {
		wipe(dek)
		return ErrCorrupt
	}
	if _, ok, err := v.st.meta("settings"); err != nil || !ok {
		wipe(dek)
		return ErrCorrupt // settings decrypting is what proves the key is right
	}
	items, settings, err := v.load(dek)
	if err != nil {
		wipe(dek)
		return err
	}
	v.dek, v.items, v.settings = dek, items, settings
	return nil
}

// SetMaster re-wraps the data key under a new master password without the old one.
// Only for resetting a forgotten master password after the vault was unlocked another way.
func (v *Vault) SetMaster(newPw []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return ErrLocked
	}
	wrapped, kdf, salt, err := wrapDEK(newPw, v.dek, v.id, DefaultKDF)
	if err != nil {
		return err
	}
	return v.st.tx(func(tx *sql.Tx) error {
		return errors.Join(setMeta(tx, "kdf", kdf), setMeta(tx, "salt", salt), setMeta(tx, "wrapped_dek", wrapped))
	})
}
