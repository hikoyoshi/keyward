package vault

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// Backup file (.keyward; PASS_PW, the old name, wrote .passpw): a small JSON header plus one AES-256-GCM ciphertext.
// The key comes from the backup password via Argon2id, so a backup does not depend on this PC.
// Everything except the KDF header — including dates and item counts — is inside the ciphertext.

const (
	backupFormat   = "passpw-backup" // from the old name PASS_PW; keep so old backups restore
	backupVersion  = 1
	maxBackupBytes = 64 << 20
)

var (
	ErrBackupPassword = errors.New("vault: wrong backup password or damaged backup")
	ErrBackupFormat   = errors.New("vault: not a Keyward backup, or made by a newer version")
)

type backupHeader struct {
	Format  string    `json:"format"`
	Version int       `json:"version"`
	KDF     KDFParams `json:"kdf"`
	Salt    []byte    `json:"salt"`
	Data    []byte    `json:"data"`
}

type backupPayload struct {
	SourceVault string   `json:"sourceVault"`
	Created     int64    `json:"created"`
	Items       []Item   `json:"items"`
	Settings    Settings `json:"settings"`
}

// BackupInfo is what the person sees before choosing to restore.
type BackupInfo struct {
	Created   int64 `json:"created"`
	Count     int   `json:"count"`
	Logins    int   `json:"logins"`
	Passwords int   `json:"passwords"`
	Notes     int   `json:"notes"`
}

// Backup is a decrypted backup held in memory between preview and restore.
type Backup struct {
	Info    BackupInfo
	payload backupPayload
}

// Wipe drops the decrypted items so they can be garbage collected sooner.
func (b *Backup) Wipe() { b.payload = backupPayload{} }

func backupAAD(h backupHeader) []byte {
	kdf, _ := json.Marshal(h.KDF)
	return []byte("passpw/backup/v1|" + string(kdf) + "|" + hex.EncodeToString(h.Salt))
}

func infoOf(p backupPayload) BackupInfo {
	info := BackupInfo{Created: p.Created, Count: len(p.Items)}
	for _, it := range p.Items {
		switch it.Type {
		case TypeLogin:
			info.Logins++
		case TypePassword:
			info.Passwords++
		case TypeNote:
			info.Notes++
		}
	}
	return info
}

// ExportBackup writes an encrypted snapshot to path, reads it back to prove it opens,
// and only then records the backup in settings.
func (v *Vault) ExportBackup(path string, password []byte) (BackupInfo, error) {
	v.mu.Lock()
	if v.dek == nil {
		v.mu.Unlock()
		return BackupInfo{}, ErrLocked
	}
	p := backupPayload{SourceVault: v.id, Created: v.now().Unix(), Settings: v.settings}
	for _, it := range v.items {
		p.Items = append(p.Items, *it)
	}
	changes := v.settings.Changes
	v.mu.Unlock()
	sort.Slice(p.Items, func(i, j int) bool { return p.Items[i].ID < p.Items[j].ID })
	p.Settings.BackupChanges, p.Settings.BackupAt, p.Settings.BackupCount = 0, 0, 0

	if err := writeBackup(path, password, p); err != nil {
		return BackupInfo{}, err
	}
	check, err := ReadBackup(path, password)
	if err != nil {
		os.Remove(path)
		return BackupInfo{}, err
	}
	defer check.Wipe()
	if check.Info.Count != len(p.Items) {
		os.Remove(path)
		return BackupInfo{}, ErrBackupPassword
	}
	err = v.UpdateSettings(func(s *Settings) {
		s.BackupChanges, s.BackupAt, s.BackupCount = changes, p.Created, len(p.Items)
	})
	return check.Info, err
}

// writeBackup never leaves plaintext on disk: it encrypts in memory, writes a temp file and renames it.
func writeBackup(path string, password []byte, p backupPayload) error {
	plain, err := json.Marshal(p)
	if err != nil {
		return err
	}
	defer wipe(plain)
	h := backupHeader{Format: backupFormat, Version: backupVersion, KDF: DefaultKDF, Salt: randomBytes(saltLen)}
	key := deriveKey(password, h.Salt, h.KDF)
	defer wipe(key)
	if h.Data, err = seal(key, plain, backupAAD(h)); err != nil {
		return err
	}
	out, err := json.Marshal(h)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".keyward-backup-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ReadBackup decrypts a backup file without touching any vault.
func ReadBackup(path string, password []byte) (*Backup, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxBackupBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBackupBytes {
		return nil, ErrBackupFormat
	}
	var h backupHeader
	if err := json.Unmarshal(raw, &h); err != nil || h.Format != backupFormat || h.Version != backupVersion || len(h.Salt) != saltLen {
		return nil, ErrBackupFormat
	}
	if err := h.KDF.validate(); err != nil {
		return nil, ErrBackupFormat
	}
	key := deriveKey(password, h.Salt, h.KDF)
	defer wipe(key)
	plain, err := open(key, h.Data, backupAAD(h))
	if err != nil {
		return nil, ErrBackupPassword
	}
	defer wipe(plain)
	var p backupPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, ErrBackupFormat
	}
	for i := range p.Items {
		if p.Items[i].ID == "" || normalize(&p.Items[i]) != nil {
			return nil, ErrBackupFormat
		}
	}
	return &Backup{Info: infoOf(p), payload: p}, nil
}

// CreateFromBackup initializes this (empty) vault with a backup's items under a new master password.
// The restored vault counts as backed up by that file.
func (v *Vault) CreateFromBackup(master []byte, b *Backup) error {
	s := b.payload.Settings
	if s.IdleMinutes == 0 {
		s.IdleMinutes = 5
	}
	s.Changes, s.BackupChanges, s.BackupAt, s.BackupCount = 0, 0, b.payload.Created, len(b.payload.Items)
	s.AIClients = nil // a restored vault starts with no paired AI tools
	return v.create(master, b.payload.Items, s)
}
