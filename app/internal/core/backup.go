package core

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/hikoyoshi/keyward/internal/vault"
)

const (
	restoreLifetime = 10 * time.Minute // a decrypted backup waits this long for the person to confirm
)

type BackupStatus struct {
	At    int64 `json:"at"`
	Count int   `json:"count"`
	Stale bool  `json:"stale"`
}

func (s *Service) backupStatus() BackupStatus {
	st, err := s.v.Settings()
	if err != nil {
		return BackupStatus{}
	}
	return BackupStatus{At: st.BackupAt, Count: st.BackupCount, Stale: st.BackupStale()}
}

// PrepareExport checks the backup password and always re-verifies: the master password, or with an
// empty master a grant from an email code for OpExport. Runs before the UI asks where to save.
func (s *Service) PrepareExport(master, backupPw, confirm string) error {
	if err := passwordRule(backupPw, "備份密碼"); err != nil {
		return err
	}
	if backupPw != confirm {
		return uerr(CodeInvalid, "兩次輸入的備份密碼不一致。")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v.Locked() {
		return uerr(CodeLocked, "密碼庫已鎖定。")
	}
	if master == "" {
		if !s.hasGrant(OpExport, true) {
			return needGrant()
		}
	} else if err := s.verifyMaster(master, false); err != nil {
		return err
	}
	s.freshUntil = s.now().Add(FreshWindow)
	s.lastActive = s.now()
	return nil
}

// ExportBackup writes and verifies the file. It needs a verification from PrepareExport within the last minute.
func (s *Service) ExportBackup(path, backupPw string) (vault.BackupInfo, error) {
	s.mu.Lock()
	if s.v.Locked() {
		s.mu.Unlock()
		return vault.BackupInfo{}, uerr(CodeLocked, "密碼庫已鎖定。")
	}
	if !s.now().Before(s.freshUntil) {
		s.mu.Unlock()
		return vault.BackupInfo{}, uerr(CodeNeedAuth, "驗證已逾時，請重新匯出。")
	}
	v := s.v
	s.mu.Unlock()
	info, err := v.ExportBackup(path, []byte(backupPw))
	if err != nil {
		return info, uerr(CodeInternal, "備份失敗，沒有留下檔案："+err.Error())
	}
	return info, nil
}

// PreviewRestore decrypts a backup so the person can check it before restoring. Works while locked:
// restoring is how someone who forgot the master password gets back in.
func (s *Service) PreviewRestore(path, backupPw string) (vault.BackupInfo, error) {
	b, err := vault.ReadBackup(path, []byte(backupPw))
	switch {
	case errors.Is(err, vault.ErrBackupPassword):
		return vault.BackupInfo{}, uerr(CodeWrong, "備份密碼不正確，或檔案已損毀。目前的密碼庫沒有任何變更。")
	case errors.Is(err, vault.ErrBackupFormat):
		return vault.BackupInfo{}, uerr(CodeInvalid, "這不是 Keyward 備份檔，或是由較新版本建立。")
	case err != nil:
		return vault.BackupInfo{}, uerr(CodeInvalid, "無法讀取備份檔。")
	}
	s.mu.Lock()
	s.dropRestore()
	s.restore, s.restoreAt = b, s.now()
	s.mu.Unlock()
	return b.Info, nil
}

type RestoreResult struct {
	KeptAs string `json:"keptAs"` // where the previous vault file was moved, if there was one
	Count  int    `json:"count"`
}

// Restore builds a new vault from the previewed backup. An existing vault file is renamed, never overwritten.
func (s *Service) Restore(master, confirm string) (RestoreResult, error) {
	if err := checkNewMaster(master, confirm); err != nil {
		return RestoreResult{}, err
	}
	s.mu.Lock()
	b := s.restore
	if b == nil || s.now().Sub(s.restoreAt) > restoreLifetime {
		s.dropRestore()
		s.mu.Unlock()
		return RestoreResult{}, uerr(CodeInvalid, "請重新選擇備份檔並輸入備份密碼。")
	}
	res := RestoreResult{Count: b.Info.Count}
	wasInitialized := s.v.Initialized()
	if wasInitialized {
		if s.opt.VaultPath == "" {
			s.mu.Unlock()
			return RestoreResult{}, uerr(CodeInternal, "找不到密碼庫檔案位置。")
		}
		s.lockLocked()
		closeTabs(s.aiOnLock(ReasonRestore))
		s.ai.clients = nil // the new vault has no paired AI tools
		s.v.Close()
		res.KeptAs = keepAside(s.opt.VaultPath, s.now())
		if err := os.Rename(s.opt.VaultPath, res.KeptAs); err != nil {
			s.reopen()
			s.mu.Unlock()
			return RestoreResult{}, uerr(CodeInternal, "無法保留目前的密碼庫檔案，沒有進行還原："+err.Error())
		}
		os.Rename(s.opt.VaultPath+"-journal", res.KeptAs+"-journal")
		if err := s.reopen(); err != nil {
			os.Rename(res.KeptAs, s.opt.VaultPath)
			s.reopen()
			s.mu.Unlock()
			return RestoreResult{}, uerr(CodeInternal, "無法建立新的密碼庫："+err.Error())
		}
	}
	if err := s.v.CreateFromBackup([]byte(master), b); err != nil {
		if wasInitialized { // put the old vault back
			s.v.Close()
			os.Remove(s.opt.VaultPath)
			os.Rename(res.KeptAs, s.opt.VaultPath)
			s.reopen()
		}
		s.mu.Unlock()
		return RestoreResult{}, internal(err)
	}
	s.dropRestore()
	s.dropEmailState() // the new vault starts without email codes
	s.afterUnlock()
	s.mu.Unlock()
	return res, nil
}

func keepAside(path string, now time.Time) string {
	dir, base := filepath.Dir(path), filepath.Base(path)
	ext := filepath.Ext(base)
	return filepath.Join(dir, base[:len(base)-len(ext)]+"-before-restore-"+now.Format("20060102-150405")+ext)
}

// reopen opens the vault file again after it was closed or moved. Caller holds s.mu.
func (s *Service) reopen() error {
	v, err := vault.Open(s.opt.VaultPath)
	if err != nil {
		return err
	}
	s.v = v
	return nil
}

func (s *Service) dropRestore() {
	if s.restore != nil {
		s.restore.Wipe()
	}
	s.restore = nil
}

// CancelRestore forgets a previewed backup.
func (s *Service) CancelRestore() {
	s.mu.Lock()
	s.dropRestore()
	s.mu.Unlock()
}

// ---------- CSV import ----------

type csvImport struct {
	path     string
	items    []vault.Item
	imported bool
}

func (s *Service) PreviewCSV(path string) (CSVPreview, error) {
	existing, err := s.cur().Items()
	if err != nil {
		return CSVPreview{}, mapErr(err)
	}
	prev, items, err := parseCSV(path, existing)
	if err != nil {
		return CSVPreview{}, err
	}
	prev.File = filepath.Base(path)
	s.mu.Lock()
	s.csv = &csvImport{path: path, items: items}
	s.lastActive = s.now()
	s.mu.Unlock()
	return prev, nil
}

type ImportResult struct {
	Added  int `json:"added"`
	Failed int `json:"failed"`
}

func (s *Service) ImportCSV() (ImportResult, error) {
	s.mu.Lock()
	c := s.csv
	s.mu.Unlock()
	if c == nil || c.imported {
		return ImportResult{}, uerr(CodeInvalid, "請重新選擇要匯入的 CSV 檔。")
	}
	var res ImportResult
	for _, it := range c.items {
		if _, err := s.cur().Save(it); err != nil {
			if errors.Is(err, vault.ErrLocked) {
				return res, uerr(CodeLocked, "密碼庫已鎖定，匯入中斷。")
			}
			res.Failed++
			continue
		}
		res.Added++
	}
	s.mu.Lock()
	for i := range c.items {
		c.items[i] = vault.Item{}
	}
	c.items, c.imported = nil, true
	s.lastActive = s.now()
	s.mu.Unlock()
	return res, nil
}

// DeleteImportedCSV removes the plaintext CSV after a successful import, only when the person asks.
// This is an ordinary delete; the disk may still hold the old data.
func (s *Service) DeleteImportedCSV() error {
	s.mu.Lock()
	c := s.csv
	s.mu.Unlock()
	if c == nil || !c.imported {
		return uerr(CodeInvalid, "沒有剛匯入的 CSV 檔。")
	}
	if err := os.Remove(c.path); err != nil && !os.IsNotExist(err) {
		return uerr(CodeInternal, "無法刪除檔案："+err.Error())
	}
	s.mu.Lock()
	s.csv = nil
	s.mu.Unlock()
	return nil
}
