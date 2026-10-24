package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	xwin "golang.org/x/sys/windows"
)

// Keyward was called PASS_PW and kept its vault in %LOCALAPPDATA%\PASS_PW. The first start of
// Keyward copies that vault to the new folder. The old folder is left as it was (with a note), so
// nothing is lost if the copy goes wrong; the person can delete it later.

const legacyNote = "已搬到 Keyward.txt"

// migrateLegacy copies vault.db (and its SQLite journal files) from oldDir to newDir when newDir has
// no vault yet. It reports whether a copy was made.
func migrateLegacy(oldDir, newDir string) (bool, error) {
	if _, err := os.Stat(filepath.Join(newDir, "vault.db")); err == nil {
		return false, nil
	}
	if _, err := os.Stat(filepath.Join(oldDir, "vault.db")); err != nil {
		return false, nil
	}
	if err := os.MkdirAll(newDir, 0o700); err != nil {
		return false, err
	}
	// Journal files first, the database last: a half-done copy leaves no vault.db, so the next
	// start simply tries again.
	for _, name := range []string{"vault.db-wal", "vault.db-shm", "vault.db"} {
		src := filepath.Join(oldDir, name)
		if _, err := os.Stat(src); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := copyFile(src, filepath.Join(newDir, name)); err != nil {
			return false, err
		}
	}
	note := "這個資料夾是舊名稱 PASS_PW 的密碼庫。\r\n" +
		"Keyward 已把密碼庫複製到：" + newDir + "\r\n" +
		"確認 Keyward 一切正常後，可以刪除這個資料夾。\r\n"
	os.WriteFile(filepath.Join(oldDir, legacyNote), []byte(note), 0o600)
	return true, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".copying"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// legacyAppRunning reports whether the old passpw.exe is open; copying its vault then could miss
// changes it has not written yet.
func legacyAppRunning() bool {
	snap, err := xwin.CreateToolhelp32Snapshot(xwin.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer xwin.CloseHandle(snap)
	var e xwin.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = xwin.Process32First(snap, &e); err == nil; err = xwin.Process32Next(snap, &e) {
		if strings.EqualFold(xwin.UTF16ToString(e.ExeFile[:]), "passpw.exe") {
			return true
		}
	}
	return false
}
