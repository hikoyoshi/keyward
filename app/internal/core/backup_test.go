package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hikoyoshi/keyward/internal/vault"
)

const bpw = "Backup-pass!99"

func export(t *testing.T, e *env) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "b.passpw")
	if err := e.s.PrepareExport(master, bpw, bpw); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.ExportBackup(file, bpw); err != nil {
		t.Fatal(err)
	}
	return file
}

func restoreCode(_ RestoreResult, err error) string { return code(err) }

func TestExportRules(t *testing.T) {
	e := setup(t)
	addWifi(t, e)
	if !e.s.Status().Backup.Stale {
		t.Fatal("no backup yet should be stale")
	}
	if code(e.s.PrepareExport(master, "short", "short")) != CodeInvalid {
		t.Fatal("short backup password")
	}
	if code(e.s.PrepareExport(master, bpw, bpw+"x")) != CodeInvalid {
		t.Fatal("mismatch")
	}
	if code(e.s.PrepareExport("wrong master pw", bpw, bpw)) != CodeWrong {
		t.Fatal("master must be verified even inside the fresh window")
	}
	e.advance(61 * time.Second)
	if _, err := e.s.ExportBackup(filepath.Join(t.TempDir(), "x.passpw"), bpw); code(err) != CodeNeedAuth {
		t.Fatalf("export without recent verification: %v", err)
	}
	export(t, e)
	st := e.s.Status().Backup
	if st.Stale || st.Count != 1 || st.At == 0 {
		t.Fatalf("after export: %+v", st)
	}
	addWifi(t, e)
	if !e.s.Status().Backup.Stale {
		t.Fatal("stale after change")
	}
}

func TestRestoreFromLockScreenKeepsOldVault(t *testing.T) {
	e := setup(t)
	d := addWifi(t, e)
	file := export(t, e)
	e.s.Save(Input{Type: vault.TypeNote, Name: "only in old vault", Note: "x"})
	e.s.Lock(ReasonManual)

	if _, err := e.s.PreviewRestore(file, "wrong backup pw"); code(err) != CodeWrong {
		t.Fatalf("wrong backup pw: %v", err)
	}
	info, err := e.s.PreviewRestore(file, bpw)
	if err != nil || info.Count != 1 || info.Passwords != 1 {
		t.Fatalf("preview: %+v %v", info, err)
	}
	if restoreCode(e.s.Restore("short", "short")) != CodeInvalid {
		t.Fatal("short new master")
	}
	res, err := e.s.Restore("Brand-new!master", "Brand-new!master")
	if err != nil {
		t.Fatal(err)
	}
	if res.KeptAs == "" || res.Count != 1 {
		t.Fatalf("result %+v", res)
	}
	if _, err := os.Stat(res.KeptAs); err != nil {
		t.Fatal("old vault file must be kept")
	}
	st := e.s.Status()
	if st.Locked || st.Backup.Stale {
		t.Fatalf("restored vault should be unlocked and counted as backed up: %+v", st)
	}
	if got, _ := e.s.Reveal(d.ID, ""); got != "wifi-secret-123" {
		t.Fatalf("restored secret %q", got)
	}
	if list, _ := e.s.List("", ""); len(list) != 1 {
		t.Fatalf("restored vault has %d items, want only the backup's 1", len(list))
	}
	// The kept file still opens with the old master password and holds the newer item.
	old, err := vault.Open(res.KeptAs)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if err := old.Unlock([]byte(master)); err != nil {
		t.Fatal(err)
	}
	if items, _ := old.Items(); len(items) != 2 {
		t.Fatalf("kept vault items %d", len(items))
	}
	e.s.Lock(ReasonManual)
	if err := e.s.Unlock("Brand-new!master"); err != nil {
		t.Fatal(err)
	}
	if restoreCode(e.s.Restore("Brand-new!master", "Brand-new!master")) != CodeInvalid {
		t.Fatal("a previewed backup must be single-use")
	}
}

func TestRestoreOnNewPC(t *testing.T) {
	src := setup(t)
	addWifi(t, src)
	file := export(t, src)

	path := filepath.Join(t.TempDir(), "new.db")
	v, _ := vault.Open(path)
	s := New(v, Options{VaultPath: path, Clipboard: &fakeClip{}})
	defer func() { s.cur().Close() }()
	if _, err := s.PreviewRestore(file, bpw); err != nil {
		t.Fatal(err)
	}
	res, err := s.Restore("New-PC!master", "New-PC!master")
	if err != nil || res.KeptAs != "" {
		t.Fatalf("restore on empty vault: %+v %v", res, err)
	}
	if st := s.Status(); !st.Initialized || st.Locked {
		t.Fatalf("status %+v", st)
	}
}

func TestRestorePreviewExpires(t *testing.T) {
	e := setup(t)
	file := export(t, e)
	e.s.PreviewRestore(file, bpw)
	e.advance(restoreLifetime + 2*time.Second)
	if restoreCode(e.s.Restore("Brand-new!master", "Brand-new!master")) != CodeInvalid {
		t.Fatal("stale preview used")
	}
}

func writeCSV(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "passwords.csv")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCSVImport(t *testing.T) {
	e := setup(t)
	e.s.Save(Input{Type: vault.TypeLogin, Name: "Work", URL: "https://work.example.com/login", Alias: "job", Account: "Me@x.com", Password: "pw-1234567"})
	csvFile := writeCSV(t, "\xef\xbb\xbfname,url,username,password,note\n"+
		"Shop,https://shop.example.com/login,buyer@x.com,shop-pw-1,\n"+
		"Work again,https://WORK.example.com/,me@x.com,other,\n"+ // duplicate of an existing item
		"Router,http://192.168.1.1/,admin,router-pw,\n"+ // not HTTPS: kept as other password
		",android://abc@com.app/,user1,app-pw,\n"+
		"Empty,https://empty.example.com,someone,,\n"+ // no password: skipped
		"Shop,https://shop.example.com/login,buyer@x.com,shop-pw-1,\n") // duplicate inside the file
	prev, err := e.s.PreviewCSV(csvFile)
	if err != nil {
		t.Fatal(err)
	}
	if prev.New != 3 || prev.AsPassword != 2 || prev.Duplicate != 2 || prev.Skipped != 1 || prev.File != "passwords.csv" {
		t.Fatalf("preview %+v", prev)
	}
	for _, r := range prev.Rows {
		if strings.Contains(r.Name+r.Host+r.Account, "pw") {
			t.Fatalf("preview leaks a password: %+v", r)
		}
	}
	res, err := e.s.ImportCSV()
	if err != nil || res.Added != 3 || res.Failed != 0 {
		t.Fatalf("import %+v %v", res, err)
	}
	if _, err := e.s.ImportCSV(); code(err) != CodeInvalid {
		t.Fatal("double import")
	}
	logins, _ := e.s.List("", vault.TypeLogin)
	others, _ := e.s.List("", vault.TypePassword)
	if len(logins) != 2 || len(others) != 2 {
		t.Fatalf("logins %d others %d", len(logins), len(others))
	}
	for _, o := range others {
		if d, _ := e.s.Get(o.ID); !strings.Contains(d.Note, "匯入時的網址") {
			t.Fatalf("non-HTTPS import should keep its address in the note: %+v", d)
		}
	}
	if !e.s.Status().Backup.Stale {
		t.Fatal("import should make the backup stale")
	}
	if err := e.s.DeleteImportedCSV(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(csvFile); !os.IsNotExist(err) {
		t.Fatal("csv not deleted")
	}
}

func TestCSVRejectsAndLockDrops(t *testing.T) {
	e := setup(t)
	if _, err := e.s.PreviewCSV(writeCSV(t, "a,b,c\n1,2,3\n")); code(err) != CodeInvalid {
		t.Fatal("csv without password column")
	}
	e.s.PreviewCSV(writeCSV(t, "url,username,password\nhttps://a.example,u,p1\n"))
	e.s.Lock(ReasonManual)
	e.s.Unlock(master)
	if _, err := e.s.ImportCSV(); code(err) != CodeInvalid {
		t.Fatal("parsed rows should be dropped on lock")
	}
	if code(e.s.DeleteImportedCSV()) != CodeInvalid {
		t.Fatal("delete without import")
	}
	e.s.Lock(ReasonManual)
	if _, err := e.s.PreviewCSV(writeCSV(t, "url,username,password\n")); code(err) != CodeLocked {
		t.Fatal("preview while locked")
	}
}
