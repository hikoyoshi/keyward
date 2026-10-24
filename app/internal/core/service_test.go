package core

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hikoyoshi/keyward/internal/vault"
)

func init() { vault.DefaultKDF = vault.KDFParams{Time: 1, MemoryKiB: 8 * 1024, Threads: 1} }

const master = "Correct-horse!1"

type fakeClip struct {
	text    string
	seq     uint32
	cleared int
}

func (c *fakeClip) SetSecret(t string) (uint32, error) { c.text = t; c.seq++; return c.seq, nil }
func (c *fakeClip) ClearIf(seq uint32) {
	if seq == c.seq {
		c.text = ""
		c.cleared++
	}
}
func (c *fakeClip) userCopies(t string) { c.text = t; c.seq++ }

type env struct {
	s       *Service
	clip    *fakeClip
	mail    *fakeMailer
	opt     Options
	clock   time.Time
	winLock bool
	locks   []string
}

// advance moves the fake clock with one Tick per second, like the app's ticker.
func (e *env) advance(d time.Duration) {
	for ; d > 0; d -= time.Second {
		step := min(d, time.Second)
		e.clock = e.clock.Add(step)
		e.s.Tick()
	}
}

func setup(t *testing.T) *env {
	t.Helper()
	return setupWith(t, nil)
}

// setupWith lets a test adjust the options (e.g. add a browser) before the service starts.
func setupWith(t *testing.T, adjust func(*Options)) *env {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v.db")
	v, err := vault.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{clip: &fakeClip{}, mail: &fakeMailer{}, clock: time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)}
	t.Cleanup(func() { e.s.cur().Close() })
	e.opt = Options{
		VaultPath:     path,
		Clipboard:     e.clip,
		Now:           func() time.Time { return e.clock },
		SessionLocked: func() (bool, bool) { return e.winLock, true },
		OnLock:        func(r string) { e.locks = append(e.locks, r) },
		Protector:     fakeProtector{},
		Mailer:        e.mail,
	}
	if adjust != nil {
		adjust(&e.opt)
	}
	e.s = New(v, e.opt)
	if err := e.s.Setup(master, master); err != nil {
		t.Fatal(err)
	}
	return e
}

func code(err error) string {
	var ue *UserError
	if errors.As(err, &ue) {
		return ue.Code
	}
	return ""
}

func addWifi(t *testing.T, e *env) Detail {
	d, err := e.s.Save(Input{Type: vault.TypePassword, Name: "Wi-Fi", Account: "HOME", Password: "wifi-secret-123"})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSetupRules(t *testing.T) {
	v, _ := vault.Open(filepath.Join(t.TempDir(), "v.db"))
	defer v.Close()
	s := New(v, Options{Clipboard: &fakeClip{}})
	if code(s.Setup("short", "short")) != CodeInvalid {
		t.Fatal("short master accepted")
	}
	if code(s.Setup("Long-enough!1", "Long-enough!2")) != CodeInvalid {
		t.Fatal("mismatch accepted")
	}
	if err := s.Setup("Long-enough!1", "Long-enough!1"); err != nil {
		t.Fatal(err)
	}
	if st := s.Status(); !st.Initialized || st.Locked || st.FreshSeconds != 60 {
		t.Fatalf("status after setup: %+v", st)
	}
	if code(s.Setup("Long-enough!1", "Long-enough!1")) != CodeAlreadySet {
		t.Fatal("second setup allowed")
	}
}

func TestRevealFreshWindowAndReauth(t *testing.T) {
	e := setup(t)
	d := addWifi(t, e)
	if got, err := e.s.Reveal(d.ID, ""); err != nil || got != "wifi-secret-123" {
		t.Fatalf("reveal inside fresh window: %q %v", got, err)
	}
	e.advance(61 * time.Second)
	if _, err := e.s.Reveal(d.ID, ""); code(err) != CodeNeedAuth {
		t.Fatalf("after 60s should need auth: %v", err)
	}
	if _, err := e.s.Reveal(d.ID, "wrong master pw"); code(err) != CodeWrong {
		t.Fatalf("wrong master: %v", err)
	}
	// Even the right password must wait out the delay.
	if _, err := e.s.Reveal(d.ID, master); code(err) != CodeWait {
		t.Fatalf("during wait: %v", err)
	}
	e.clock = e.clock.Add(time.Second)
	if got, err := e.s.Reveal(d.ID, master); err != nil || got != "wifi-secret-123" {
		t.Fatalf("after wait: %q %v", got, err)
	}
	// Verification opens a new 60 s window.
	if _, err := e.s.Reveal(d.ID, ""); err != nil {
		t.Fatalf("fresh window after verify: %v", err)
	}
}

func TestBackoffGrows(t *testing.T) {
	e := setup(t)
	e.s.Lock(ReasonManual)
	want := []string{"1 秒", "2 秒", "4 秒", "8 秒"}
	for _, w := range want {
		err := e.s.Unlock("nope nope nope")
		if code(err) != CodeWrong || !strings.Contains(err.Error(), w) {
			t.Fatalf("want wait %s, got %v", w, err)
		}
		e.clock = e.clock.Add(10 * time.Second)
	}
	if err := e.s.Unlock(master); err != nil {
		t.Fatal(err)
	}
	if e.s.fails != 0 {
		t.Fatal("success should reset failures")
	}
}

func TestDetailHidesSecrets(t *testing.T) {
	e := setup(t)
	d := addWifi(t, e)
	n, _ := e.s.Save(Input{Type: vault.TypeNote, Name: "codes", Note: "RECOVERY-1"})
	got, _ := e.s.Get(n.ID)
	if got.Note != "" {
		t.Fatal("note body leaked in detail")
	}
	list, _ := e.s.List("", "")
	for _, x := range list {
		if strings.Contains(x.Name+x.Account+x.Alias+x.Host, "secret") {
			t.Fatal("secret in summary")
		}
	}
	if w, _ := e.s.Get(d.ID); w.Account != "HOME" {
		t.Fatal("non-secret fields should be present")
	}
}

func TestListFilterAndSearch(t *testing.T) {
	e := setup(t)
	addWifi(t, e)
	e.s.Save(Input{Type: vault.TypeLogin, Name: "Work", URL: "https://work.example.com/login", Alias: "job", Account: "me@x.com", Password: "pw-1234567"})
	if l, _ := e.s.List("", vault.TypeLogin); len(l) != 1 || l[0].Host != "work.example.com" {
		t.Fatalf("type filter: %+v", l)
	}
	if l, _ := e.s.List("JOB", ""); len(l) != 1 {
		t.Fatalf("search by alias: %+v", l)
	}
	if l, _ := e.s.List("pw-1234567", ""); len(l) != 0 {
		t.Fatal("search must not match passwords")
	}
}

func TestCopyClearsOnlyOurClipboard(t *testing.T) {
	e := setup(t)
	d := addWifi(t, e)
	if err := e.s.Copy(d.ID, ""); err != nil || e.clip.text != "wifi-secret-123" {
		t.Fatalf("copy: %v %q", err, e.clip.text)
	}
	e.advance(29 * time.Second)
	if e.clip.text == "" {
		t.Fatal("cleared too early")
	}
	e.advance(time.Second)
	if e.clip.text != "" {
		t.Fatal("not cleared after 30s")
	}
	// If the person copied something else meanwhile, leave it alone.
	e.s.Reveal(d.ID, master)
	e.s.Copy(d.ID, "")
	e.clip.userCopies("my own text")
	e.advance(31 * time.Second)
	if e.clip.text != "my own text" {
		t.Fatal("clobbered the user's clipboard")
	}
}

func TestLockClearsClipboardAndFreshness(t *testing.T) {
	e := setup(t)
	d := addWifi(t, e)
	e.s.Copy(d.ID, "")
	e.s.Lock(ReasonManual)
	if e.clip.text != "" {
		t.Fatal("lock should clear our clipboard content")
	}
	if _, err := e.s.Reveal(d.ID, ""); code(err) != CodeLocked {
		t.Fatalf("reveal while locked: %v", err)
	}
	e.s.Unlock(master)
	if _, err := e.s.Reveal(d.ID, ""); err != nil {
		t.Fatal("unlock should open a fresh window")
	}
}

func TestIdleLock(t *testing.T) {
	e := setup(t)
	for i := 0; i < 4; i++ {
		e.advance(time.Minute)
		e.s.Touch()
	}
	if e.s.Status().Locked {
		t.Fatal("activity should postpone idle lock")
	}
	for i := 0; i < 5; i++ {
		e.advance(time.Minute)
	}
	if !e.s.Status().Locked || len(e.locks) != 1 || e.locks[0] != ReasonIdle {
		t.Fatalf("idle lock: %+v", e.locks)
	}
}

func TestIdleSettingPersists(t *testing.T) {
	e := setup(t)
	if code(e.s.SetIdleMinutes(7)) != CodeInvalid {
		t.Fatal("odd idle value accepted")
	}
	e.s.SetIdleMinutes(15)
	e.s.Lock(ReasonManual)
	e.s.Unlock(master)
	if e.s.Status().IdleMinutes != 15 {
		t.Fatal("idle minutes not restored on unlock")
	}
	for i := 0; i < 14; i++ {
		e.advance(time.Minute)
	}
	if e.s.Status().Locked {
		t.Fatal("locked before 15 minutes")
	}
}

func TestWindowsLockAndSleep(t *testing.T) {
	e := setup(t)
	e.winLock = true
	e.advance(time.Second)
	if len(e.locks) != 1 || e.locks[0] != ReasonWindows {
		t.Fatalf("windows lock: %v", e.locks)
	}
	e.winLock = false
	e.s.Unlock(master)
	e.clock = e.clock.Add(2 * time.Hour) // no ticks while asleep
	e.s.Touch()                          // even if the UI reports activity right after waking
	e.s.Tick()
	if len(e.locks) != 2 || e.locks[1] != ReasonSleep {
		t.Fatalf("sleep lock: %v", e.locks)
	}
}

func TestChangeMaster(t *testing.T) {
	e := setup(t)
	if code(e.s.ChangeMaster("bad current pw", "New-master!1", "New-master!1")) != CodeWrong {
		t.Fatal("wrong current accepted")
	}
	e.clock = e.clock.Add(5 * time.Second)
	if code(e.s.ChangeMaster(master, "short", "short")) != CodeInvalid {
		t.Fatal("short new accepted")
	}
	if err := e.s.ChangeMaster(master, "New-master!1", "New-master!1"); err != nil {
		t.Fatal(err)
	}
	e.s.Lock(ReasonManual)
	if code(e.s.Unlock(master)) != CodeWrong {
		t.Fatal("old master still works")
	}
	e.clock = e.clock.Add(5 * time.Second)
	if err := e.s.Unlock("New-master!1"); err != nil {
		t.Fatal(err)
	}
}

func TestSaveErrorsAreUserFacing(t *testing.T) {
	e := setup(t)
	_, err := e.s.Save(Input{Type: vault.TypeLogin, Name: "x", URL: "http://x.com", Alias: "a", Account: "b", Password: "p"})
	if code(err) != CodeInvalid || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("got %v", err)
	}
	e.s.Lock(ReasonManual)
	if _, err := e.s.List("", ""); code(err) != CodeLocked {
		t.Fatalf("list while locked: %v", err)
	}
}

func TestGenerate(t *testing.T) {
	a, b := Generate(20, true), Generate(20, true)
	if len(a) != 20 || a == b {
		t.Fatalf("generate: %q %q", a, b)
	}
	if strings.ContainsAny(Generate(64, false), symbols) {
		t.Fatal("symbols present when disabled")
	}
	if len(Generate(2, false)) != 8 {
		t.Fatal("minimum length not enforced")
	}
}

func TestPasswordRule(t *testing.T) {
	ok := []string{"Kq7!mZ2p", "Blue-Tiger-Rain-42!", "我的密碼本-Rx7#q2", "Correct-horse!1"}
	bad := []string{
		"Abc!123",   // 7 characters
		"abcdefg!1", // no uppercase
		"Abcdefgh1", // no symbol
		"Abcd efgh", // a space is not a symbol
		"",
		"Password1!", // common password
		"Qwerty123!", // keyboard pattern
		"Abcd1234!",  // simple sequence
		"Keyward1!",  // the app's own name
	}
	for _, p := range ok {
		if err := passwordRule(p, "主密碼"); err != nil {
			t.Errorf("%q rejected: %v", p, err)
		}
	}
	for _, p := range bad {
		if err := passwordRule(p, "主密碼"); code(err) != CodeInvalid {
			t.Errorf("%q accepted", p)
		}
	}
	e := setup(t)
	if code(e.s.PrepareExport(master, "backup-lower!", "backup-lower!")) != CodeInvalid {
		t.Fatal("backup password follows the same rule")
	}
}

func TestPasswordStrength(t *testing.T) {
	cases := []struct {
		pw    string
		level int
		rules bool
	}{
		{"", 0, false},
		{"Password1!", 1, true},
		{"short", 1, false},
		{"Kq7!mZ2p", 2, true},
		{"Blue-Tiger-Rain-42!", 4, true},
	}
	for _, c := range cases {
		if s := PasswordStrength(c.pw); s.Level != c.level || s.Rules != c.rules {
			t.Errorf("%q: %+v, want level %d rules %v", c.pw, s, c.level, c.rules)
		}
	}
}
