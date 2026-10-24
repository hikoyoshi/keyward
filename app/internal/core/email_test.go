package core

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hikoyoshi/keyward/internal/vault"
)

// fakeProtector stands in for DPAPI: it checks the entropy and the blob's integrity, nothing more.
type fakeProtector struct{}

func (fakeProtector) Protect(plain, entropy []byte) ([]byte, error) {
	sum := sha256.Sum256(append(append([]byte{}, entropy...), plain...))
	return append(sum[:], plain...), nil
}

func (fakeProtector) Unprotect(blob, entropy []byte) ([]byte, error) {
	if len(blob) < 32 {
		return nil, errors.New("fake dpapi: short blob")
	}
	plain := blob[32:]
	sum := sha256.Sum256(append(append([]byte{}, entropy...), plain...))
	if !bytes.Equal(sum[:], blob[:32]) {
		return nil, errors.New("fake dpapi: bad blob")
	}
	return append([]byte{}, plain...), nil
}

type sentMail struct {
	to  string
	cfg SMTPConfig
	m   CodeMail
}

type fakeMailer struct {
	sent []sentMail
	fail error
}

func (f *fakeMailer) Send(cfg SMTPConfig, to string, m CodeMail) error {
	if f.fail != nil {
		return f.fail
	}
	f.sent = append(f.sent, sentMail{to, cfg, m})
	return nil
}

func (f *fakeMailer) last(t *testing.T) CodeMail {
	t.Helper()
	if len(f.sent) == 0 {
		t.Fatal("no mail sent")
	}
	return f.sent[len(f.sent)-1].m
}

var testEmail = EmailInput{Host: "smtp.example.com", Port: 587, User: "sender@example.com", Password: "fake-app-password", To: "demo@example.com"}

// enableEmail runs the whole setup: re-verify, send a test code, confirm it.
func enableEmail(t *testing.T, e *env) {
	t.Helper()
	if err := e.s.Authorize(OpEmailSetup, master); err != nil {
		t.Fatal(err)
	}
	sent, err := e.s.StartEmailSetup(testEmail)
	if err != nil {
		t.Fatal(err)
	}
	if sent.Masked != "d***@example.com" {
		t.Fatalf("masked: %q", sent.Masked)
	}
	m := e.mail.last(t)
	if m.Purpose != PurposeBind || e.mail.sent[len(e.mail.sent)-1].to != "demo@example.com" {
		t.Fatalf("bind mail: %+v", e.mail.sent)
	}
	st, err := e.s.FinishEmailSetup(m.Code)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Enabled || st.Masked != "d***@example.com" {
		t.Fatalf("status: %+v", st)
	}
	e.clock = e.clock.Add(ResendGap) // keep later sends clear of the resend gap
}

// lockAndSend locks the vault and mails a code for purpose.
func lockAndSend(t *testing.T, e *env, purpose string) string {
	t.Helper()
	e.s.Lock(ReasonManual)
	if _, err := e.s.SendCode(purpose, ""); err != nil {
		t.Fatal(err)
	}
	return e.mail.last(t).Code
}

func wrongCode(right string) string {
	if right == "000000" {
		return "000001"
	}
	return "000000"
}

func TestEmailSetupNeedsFreshVerification(t *testing.T) {
	e := setup(t)
	// Just unlocked (inside the 60 s window) is not enough.
	if _, err := e.s.StartEmailSetup(testEmail); code(err) != CodeNeedAuth {
		t.Fatalf("setup without re-verify: %v", err)
	}
	if _, err := e.s.EmailSettings(); code(err) != CodeNeedAuth {
		t.Fatalf("settings without re-verify: %v", err)
	}
	if err := e.s.Authorize(OpEmailSetup, "wrong master pw"); code(err) != CodeWrong {
		t.Fatalf("wrong master: %v", err)
	}
	e.clock = e.clock.Add(time.Second)
	bad := testEmail
	bad.Port = 25
	if err := e.s.Authorize(OpEmailSetup, master); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.StartEmailSetup(bad); code(err) != CodeInvalid {
		t.Fatalf("port 25 accepted: %v", err)
	}
	bad = testEmail
	bad.To = "x@example.com\r\nBcc: evil@example.com"
	if _, err := e.s.StartEmailSetup(bad); code(err) != CodeInvalid {
		t.Fatalf("header injection accepted: %v", err)
	}
	// A grant for one action does not cover another.
	if err := e.s.DisableEmail(); code(err) != CodeNeedAuth {
		t.Fatalf("disable with setup grant: %v", err)
	}
	if _, err := e.s.StartEmailSetup(testEmail); err != nil {
		t.Fatal(err)
	}
	m := e.mail.last(t)
	if _, err := e.s.FinishEmailSetup(wrongCode(m.Code)); code(err) != CodeWrongCode {
		t.Fatalf("wrong test code: %v", err)
	}
	if e.s.Status().Email.Enabled {
		t.Fatal("enabled before the test code")
	}
	if _, err := e.s.FinishEmailSetup(m.Code); err != nil {
		t.Fatal(err)
	}
	// The grant was used up by enabling.
	if _, err := e.s.StartEmailSetup(testEmail); code(err) != CodeNeedAuth {
		t.Fatalf("grant reused: %v", err)
	}
}

func TestCodeIsSixDigitsAndOnlyHMACStored(t *testing.T) {
	e := setup(t)
	enableEmail(t, e)
	c := lockAndSend(t, e, PurposeUnlock)
	if !sixDigits.MatchString(c) {
		t.Fatalf("code %q", c)
	}
	p := e.s.otp.code
	if p == nil || len(p.mac) != 32 || bytes.Contains(p.mac, []byte(c)) {
		t.Fatalf("pending: %+v", p)
	}
	if p.expires.Sub(p.created) != CodeLifetime {
		t.Fatal("lifetime")
	}
	if err := e.s.UnlockWithCode(c, false); err != nil {
		t.Fatal(err)
	}
	if e.s.Status().Locked {
		t.Fatal("still locked")
	}
	if got, err := e.s.Reveal(addWifi(t, e).ID, ""); err != nil || got != "wifi-secret-123" {
		t.Fatalf("data after email unlock: %q %v", got, err)
	}
}

func TestCodeExpiresAfterTenMinutes(t *testing.T) {
	e := setup(t)
	enableEmail(t, e)
	c := lockAndSend(t, e, PurposeUnlock)
	e.clock = e.clock.Add(CodeLifetime - time.Second)
	if err := e.s.UnlockWithCode(wrongCode(c), false); code(err) != CodeWrongCode {
		t.Fatalf("still valid just before expiry: %v", err)
	}
	e.clock = e.clock.Add(time.Second)
	if err := e.s.UnlockWithCode(c, false); code(err) != CodeCodeGone {
		t.Fatalf("expired code: %v", err)
	}
	if !e.s.Status().Locked {
		t.Fatal("unlocked with expired code")
	}
}

// Sleeping moves the wall clock forward, so the code expires; moving the clock back voids it.
func TestCodeNotExtendedBySleepOrClockBack(t *testing.T) {
	e := setup(t)
	enableEmail(t, e)
	c := lockAndSend(t, e, PurposeUnlock)
	e.clock = e.clock.Add(2 * time.Hour) // PC slept
	e.s.Tick()
	if err := e.s.UnlockWithCode(c, false); code(err) != CodeCodeGone {
		t.Fatalf("after sleep: %v", err)
	}
	c = mustSend(t, e, PurposeUnlock, "")
	e.clock = e.clock.Add(-time.Hour)
	if err := e.s.UnlockWithCode(c, false); code(err) != CodeCodeGone {
		t.Fatalf("after clock moved back: %v", err)
	}
}

func mustSend(t *testing.T, e *env, purpose, target string) string {
	t.Helper()
	if _, err := e.s.SendCode(purpose, target); err != nil {
		t.Fatal(err)
	}
	return e.mail.last(t).Code
}

func TestFiveWrongTriesVoidTheCode(t *testing.T) {
	e := setup(t)
	enableEmail(t, e)
	c := lockAndSend(t, e, PurposeUnlock)
	for i := 1; i < CodeMaxTries; i++ {
		err := e.s.UnlockWithCode(wrongCode(c), false)
		if code(err) != CodeWrongCode || !strings.Contains(err.Error(), "還可以再試") {
			t.Fatalf("try %d: %v", i, err)
		}
	}
	if err := e.s.UnlockWithCode(wrongCode(c), false); code(err) != CodeCodeGone {
		t.Fatalf("5th wrong try: %v", err)
	}
	// The right code no longer works once voided.
	if err := e.s.UnlockWithCode(c, false); code(err) != CodeCodeGone {
		t.Fatalf("right code after void: %v", err)
	}
	if !e.s.Status().Locked {
		t.Fatal("unlocked")
	}
	// Malformed input is rejected without using up a try.
	e.clock = e.clock.Add(ResendGap)
	c = mustSend(t, e, PurposeUnlock, "")
	if err := e.s.UnlockWithCode("12a456", false); code(err) != CodeInvalid {
		t.Fatalf("malformed: %v", err)
	}
	if e.s.otp.code.tries != 0 {
		t.Fatal("malformed input counted")
	}
}

func TestResendVoidsOldCodeAndRateLimits(t *testing.T) {
	e := setup(t)
	enableEmail(t, e)
	first := lockAndSend(t, e, PurposeUnlock)
	if _, err := e.s.SendCode(PurposeUnlock, ""); code(err) != CodeRateLimited {
		t.Fatalf("resend inside 60 s: %v", err)
	}
	e.clock = e.clock.Add(ResendGap - time.Second)
	if _, err := e.s.SendCode(PurposeUnlock, ""); code(err) != CodeRateLimited {
		t.Fatalf("resend at 59 s: %v", err)
	}
	e.clock = e.clock.Add(time.Second)
	second := mustSend(t, e, PurposeUnlock, "")
	if first != second {
		if err := e.s.UnlockWithCode(first, false); code(err) != CodeWrongCode {
			t.Fatalf("old code after resend: %v", err)
		}
	}
	if err := e.s.UnlockWithCode(second, false); err != nil {
		t.Fatalf("new code: %v", err)
	}
}

// Found in the browser walkthrough: enabling Email and locking right away refused the unlock code for a minute.
func TestNewRequestRightAfterUsedCode(t *testing.T) {
	e := setup(t)
	if err := e.s.Authorize(OpEmailSetup, master); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.StartEmailSetup(testEmail); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.FinishEmailSetup(e.mail.last(t).Code); err != nil {
		t.Fatal(err)
	}
	e.s.Lock(ReasonManual)
	c := mustSend(t, e, PurposeUnlock, "") // no clock change since the bind code
	// While that code is outstanding, asking again is a resend and must wait.
	if _, err := e.s.SendCode(PurposeUnlock, ""); code(err) != CodeRateLimited {
		t.Fatalf("resend of an outstanding code: %v", err)
	}
	// After a code is voided by wrong tries, the gap still applies.
	for i := 0; i < CodeMaxTries; i++ {
		e.s.UnlockWithCode("000000", false)
	}
	if _, err := e.s.SendCode(PurposeUnlock, ""); code(err) != CodeRateLimited {
		t.Fatalf("new code right after a voided one: %v", err)
	}
	_ = c
}

func TestFiveMailsPerHour(t *testing.T) {
	e := setup(t)
	enableEmail(t, e) // the bind code counts too
	e.s.Lock(ReasonManual)
	for i := 2; i <= SendsPerHour; i++ {
		mustSend(t, e, PurposeUnlock, "")
		e.clock = e.clock.Add(ResendGap)
	}
	if _, err := e.s.SendCode(PurposeUnlock, ""); code(err) != CodeRateLimited || !strings.Contains(err.Error(), "5 封") {
		t.Fatalf("6th mail in an hour: %v", err)
	}
	// The first mail (the bind code) leaves the one-hour window.
	e.clock = e.clock.Add(time.Hour - time.Duration(SendsPerHour)*ResendGap)
	mustSend(t, e, PurposeUnlock, "")
}

func TestFailedSendKeepsAllowanceAndOffersMaster(t *testing.T) {
	e := setup(t)
	enableEmail(t, e)
	e.s.Lock(ReasonManual)
	e.mail.fail = errors.New("535 authentication failed")
	_, err := e.s.SendCode(PurposeUnlock, "")
	if code(err) != CodeSendFailed || !strings.Contains(err.Error(), "535") || strings.Contains(err.Error(), "fake-app-password") {
		t.Fatalf("send failure: %v", err)
	}
	if e.s.otp.code != nil {
		t.Fatal("a code is pending although the mail failed")
	}
	e.mail.fail = nil
	mustSend(t, e, PurposeUnlock, "") // no 60 s wait after a failure
	if err := e.s.Unlock(master); err != nil {
		t.Fatalf("master still unlocks: %v", err)
	}
}

func TestThreeVoidedCodesPauseEmail(t *testing.T) {
	e := setup(t)
	enableEmail(t, e)
	e.s.Lock(ReasonManual)
	voidOne := func() error {
		c := mustSend(t, e, PurposeUnlock, "")
		var err error
		for i := 0; i < CodeMaxTries; i++ {
			err = e.s.UnlockWithCode(wrongCode(c), false)
		}
		e.clock = e.clock.Add(ResendGap)
		return err
	}
	voidOne()
	voidOne()
	if err := voidOne(); code(err) != CodePaused {
		t.Fatalf("third void: %v", err)
	}
	if st := e.s.Status().Email; st.PausedSeconds <= 0 {
		t.Fatalf("status: %+v", st)
	}
	if _, err := e.s.SendCode(PurposeUnlock, ""); code(err) != CodePaused {
		t.Fatalf("send while paused: %v", err)
	}
	if err := e.s.Unlock(master); err != nil {
		t.Fatalf("master during pause: %v", err)
	}
	e.s.Lock(ReasonManual)
	e.clock = e.clock.Add(EmailPause)
	c := mustSend(t, e, PurposeUnlock, "")
	if err := e.s.UnlockWithCode(c, false); err != nil {
		t.Fatalf("after pause: %v", err)
	}
}

// A success in between resets the count of voided codes.
func TestSuccessResetsVoidCount(t *testing.T) {
	e := setup(t)
	enableEmail(t, e)
	e.s.Lock(ReasonManual)
	for round := 0; round < 2; round++ {
		for v := 0; v < VoidsToPause-1; v++ {
			c := mustSend(t, e, PurposeUnlock, "")
			for i := 0; i < CodeMaxTries; i++ {
				e.s.UnlockWithCode(wrongCode(c), false)
			}
			e.clock = e.clock.Add(ResendGap)
		}
		if round == 0 {
			c := mustSend(t, e, PurposeUnlock, "")
			if err := e.s.UnlockWithCode(c, false); err != nil {
				t.Fatal(err)
			}
			e.s.Lock(ReasonManual)
			e.clock = e.clock.Add(time.Hour) // stay under five mails per hour
		}
	}
	if !e.s.otp.pausedUntil.IsZero() {
		t.Fatal("paused although a code succeeded in between")
	}
}

func TestRestartVoidsPendingCodes(t *testing.T) {
	e := setup(t)
	enableEmail(t, e)
	c := lockAndSend(t, e, PurposeUnlock)
	e.s.Shutdown()
	v, err := vault.Open(e.opt.VaultPath)
	if err != nil {
		t.Fatal(err)
	}
	e.s = New(v, e.opt)
	if !e.s.Status().Email.Enabled {
		t.Fatal("email setting lost on restart")
	}
	if err := e.s.UnlockWithCode(c, false); code(err) != CodeCodeGone {
		t.Fatalf("code from before restart: %v", err)
	}
	// Email still works after restart with a new code (the DPAPI copy is on disk).
	c = mustSend(t, e, PurposeUnlock, "")
	if err := e.s.UnlockWithCode(c, false); err != nil {
		t.Fatal(err)
	}
}

func TestCodesAreBoundToPurpose(t *testing.T) {
	e := setup(t)
	a := addWifi(t, e)
	b, _ := e.s.Save(Input{Type: vault.TypePassword, Name: "Router", Password: "router-secret-1"})
	enableEmail(t, e)

	// An unlock code cannot start a master password reset.
	c := lockAndSend(t, e, PurposeUnlock)
	if err := e.s.UnlockWithCode(c, true); code(err) != CodeWrongCode {
		t.Fatalf("unlock code used for reset: %v", err)
	}
	if err := e.s.UnlockWithCode(c, false); err != nil {
		t.Fatal(err)
	}
	if err := e.s.ResetMaster("Brand-new!master", "Brand-new!master"); code(err) != CodeNeedAuth {
		t.Fatalf("reset after plain unlock: %v", err)
	}

	// A reveal code is bound to its item.
	e.clock = e.clock.Add(ResendGap + FreshWindow)
	c = mustSend(t, e, PurposeReveal, a.ID)
	if err := e.s.VerifyCode(PurposeReveal, b.ID, c); code(err) != CodeWrongCode {
		t.Fatalf("reveal code for another item: %v", err)
	}
	if err := e.s.VerifyCode(PurposeSensitive, OpExport, c); code(err) != CodeWrongCode {
		t.Fatalf("reveal code for export: %v", err)
	}
	if err := e.s.VerifyCode(PurposeReveal, a.ID, c); err != nil {
		t.Fatal(err)
	}
	if got, err := e.s.Reveal(a.ID, ""); err != nil || got != "wifi-secret-123" {
		t.Fatalf("reveal after code: %q %v", got, err)
	}
	// One-time: the same code cannot be used again.
	if err := e.s.VerifyCode(PurposeReveal, a.ID, c); code(err) != CodeCodeGone {
		t.Fatalf("code reused: %v", err)
	}

	// A sensitive code is bound to one action, and the grant is used once.
	e.clock = e.clock.Add(ResendGap + FreshWindow)
	c = mustSend(t, e, PurposeSensitive, OpEmailDisable)
	if err := e.s.VerifyCode(PurposeSensitive, OpExport, c); code(err) != CodeWrongCode {
		t.Fatalf("disable code for export: %v", err)
	}
	if err := e.s.VerifyCode(PurposeSensitive, OpEmailDisable, c); err != nil {
		t.Fatal(err)
	}
	if err := e.s.PrepareExport("", "Backup-pass!1", "Backup-pass!1"); code(err) != CodeNeedAuth {
		t.Fatalf("export with disable grant: %v", err)
	}
	if _, err := e.s.SendCode(PurposeSensitive, "anything"); code(err) != CodeInvalid {
		t.Fatalf("unknown action: %v", err)
	}
}

// The 60-second window after unlocking never covers sensitive actions.
func TestSensitiveActionsIgnoreFreshWindow(t *testing.T) {
	e := setup(t)
	enableEmail(t, e)
	if err := e.s.DisableEmail(); code(err) != CodeNeedAuth {
		t.Fatalf("disable inside fresh window: %v", err)
	}
	if err := e.s.PrepareExport("", "Backup-pass!1", "Backup-pass!1"); code(err) != CodeNeedAuth {
		t.Fatalf("export inside fresh window: %v", err)
	}
	c := mustSend(t, e, PurposeSensitive, OpExport)
	if err := e.s.VerifyCode(PurposeSensitive, OpExport, c); err != nil {
		t.Fatal(err)
	}
	if err := e.s.PrepareExport("", "Backup-pass!1", "Backup-pass!1"); err != nil {
		t.Fatalf("export after email code: %v", err)
	}
	if err := e.s.PrepareExport("", "Backup-pass!1", "Backup-pass!1"); code(err) != CodeNeedAuth {
		t.Fatalf("export grant reused: %v", err)
	}
	// Locking drops any grant.
	if err := e.s.Authorize(OpEmailDisable, master); err != nil {
		t.Fatal(err)
	}
	e.s.Lock(ReasonManual)
	e.s.Unlock(master)
	if err := e.s.DisableEmail(); code(err) != CodeNeedAuth {
		t.Fatalf("grant survived lock: %v", err)
	}
}

func TestResetMasterWithEmail(t *testing.T) {
	e := setup(t)
	d := addWifi(t, e)
	enableEmail(t, e)
	c := lockAndSend(t, e, PurposeReset)
	if err := e.s.UnlockWithCode(c, true); err != nil {
		t.Fatal(err)
	}
	// The UI uses this to offer the reset again if the person closed the dialog.
	if s := e.s.Status().Email.ResetSeconds; s <= 0 || s > int(resetGrant/time.Second) {
		t.Fatalf("reset window in status: %d", s)
	}
	if err := e.s.ResetMaster("short", "short"); code(err) != CodeInvalid {
		t.Fatalf("short new master: %v", err)
	}
	if err := e.s.ResetMaster("My-new!master", "My-new!master"); err != nil {
		t.Fatal(err)
	}
	if err := e.s.ResetMaster("Another!master", "Another!master"); code(err) != CodeNeedAuth {
		t.Fatalf("reset allowed twice: %v", err)
	}
	if s := e.s.Status().Email.ResetSeconds; s != 0 {
		t.Fatalf("reset window still shown after reset: %d", s)
	}
	e.s.Lock(ReasonManual)
	if err := e.s.Unlock(master); code(err) != CodeWrong {
		t.Fatalf("old master after reset: %v", err)
	}
	e.clock = e.clock.Add(time.Second)
	if err := e.s.Unlock("My-new!master"); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.s.Reveal(d.ID, ""); got != "wifi-secret-123" {
		t.Fatalf("data after reset: %q", got)
	}
	// Email unlock keeps working: the data key did not change.
	e.clock = e.clock.Add(ResendGap)
	c = lockAndSend(t, e, PurposeUnlock)
	if err := e.s.UnlockWithCode(c, false); err != nil {
		t.Fatal(err)
	}
}

func TestResetGrantExpiresAndLockDropsIt(t *testing.T) {
	e := setup(t)
	enableEmail(t, e)
	c := lockAndSend(t, e, PurposeReset)
	if err := e.s.UnlockWithCode(c, true); err != nil {
		t.Fatal(err)
	}
	e.s.Lock(ReasonManual)
	e.s.Unlock(master)
	if err := e.s.ResetMaster("My-new!master", "My-new!master"); code(err) != CodeNeedAuth {
		t.Fatalf("reset after lock: %v", err)
	}
}

func TestDisableEmail(t *testing.T) {
	e := setup(t)
	enableEmail(t, e)
	// A code is pending when Email gets disabled.
	e.s.Lock(ReasonManual)
	pending := mustSend(t, e, PurposeUnlock, "")
	e.s.Unlock(master)
	if err := e.s.Authorize(OpEmailDisable, master); err != nil {
		t.Fatal(err)
	}
	if err := e.s.DisableEmail(); err != nil {
		t.Fatal(err)
	}
	if st := e.s.Status().Email; st.Enabled || st.Masked != "" {
		t.Fatalf("status after disable: %+v", st)
	}
	if e.s.cur().EmailEnabled() {
		t.Fatal("DPAPI copy still stored")
	}
	e.s.Lock(ReasonManual)
	if err := e.s.UnlockWithCode(pending, false); code(err) != CodeCodeGone {
		t.Fatalf("pending code after disable: %v", err)
	}
	e.clock = e.clock.Add(ResendGap)
	if _, err := e.s.SendCode(PurposeUnlock, ""); code(err) != CodeEmailOff {
		t.Fatalf("send after disable: %v", err)
	}
	if _, err := e.s.SendCode(PurposeReset, ""); code(err) != CodeEmailOff {
		t.Fatalf("reset after disable: %v", err)
	}
}

func TestChangeAddressKeepsPasswordAndUsesOldAddressToVerify(t *testing.T) {
	e := setup(t)
	enableEmail(t, e)
	c := mustSend(t, e, PurposeSensitive, OpEmailSetup)
	if e.mail.sent[len(e.mail.sent)-1].to != "demo@example.com" {
		t.Fatal("re-verification must go to the bound address")
	}
	if err := e.s.VerifyCode(PurposeSensitive, OpEmailSetup, c); err != nil {
		t.Fatal(err)
	}
	got, err := e.s.EmailSettings()
	if err != nil || got.Host != "smtp.example.com" || got.To != "demo@example.com" || got.Password != "" {
		t.Fatalf("settings for the form: %+v %v", got, err)
	}
	next := testEmail
	next.To, next.Password = "new.box@example.org", "" // empty keeps the stored app password
	e.clock = e.clock.Add(ResendGap)
	if _, err := e.s.StartEmailSetup(next); err != nil {
		t.Fatal(err)
	}
	last := e.mail.sent[len(e.mail.sent)-1]
	if last.to != "new.box@example.org" || last.cfg.Password != "fake-app-password" {
		t.Fatalf("bind mail: %+v", last)
	}
	// Until confirmed, codes still go to the old address.
	if st := e.s.Status().Email; st.Masked != "d***@example.com" {
		t.Fatalf("masked before confirm: %+v", st)
	}
	if _, err := e.s.FinishEmailSetup(last.m.Code); err != nil {
		t.Fatal(err)
	}
	if st := e.s.Status().Email; st.Masked != "n***@example.org" {
		t.Fatalf("masked after change: %+v", st)
	}
}

func TestLockScreenCannotChangeAddress(t *testing.T) {
	e := setup(t)
	enableEmail(t, e)
	e.s.Lock(ReasonManual)
	if err := e.s.Authorize(OpEmailSetup, master); code(err) != CodeLocked {
		t.Fatalf("authorize while locked: %v", err)
	}
	if _, err := e.s.StartEmailSetup(testEmail); code(err) != CodeLocked {
		t.Fatalf("setup while locked: %v", err)
	}
	if _, err := e.s.SendCode(PurposeReveal, "x"); code(err) != CodeLocked {
		t.Fatalf("reveal code while locked: %v", err)
	}
}

func TestEmailOffWithoutProtector(t *testing.T) {
	e := setup(t)
	e.opt.Protector, e.opt.Mailer = nil, nil
	e.s.opt = e.opt
	if st := e.s.Status().Email; st.Available || st.Enabled {
		t.Fatalf("status: %+v", st)
	}
	e.s.Authorize(OpEmailSetup, master)
	if _, err := e.s.StartEmailSetup(testEmail); code(err) != CodeEmailOff {
		t.Fatalf("setup without DPAPI: %v", err)
	}
}

// Restoring a backup builds a new vault without the email unlock path.
func TestRestoreDropsEmail(t *testing.T) {
	e := setup(t)
	enableEmail(t, e)
	path := export(t, e)
	if _, err := e.s.PreviewRestore(path, bpw); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Restore(master, master); err != nil {
		t.Fatal(err)
	}
	if e.s.Status().Email.Enabled {
		t.Fatal("restored vault has email unlock")
	}
}

func TestMaskEmail(t *testing.T) {
	for in, want := range map[string]string{"demo@example.com": "d***@example.com", "王小明@example.tw": "王***@example.tw", "bad": "***"} {
		if got := MaskEmail(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

// Unlocked with a plain Email code (or the 10-minute reset window ran out) and the master password
// is forgotten: an Email code for OpMasterReset still allows setting a new one.
func TestMasterResetAfterPlainEmailUnlock(t *testing.T) {
	e := setup(t)
	enableEmail(t, e)
	e.clock = e.clock.Add(ResendGap)
	c := lockAndSend(t, e, PurposeUnlock)
	if err := e.s.UnlockWithCode(c, false); err != nil {
		t.Fatal(err)
	}
	if err := e.s.ResetMaster("My-new!master", "My-new!master"); code(err) != CodeNeedAuth {
		t.Fatalf("reset without verification: %v", err)
	}
	e.clock = e.clock.Add(ResendGap)
	c = mustSend(t, e, PurposeSensitive, OpMasterReset)
	if err := e.s.VerifyCode(PurposeSensitive, OpMasterReset, c); err != nil {
		t.Fatal(err)
	}
	if err := e.s.ResetMaster("My-new!master", "My-new!master"); err != nil {
		t.Fatal(err)
	}
	if err := e.s.ResetMaster("Another!master", "Another!master"); code(err) != CodeNeedAuth {
		t.Fatalf("one code, one reset: %v", err)
	}
	e.s.Lock(ReasonManual)
	if err := e.s.Unlock(master); code(err) != CodeWrong {
		t.Fatalf("old master still works: %v", err)
	}
	e.clock = e.clock.Add(time.Second)
	if err := e.s.Unlock("My-new!master"); err != nil {
		t.Fatal(err)
	}
}
