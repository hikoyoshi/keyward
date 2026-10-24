package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hikoyoshi/keyward/internal/vault"
)

// Email verification codes (PLAN.md section 6). Codes live only in memory as an HMAC under a key
// made at start-up, so restarting the app voids every pending code.

const (
	CodeLifetime   = 10 * time.Minute
	CodeMaxTries   = 5
	ResendGap      = 60 * time.Second
	SendsPerHour   = 5
	VoidsToPause   = 3
	EmailPause     = 15 * time.Minute
	sensitiveGrant = 10 * time.Minute // time to finish a re-verified action such as filling the SMTP form
	resetGrant     = 10 * time.Minute
)

// Purposes a code is bound to. Reveal codes are bound to one item, sensitive codes to one action.
const (
	PurposeUnlock    = "unlock"
	PurposeReset     = "reset"
	PurposeReveal    = "reveal"
	PurposeSensitive = "sensitive"
	PurposeBind      = "bind" // test code to a new address while setting up
)

// Sensitive actions that always need a fresh verification, never the 60-second window.
const (
	OpEmailSetup   = "email-setup" // enable, or change address/SMTP
	OpEmailDisable = "email-disable"
	OpExport       = "export"
	// OpMasterReset sets a new master password without the current one, after an Email code.
	// It is for someone who unlocked with Email and does not remember the master password.
	OpMasterReset = "master-reset"
)

var sensitiveOps = map[string]bool{OpEmailSetup: true, OpEmailDisable: true, OpExport: true, OpMasterReset: true}

const (
	CodeEmailOff    = "email_off"
	CodePaused      = "email_paused"
	CodeRateLimited = "rate_limited"
	CodeSendFailed  = "send_failed"
	CodeWrongCode   = "wrong_code"
	CodeCodeGone    = "code_gone" // expired, voided, used or never sent
)

type SMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
}

// EmailConfig is stored OS-protected so codes can be sent while the vault is locked.
type EmailConfig struct {
	SMTP SMTPConfig `json:"smtp"`
	To   string     `json:"to"`
}

// CodeMail is everything a mailer needs; the wording is fixed in codeMessage, so no other mail can be sent.
type CodeMail struct {
	Code    string
	Purpose string
	Expires time.Time
	Lang    string // "en" or Traditional Chinese
}

type Mailer interface {
	Send(cfg SMTPConfig, to string, m CodeMail) error
}

type pendingCode struct {
	mac     []byte
	serial  uint64
	created time.Time
	expires time.Time
	tries   int
	purpose string
	target  string
}

type otpState struct {
	key         []byte
	serial      uint64
	code        *pendingCode
	sends       []time.Time
	voids       int  // codes voided in a row by wrong tries
	lastUsed    bool // the latest code was entered correctly, so a new request is not a resend
	pausedUntil time.Time
	grantOp     string
	grantUntil  time.Time
	resetUntil  time.Time
	bind        *EmailConfig // address being set up, waiting for its test code
	masked      string       // cached for Status; "" when unknown
}

func newOTP() otpState {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("core: system random source failed: " + err.Error())
	}
	return otpState{key: key}
}

func (o *otpState) mac(p *pendingCode, code string) []byte {
	h := hmac.New(sha256.New, o.key)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], p.serial)
	h.Write(n[:])
	h.Write([]byte(p.purpose + "\x00" + p.target + "\x00" + code))
	return h.Sum(nil)
}

func newCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%06d", n.Int64())
}

type EmailStatus struct {
	Available     bool   `json:"available"` // this build can protect keys with the OS
	Enabled       bool   `json:"enabled"`
	Masked        string `json:"masked,omitempty"`
	PausedSeconds int    `json:"pausedSeconds,omitempty"`
	ResetSeconds  int    `json:"resetSeconds,omitempty"` // time left to set a new master password after an Email reset
}

// CodeSent tells the UI where the code went and when it may ask again.
type CodeSent struct {
	Masked    string `json:"masked"`
	ExpiresIn int    `json:"expiresIn"`
	ResendIn  int    `json:"resendIn"`
}

// emailStatus needs s.mu.
func (s *Service) emailStatus() EmailStatus {
	st := EmailStatus{Available: s.opt.Protector != nil && s.opt.Mailer != nil}
	if !st.Available || !s.v.EmailEnabled() {
		return st
	}
	st.Enabled = true
	if s.otp.masked == "" {
		if cfg, err := s.emailConfig(); err == nil {
			s.otp.masked = MaskEmail(cfg.To)
		}
	}
	st.Masked = s.otp.masked
	if left := s.otp.pausedUntil.Sub(s.now()); left > 0 {
		st.PausedSeconds = int((left + time.Second - 1) / time.Second)
	}
	if left := s.otp.resetUntil.Sub(s.now()); left > 0 && !s.v.Locked() {
		st.ResetSeconds = int((left + time.Second - 1) / time.Second)
	}
	return st
}

func (s *Service) emailConfig() (EmailConfig, error) {
	var cfg EmailConfig
	raw, err := s.v.EmailConfig(s.opt.Protector)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(raw, &cfg)
	wipeBytes(raw)
	return cfg, err
}

// MaskEmail shows the first character of the local part, e.g. d***@example.com.
func MaskEmail(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 1 {
		return "***"
	}
	r := []rune(addr[:at])
	return string(r[0]) + "***" + addr[at:]
}

// ---------- sending ----------

// SendCode mails a new code for purpose (and target: item ID for reveal, action for sensitive).
// The new code replaces any pending one at once, even if sending then fails.
func (s *Service) SendCode(purpose, target string) (CodeSent, error) {
	s.mu.Lock()
	if err := s.checkPurpose(purpose, target); err != nil {
		s.mu.Unlock()
		return CodeSent{}, err
	}
	if !s.emailStatus().Enabled {
		s.mu.Unlock()
		return CodeSent{}, uerr(CodeEmailOff, "尚未啟用 Email 驗證碼，請改用主密碼。")
	}
	cfg, err := s.emailConfig()
	if err != nil {
		s.mu.Unlock()
		return CodeSent{}, uerr(CodeSendFailed, "無法讀取寄信設定（可能換了 Windows 帳號或電腦）。請改用主密碼，並重新設定 Email 驗證碼。")
	}
	return s.sendLocked(cfg, purpose, target)
}

func (s *Service) checkPurpose(purpose, target string) error {
	switch purpose {
	case PurposeUnlock, PurposeReset:
		if !s.v.Initialized() {
			return uerr(CodeNotSetUp, "尚未建立密碼庫。")
		}
		if !s.v.Locked() {
			return uerr(CodeInvalid, "密碼庫已經解鎖。")
		}
	case PurposeReveal, PurposeSensitive:
		if s.v.Locked() {
			return uerr(CodeLocked, "密碼庫已鎖定。")
		}
		if purpose == PurposeSensitive && !sensitiveOps[target] {
			return uerr(CodeInvalid, "不支援的操作。")
		}
		if purpose == PurposeReveal {
			if _, err := s.v.Item(target); err != nil {
				return mapErr(err)
			}
		}
	default:
		return uerr(CodeInvalid, "不支援的驗證用途。")
	}
	return nil
}

// sendLocked applies the pause and rate limits, replaces the pending code and sends it.
// It is called with s.mu held and releases it before talking to the mail server.
func (s *Service) sendLocked(cfg EmailConfig, purpose, target string) (CodeSent, error) {
	now := s.now()
	o := &s.otp
	if now.Before(o.pausedUntil) {
		left := o.pausedUntil.Sub(now)
		s.mu.Unlock()
		return CodeSent{}, uerr(CodePaused, "連續 3 組驗證碼輸入錯誤，Email 驗證暫停到 "+clock(now.Add(left))+"。請改用主密碼。")
	}
	recent := o.sends[:0]
	for _, t := range o.sends {
		if t.After(now) { // the clock moved back; count it as sent just now
			t = now
		}
		if now.Sub(t) < time.Hour {
			recent = append(recent, t)
		}
	}
	o.sends = recent
	if n := len(recent); n > 0 {
		// The gap limits resending while a code is outstanding; right after a code was used
		// (e.g. enabling Email, then locking) a new request for another purpose may go out at once.
		if gap := now.Sub(recent[n-1]); gap < ResendGap && !o.lastUsed {
			s.mu.Unlock()
			return CodeSent{}, uerr(CodeRateLimited, "重新寄送需間隔 60 秒，"+waitMsg(ResendGap-gap))
		}
		if n >= SendsPerHour {
			s.mu.Unlock()
			return CodeSent{}, uerr(CodeRateLimited, "這一小時已寄出 5 封驗證碼，請到 "+clock(recent[0].Add(time.Hour))+" 後再試，或改用主密碼。")
		}
	}
	o.serial++
	o.lastUsed = false
	code := newCode()
	p := &pendingCode{serial: o.serial, created: now, expires: now.Add(CodeLifetime), purpose: purpose, target: target}
	p.mac = o.mac(p, code)
	o.code = p
	o.sends = append(o.sends, now)
	mailer := s.opt.Mailer
	s.mu.Unlock()

	err := mailer.Send(cfg.SMTP, cfg.To, CodeMail{Code: code, Purpose: purpose, Expires: p.expires, Lang: s.language()})
	if err != nil {
		s.mu.Lock()
		if o.code == p {
			o.code = nil
		}
		// A failed attempt does not use up the sending allowance.
		for i := len(o.sends) - 1; i >= 0; i-- {
			if o.sends[i].Equal(now) {
				o.sends = append(o.sends[:i], o.sends[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
		return CodeSent{}, uerr(CodeSendFailed, "寄送驗證碼失敗："+sendErrMsg(err))
	}
	return CodeSent{Masked: MaskEmail(cfg.To), ExpiresIn: int(CodeLifetime / time.Second), ResendIn: int(ResendGap / time.Second)}, nil
}

func clock(t time.Time) string { return t.Local().Format("15:04") }

// sendErrMsg keeps the server's reply (useful for fixing SMTP settings) but never echoes credentials.
func sendErrMsg(err error) string {
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return msg
}

// ---------- checking ----------

var sixDigits = regexp.MustCompile(`^[0-9]{6}$`)

// checkCode consumes the pending code on success. Caller holds s.mu.
func (s *Service) checkCode(purpose, target, code string) error {
	now := s.now()
	o := &s.otp
	code = strings.TrimSpace(code)
	if !sixDigits.MatchString(code) {
		return uerr(CodeInvalid, "請輸入 6 位數字。")
	}
	p := o.code
	if p == nil {
		return uerr(CodeCodeGone, "驗證碼已失效或尚未寄出，請重新寄送。")
	}
	// The clock moving back must not extend a code, so a code "from the future" is void too.
	if !now.Before(p.expires) || now.Before(p.created) {
		o.code = nil
		return uerr(CodeCodeGone, "驗證碼已逾期（10 分鐘），請重新寄送。")
	}
	want := o.mac(&pendingCode{serial: p.serial, purpose: purpose, target: target}, code)
	if hmac.Equal(want, p.mac) {
		o.code = nil
		o.voids = 0
		o.lastUsed = true
		return nil
	}
	// A right code for another purpose counts as wrong here.
	p.tries++
	if p.tries < CodeMaxTries {
		return uerr(CodeWrongCode, "驗證碼不正確，還可以再試 "+strconv.Itoa(CodeMaxTries-p.tries)+" 次。")
	}
	o.code = nil
	o.voids++
	if o.voids >= VoidsToPause {
		o.voids = 0
		o.pausedUntil = now.Add(EmailPause)
		return uerr(CodePaused, "連續 3 組驗證碼輸入錯誤 5 次，Email 驗證暫停 15 分鐘（到 "+clock(o.pausedUntil)+"）。請改用主密碼。")
	}
	return uerr(CodeCodeGone, "已輸入錯誤 5 次，這組驗證碼已作廢，請重新寄送。")
}

// UnlockWithCode unlocks with an emailed code. With reset, it also allows setting a new master password
// without the old one for the next 10 minutes.
func (s *Service) UnlockWithCode(code string, reset bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.v.Locked() {
		return uerr(CodeInvalid, "密碼庫已經解鎖。")
	}
	purpose := PurposeUnlock
	if reset {
		purpose = PurposeReset
	}
	if err := s.checkCode(purpose, "", code); err != nil {
		return err
	}
	if err := s.v.UnlockWithEmail(s.opt.Protector); err != nil {
		if errors.Is(err, vault.ErrEmailOff) {
			return uerr(CodeEmailOff, "Email 驗證碼已停用，請改用主密碼。")
		}
		if errors.Is(err, vault.ErrCorrupt) {
			return uerr(CodeInternal, "密碼庫檔案無法通過完整性檢查，可能已損毀或被修改。請從備份還原。")
		}
		return uerr(CodeInternal, "驗證碼正確，但這台電腦無法解開 Email 解鎖資料（可能換了 Windows 帳號或重灌）。請改用主密碼。")
	}
	s.afterUnlock()
	if reset {
		s.otp.resetUntil = s.now().Add(resetGrant)
	}
	return nil
}

// VerifyCode handles codes for revealing an item (opens the usual 60-second window)
// and for sensitive actions (grants that one action once).
func (s *Service) VerifyCode(purpose, target, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v.Locked() {
		return uerr(CodeLocked, "密碼庫已鎖定。")
	}
	if purpose != PurposeReveal && purpose != PurposeSensitive {
		return uerr(CodeInvalid, "不支援的驗證用途。")
	}
	if err := s.checkCode(purpose, target, code); err != nil {
		return err
	}
	now := s.now()
	s.lastActive = now
	if purpose == PurposeReveal {
		s.freshUntil = now.Add(FreshWindow)
	} else {
		s.otp.grantOp, s.otp.grantUntil = target, now.Add(sensitiveGrant)
	}
	return nil
}

// Authorize re-verifies the master password for one sensitive action.
func (s *Service) Authorize(op, master string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v.Locked() {
		return uerr(CodeLocked, "密碼庫已鎖定。")
	}
	if !sensitiveOps[op] {
		return uerr(CodeInvalid, "不支援的操作。")
	}
	if err := s.verifyMaster(master, false); err != nil {
		return err
	}
	now := s.now()
	s.lastActive = now
	s.otp.grantOp, s.otp.grantUntil = op, now.Add(sensitiveGrant)
	return nil
}

// hasGrant reports a fresh re-verification for op; take also uses it up. Caller holds s.mu.
func (s *Service) hasGrant(op string, take bool) bool {
	ok := s.otp.grantOp == op && s.now().Before(s.otp.grantUntil)
	if ok && take {
		s.otp.grantOp, s.otp.grantUntil = "", time.Time{}
	}
	return ok
}

func needGrant() error {
	return uerr(CodeNeedAuth, "這個操作需要重新驗證，請再試一次。")
}

// ---------- setting up, changing and disabling ----------

type EmailInput struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"` // empty while changing keeps the stored one
	To       string `json:"to"`
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)

func checkAddr(a string) (string, bool) {
	a = strings.TrimSpace(a)
	if a == "" || strings.ContainsAny(a, "\r\n<>\"") {
		return "", false
	}
	p, err := mail.ParseAddress(a)
	if err != nil || p.Address != a || p.Name != "" {
		return "", false
	}
	return a, true
}

func (in EmailInput) config() (EmailConfig, error) {
	cfg := EmailConfig{SMTP: SMTPConfig{Host: strings.TrimSpace(in.Host), Port: in.Port, User: strings.TrimSpace(in.User), Password: in.Password}}
	if !hostRe.MatchString(cfg.SMTP.Host) || len(cfg.SMTP.Host) > 253 {
		return cfg, uerr(CodeInvalid, "SMTP 伺服器名稱不正確，例如 smtp.gmail.com。")
	}
	if cfg.SMTP.Port != 465 && cfg.SMTP.Port != 587 {
		return cfg, uerr(CodeInvalid, "連接埠請用 587（STARTTLS）或 465（TLS）。")
	}
	if cfg.SMTP.User == "" || strings.ContainsAny(cfg.SMTP.User, "\r\n") {
		return cfg, uerr(CodeInvalid, "請輸入寄件帳號。")
	}
	to, ok := checkAddr(in.To)
	if !ok {
		return cfg, uerr(CodeInvalid, "收件信箱格式不正確。")
	}
	cfg.To = to
	return cfg, nil
}

// StartEmailSetup checks the form and mails a test code to the new address.
// It needs a fresh re-verification (Authorize or a sensitive code) for OpEmailSetup.
func (s *Service) StartEmailSetup(in EmailInput) (CodeSent, error) {
	cfg, err := in.config()
	if err != nil {
		return CodeSent{}, err
	}
	s.mu.Lock()
	if s.v.Locked() {
		s.mu.Unlock()
		return CodeSent{}, uerr(CodeLocked, "密碼庫已鎖定。")
	}
	if s.opt.Protector == nil || s.opt.Mailer == nil {
		s.mu.Unlock()
		return CodeSent{}, uerr(CodeEmailOff, "這個版本不支援 Email 驗證碼。")
	}
	if !s.hasGrant(OpEmailSetup, false) {
		s.mu.Unlock()
		return CodeSent{}, needGrant()
	}
	if cfg.SMTP.Password == "" {
		old, err := s.emailConfig()
		if err != nil || !s.v.EmailEnabled() {
			s.mu.Unlock()
			return CodeSent{}, uerr(CodeInvalid, "請輸入應用程式密碼。")
		}
		cfg.SMTP.Password = old.SMTP.Password
	}
	s.otp.bind = &cfg
	s.lastActive = s.now()
	return s.sendLocked(cfg, PurposeBind, cfg.To)
}

// EmailSettings returns the stored settings without the app password, to prefill the change form.
// Like StartEmailSetup, it needs a fresh re-verification.
func (s *Service) EmailSettings() (EmailInput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v.Locked() {
		return EmailInput{}, uerr(CodeLocked, "密碼庫已鎖定。")
	}
	if !s.hasGrant(OpEmailSetup, false) {
		return EmailInput{}, needGrant()
	}
	if !s.v.EmailEnabled() || s.opt.Protector == nil {
		return EmailInput{Port: 587}, nil
	}
	cfg, err := s.emailConfig()
	if err != nil {
		return EmailInput{Port: 587}, nil
	}
	return EmailInput{Host: cfg.SMTP.Host, Port: cfg.SMTP.Port, User: cfg.SMTP.User, To: cfg.To}, nil
}

// FinishEmailSetup checks the test code and turns email codes on (or switches to the new address).
func (s *Service) FinishEmailSetup(code string) (EmailStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v.Locked() {
		return EmailStatus{}, uerr(CodeLocked, "密碼庫已鎖定。")
	}
	cfg := s.otp.bind
	if cfg == nil || !s.hasGrant(OpEmailSetup, false) {
		return EmailStatus{}, needGrant()
	}
	if err := s.checkCode(PurposeBind, cfg.To, code); err != nil {
		return EmailStatus{}, err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return EmailStatus{}, internal(err)
	}
	defer wipeBytes(raw)
	if err := s.v.SetEmail(s.opt.Protector, raw); err != nil {
		return EmailStatus{}, uerr(CodeInternal, "無法保存 Email 設定："+err.Error())
	}
	s.hasGrant(OpEmailSetup, true)
	s.otp.bind = nil
	s.otp.masked = MaskEmail(cfg.To)
	s.lastActive = s.now()
	return s.emailStatus(), nil
}

// DisableEmail removes the OS-protected key, the email settings and any pending code.
func (s *Service) DisableEmail() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v.Locked() {
		return uerr(CodeLocked, "密碼庫已鎖定。")
	}
	if !s.hasGrant(OpEmailDisable, true) {
		return needGrant()
	}
	if err := s.v.ClearEmail(); err != nil {
		return internal(err)
	}
	s.dropEmailState()
	return nil
}

// dropEmailState forgets pending codes and cached email details, keeping the send history and pause. Caller holds s.mu.
func (s *Service) dropEmailState() {
	s.otp.code, s.otp.bind, s.otp.masked = nil, nil, ""
	s.otp.resetUntil = time.Time{}
}

// ResetMaster sets a new master password after UnlockWithCode(…, reset=true), or after an Email code
// for OpMasterReset while unlocked. The old one stops working.
func (s *Service) ResetMaster(next, confirm string) error {
	if err := checkNewMaster(next, confirm); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v.Locked() {
		return uerr(CodeLocked, "密碼庫已鎖定。")
	}
	if !s.now().Before(s.otp.resetUntil) && !s.hasGrant(OpMasterReset, true) {
		return uerr(CodeNeedAuth, "重設時限已過，請在設定頁「變更主密碼」改寄 Email 驗證碼，或用目前的主密碼變更。")
	}
	if err := s.v.SetMaster([]byte(next)); err != nil {
		return internal(err)
	}
	s.otp.resetUntil = time.Time{}
	s.fails, s.waitUntil = 0, time.Time{}
	s.freshUntil = s.now().Add(FreshWindow)
	return nil
}

// CancelEmailSetup forgets an address that was never confirmed.
func (s *Service) CancelEmailSetup() {
	s.mu.Lock()
	if s.otp.code != nil && s.otp.code.purpose == PurposeBind {
		s.otp.code = nil
	}
	s.otp.bind = nil
	s.mu.Unlock()
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
