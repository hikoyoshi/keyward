// Package core holds the rules between the UI and the vault: locking, re-verification and clipboard handling.
package core

import (
	"crypto/rand"
	"errors"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hikoyoshi/keyward/internal/vault"
)

const (
	FreshWindow    = 60 * time.Second // after unlock or verification, show/copy without asking again
	ClipboardClear = 30 * time.Second
	sleepGap       = 30 * time.Second // a longer gap between ticks means the PC slept
	minMaster      = 8                // see passwordRule
	maxBackoff     = 30 * time.Second
)

// Lock reasons reported to the UI.
const (
	ReasonManual  = "manual"
	ReasonIdle    = "idle"
	ReasonWindows = "windows"
	ReasonSleep   = "sleep"
)

type Clipboard interface {
	SetSecret(text string) (seq uint32, err error)
	ClearIf(seq uint32)
}

type Options struct {
	VaultPath     string // needed to keep the old file aside when restoring a backup
	Clipboard     Clipboard
	SessionLocked func() (locked, ok bool)
	OnLock        func(reason string)
	Now           func() time.Time
	Protector     vault.Protector // Windows DPAPI; nil turns email codes off
	Mailer        Mailer
	Browser       Browser           // Keyward's own browser for AI login; nil turns AI login off
	OnAIEvent     func(kind string) // AI requests and session changes, so the window can refresh
}

// Error codes the UI branches on; Msg is shown to the person as is.
const (
	CodeNeedAuth   = "need_auth"
	CodeWait       = "wait"
	CodeWrong      = "wrong_password"
	CodeLocked     = "locked"
	CodeInvalid    = "invalid"
	CodeNotFound   = "not_found"
	CodeInternal   = "internal"
	CodeNotSetUp   = "not_set_up"
	CodeAlreadySet = "already_set_up"
)

type UserError struct {
	Code string
	Msg  string
}

// Error is "code:message" so the web UI can split it without extra plumbing.
func (e *UserError) Error() string { return e.Code + ":" + e.Msg }

func uerr(code, msg string) error { return &UserError{Code: code, Msg: msg} }

type Service struct {
	lang       atomic.Value // "zh-TW" or "en": the language of mails Keyward sends
	mu         sync.Mutex
	v          *vault.Vault
	opt        Options
	freshUntil time.Time
	fails      int
	waitUntil  time.Time
	lastActive time.Time
	lastTick   time.Time
	idle       time.Duration
	clipSeq    uint32
	clipAt     time.Time // zero when nothing of ours is on the clipboard
	restore    *vault.Backup
	restoreAt  time.Time
	csv        *csvImport
	otp        otpState
	ai         aiState
}

func New(v *vault.Vault, opt Options) *Service {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.SessionLocked == nil {
		opt.SessionLocked = func() (bool, bool) { return false, false }
	}
	if opt.OnLock == nil {
		opt.OnLock = func(string) {}
	}
	now := opt.Now()
	return &Service{v: v, opt: opt, idle: 5 * time.Minute, lastActive: now, lastTick: now, otp: newOTP(), ai: newAI()}
}

// cur returns the open vault; Restore may replace it.
func (s *Service) cur() *vault.Vault {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.v
}

func (s *Service) now() time.Time { return s.opt.Now().Round(0) }

type Status struct {
	Initialized  bool         `json:"initialized"`
	Locked       bool         `json:"locked"`
	FreshSeconds int          `json:"freshSeconds"`
	IdleMinutes  int          `json:"idleMinutes"`
	Backup       BackupStatus `json:"backup"`
	Email        EmailStatus  `json:"email"`
}

func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{Initialized: s.v.Initialized(), Locked: s.v.Locked(), IdleMinutes: int(s.idle / time.Minute)}
	if left := s.freshUntil.Sub(s.now()); left > 0 && !st.Locked {
		st.FreshSeconds = int(left.Seconds() + 0.5)
	}
	if !st.Locked {
		st.Backup = s.backupStatus()
	}
	if st.Initialized {
		st.Email = s.emailStatus()
	}
	return st
}

// passwordRule is shared by the master and backup passwords (the backup may reuse the master):
// at least 8 characters, one uppercase letter and one symbol. Spaces do not count as the symbol.
func passwordRule(pw, what string) error {
	var upper, symbol bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r):
			symbol = true
		}
	}
	if utf8.RuneCountInString(pw) < minMaster || !upper || !symbol {
		return uerr(CodeInvalid, what+"需要至少 8 個字元，並包含大寫英文字母與特殊符號（例如 ! @ # $）。")
	}
	return nil
}

func checkNewMaster(pw, confirm string) error {
	if err := passwordRule(pw, "主密碼"); err != nil {
		return err
	}
	if pw != confirm {
		return uerr(CodeInvalid, "兩次輸入不一致。")
	}
	return nil
}

// Setup creates the vault and leaves it unlocked.
func (s *Service) Setup(master, confirm string) error {
	if err := checkNewMaster(master, confirm); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.v.Create([]byte(master)); err != nil {
		if errors.Is(err, vault.ErrAlreadyInitialized) {
			return uerr(CodeAlreadySet, "密碼庫已經建立。")
		}
		return internal(err)
	}
	s.afterUnlock()
	return nil
}

// verifyMaster applies the growing wait between wrong attempts. Caller holds s.mu.
func (s *Service) verifyMaster(master string, unlock bool) error {
	now := s.now()
	if now.Before(s.waitUntil) {
		return uerr(CodeWait, waitMsg(s.waitUntil.Sub(now)))
	}
	var err error
	if unlock {
		err = s.v.Unlock([]byte(master))
	} else {
		err = s.v.VerifyMaster([]byte(master))
	}
	switch {
	case err == nil:
		s.fails = 0
		return nil
	case errors.Is(err, vault.ErrWrongPassword):
		s.fails++
		d := time.Second << min(s.fails-1, 5)
		if d > maxBackoff {
			d = maxBackoff
		}
		s.waitUntil = now.Add(d)
		return uerr(CodeWrong, "主密碼不正確。"+waitMsg(d))
	case errors.Is(err, vault.ErrNotInitialized):
		return uerr(CodeNotSetUp, "尚未建立密碼庫。")
	case errors.Is(err, vault.ErrCorrupt):
		return uerr(CodeInternal, "密碼庫檔案無法通過完整性檢查，可能已損毀或被修改。請從備份還原。")
	default:
		return internal(err)
	}
}

func waitMsg(d time.Duration) string {
	sec := int((d + time.Second - 1) / time.Second)
	return "請等 " + strconv.Itoa(sec) + " 秒再試。"
}

func (s *Service) Unlock(master string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.v.Locked() {
		return nil
	}
	if err := s.verifyMaster(master, true); err != nil {
		return err
	}
	s.afterUnlock()
	return nil
}

func (s *Service) afterUnlock() {
	now := s.now()
	s.freshUntil = now.Add(FreshWindow)
	s.lastActive = now
	if st, err := s.v.Settings(); err == nil && st.IdleMinutes > 0 {
		s.idle = time.Duration(st.IdleMinutes) * time.Minute
	}
	s.reloadClients()
}

// Lock hides everything and clears our secret from the clipboard if it is still there.
// reason is ReasonManual for "鎖定密碼庫" or ReasonStopAll for "全部鎖定並停止".
func (s *Service) Lock(reason string) {
	s.mu.Lock()
	wasLocked := s.v.Locked()
	s.lockLocked()
	tabs := s.aiOnLock(reason)
	s.mu.Unlock()
	closeTabs(tabs)
	if !wasLocked {
		s.opt.OnLock(reason)
	}
}

func (s *Service) lockLocked() {
	s.v.Lock()
	s.freshUntil = time.Time{}
	// Pending codes survive locking (unlock codes are sent while locked); re-verified grants do not.
	s.otp.grantOp, s.otp.grantUntil, s.otp.resetUntil, s.otp.bind = "", time.Time{}, time.Time{}, nil
	if s.csv != nil && !s.csv.imported {
		s.csv = nil // parsed CSV rows hold passwords
	}
	if !s.clipAt.IsZero() {
		s.opt.Clipboard.ClearIf(s.clipSeq)
		s.clipAt = time.Time{}
	}
}

// Touch records the person's activity in the UI; only this postpones the idle lock.
func (s *Service) Touch() {
	s.mu.Lock()
	s.lastActive = s.now()
	s.mu.Unlock()
}

// Tick runs once a second: idle lock, Windows lock, sleep detection and clipboard clearing.
func (s *Service) Tick() {
	s.mu.Lock()
	now := s.now()
	gap := now.Sub(s.lastTick)
	s.lastTick = now
	if !s.clipAt.IsZero() && !now.Before(s.clipAt) {
		s.opt.Clipboard.ClearIf(s.clipSeq)
		s.clipAt = time.Time{}
	}
	if s.restore != nil && now.Sub(s.restoreAt) > restoreLifetime {
		s.dropRestore()
	}
	// Windows lock and sleep end AI work even when the vault was already locked.
	winLocked, ok := s.opt.SessionLocked()
	winLocked = ok && winLocked
	aiReason := ""
	switch {
	case gap > sleepGap:
		aiReason = ReasonSleep
	case winLocked && !s.ai.winLocked:
		aiReason = ReasonWindows
	}
	s.ai.winLocked = winLocked
	if s.aiPausesIdle(now) {
		s.lastActive = now // the idle timer starts over when the paused grant ends
	}
	reason := ""
	if !s.v.Locked() {
		if winLocked {
			reason = ReasonWindows
		} else if gap > sleepGap {
			reason = ReasonSleep
		} else if now.Sub(s.lastActive) >= s.idle {
			reason = ReasonIdle
		}
	}
	if reason != "" {
		s.lockLocked()
	}
	var tabs []Tab
	if aiReason != "" {
		tabs = s.aiOnLock(aiReason)
	} else if reason != "" {
		tabs = s.aiOnLock(reason)
	}
	tabs = append(tabs, s.aiTick(now)...)
	s.mu.Unlock()
	closeTabs(tabs)
	if reason != "" {
		s.opt.OnLock(reason)
	}
}

// Shutdown is called when the window closes.
func (s *Service) Shutdown() {
	s.mu.Lock()
	s.lockLocked()
	tabs := s.aiOnLock(ReasonShutdown)
	s.dropRestore()
	s.v.Close()
	s.mu.Unlock()
	for _, t := range tabs {
		if t != nil {
			t.Close()
		}
	}
	if s.opt.Browser != nil {
		s.opt.Browser.Close()
	}
}

// ---------- items ----------

type Summary struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Host    string `json:"host,omitempty"`
	Alias   string `json:"alias,omitempty"`
	Account string `json:"account,omitempty"`
	AI      bool   `json:"ai"`
}

// Detail is an item without its secret.
type Detail struct {
	Summary
	URL      string `json:"url,omitempty"`
	LoginURL string `json:"loginUrl,omitempty"`
	Note     string `json:"note,omitempty"`
	GrantMin int    `json:"grantMin,omitempty"`
	Created  int64  `json:"created"`
	Updated  int64  `json:"updated"`
}

type Input struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	LoginURL string `json:"loginUrl"`
	Alias    string `json:"alias"`
	Account  string `json:"account"`
	Password string `json:"password"`
	Note     string `json:"note"`
	AI       bool   `json:"ai"`
	GrantMin int    `json:"grantMin"`
}

func summarize(it vault.Item) Summary {
	host := strings.TrimPrefix(it.Origin, "https://") // local http sites keep their scheme as a reminder
	return Summary{ID: it.ID, Type: it.Type, Name: it.Name, Host: host, Alias: it.Alias, Account: it.Account, AI: it.AI}
}

func detail(it vault.Item) Detail {
	d := Detail{Summary: summarize(it), URL: it.URL, LoginURL: it.LoginURL, GrantMin: it.GrantMin, Created: it.Created, Updated: it.Updated}
	if it.Type != vault.TypeNote {
		d.Note = it.Note // for notes the body is the secret
	}
	return d
}

// List filters by type ("" for all) and a case-insensitive query over non-secret fields.
func (s *Service) List(query, typ string) ([]Summary, error) {
	items, err := s.cur().Items()
	if err != nil {
		return nil, mapErr(err)
	}
	q := strings.ToLower(strings.TrimSpace(query))
	out := []Summary{}
	for _, it := range items {
		if typ != "" && it.Type != typ {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(strings.Join([]string{it.Name, it.Origin, it.Alias, it.Account}, " ")), q) {
			continue
		}
		out = append(out, summarize(it))
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

func (s *Service) Get(id string) (Detail, error) {
	it, err := s.cur().Item(id)
	if err != nil {
		return Detail{}, mapErr(err)
	}
	return detail(it), nil
}

func (s *Service) Save(in Input) (Detail, error) {
	s.Touch()
	v := s.cur()
	old, oldErr := v.Item(in.ID)
	it, err := v.Save(vault.Item{ID: in.ID, Type: in.Type, Name: in.Name, URL: in.URL, LoginURL: in.LoginURL, Alias: in.Alias, Account: in.Account,
		Password: in.Password, Note: in.Note, AI: in.AI, GrantMin: in.GrantMin})
	if err != nil {
		return Detail{}, mapErr(err)
	}
	// AI work was approved for a specific site, account and password; any change ends it.
	if oldErr == nil && old.AI && (!it.AI || old.Origin != it.Origin || old.LoginOrigin != it.LoginOrigin || old.Account != it.Account || old.Password != it.Password) {
		s.aiItemChanged(it.ID, it.Name, "項目已變更")
	}
	return detail(it), nil
}

func (s *Service) Delete(id string) error {
	s.Touch()
	v := s.cur()
	old, _ := v.Item(id)
	if err := v.Delete(id); err != nil {
		return mapErr(err)
	}
	s.aiItemChanged(id, old.Name, "項目已刪除")
	return nil
}

// secretFor checks the recent-verification window, or the given master password, then returns the secret.
func (s *Service) secretFor(id, master string) (vault.Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v.Locked() {
		return vault.Item{}, uerr(CodeLocked, "密碼庫已鎖定。")
	}
	now := s.now()
	s.lastActive = now
	if master != "" {
		if err := s.verifyMaster(master, false); err != nil {
			return vault.Item{}, err
		}
		s.freshUntil = now.Add(FreshWindow)
	} else if !now.Before(s.freshUntil) {
		return vault.Item{}, uerr(CodeNeedAuth, "請先確認是你本人。")
	}
	it, err := s.v.Item(id)
	if err != nil {
		return vault.Item{}, mapErr(err)
	}
	return it, nil
}

func (s *Service) Reveal(id, master string) (string, error) {
	it, err := s.secretFor(id, master)
	if err != nil {
		return "", err
	}
	return it.Secret(), nil
}

func (s *Service) Copy(id, master string) error {
	it, err := s.secretFor(id, master)
	if err != nil {
		return err
	}
	seq, err := s.opt.Clipboard.SetSecret(it.Secret())
	if err != nil {
		return uerr(CodeInternal, "無法寫入剪貼簿，請稍後再試。")
	}
	s.mu.Lock()
	s.clipSeq, s.clipAt = seq, s.now().Add(ClipboardClear)
	s.mu.Unlock()
	return nil
}

func (s *Service) ChangeMaster(current, next, confirm string) error {
	if err := checkNewMaster(next, confirm); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v.Locked() {
		return uerr(CodeLocked, "密碼庫已鎖定。")
	}
	if err := s.verifyMaster(current, false); err != nil {
		return err
	}
	if err := s.v.ChangeMaster([]byte(current), []byte(next)); err != nil {
		return internal(err)
	}
	s.freshUntil = s.now().Add(FreshWindow)
	return nil
}

var idleChoices = map[int]bool{1: true, 5: true, 15: true, 30: true}

func (s *Service) SetIdleMinutes(m int) error {
	if !idleChoices[m] {
		return uerr(CodeInvalid, "閒置時間不正確。")
	}
	if err := s.cur().UpdateSettings(func(st *vault.Settings) { st.IdleMinutes = m }); err != nil {
		return mapErr(err)
	}
	s.mu.Lock()
	s.idle = time.Duration(m) * time.Minute
	s.lastActive = s.now()
	s.mu.Unlock()
	return nil
}

const (
	lettersDigits = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	symbols       = "!@#$%^&*-_=+?"
)

// Generate returns a random password from crypto/rand.
func Generate(length int, withSymbols bool) string {
	if length < 8 {
		length = 8
	}
	if length > 128 {
		length = 128
	}
	set := lettersDigits
	if withSymbols {
		set += symbols
	}
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			panic(err)
		}
		b[i] = set[n.Int64()]
	}
	return string(b)
}

func mapErr(err error) error {
	var ve *vault.ValidationError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ve):
		return uerr(CodeInvalid, ve.Msg)
	case errors.Is(err, vault.ErrLocked):
		return uerr(CodeLocked, "密碼庫已鎖定。")
	case errors.Is(err, vault.ErrNotFound):
		return uerr(CodeNotFound, "找不到這個項目，可能已被刪除。")
	default:
		return internal(err)
	}
}

// internal hides raw errors from the UI; details may contain paths but never secrets.
func internal(err error) error {
	return uerr(CodeInternal, "發生未預期的錯誤："+err.Error())
}

// SetLanguage chooses the language of the code mails ("en" or Traditional Chinese otherwise).
// The window translates its own text; messages returned to it stay in Chinese.
func (s *Service) SetLanguage(lang string) {
	if lang != "en" {
		lang = "zh-TW"
	}
	s.lang.Store(lang)
}

func (s *Service) language() string {
	if l, ok := s.lang.Load().(string); ok {
		return l
	}
	return "zh-TW"
}
