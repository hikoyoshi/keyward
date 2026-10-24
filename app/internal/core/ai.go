package core

// AI agent login. A paired AI tool asks to log in to a site; the person approves in Keyward;
// Keyward fills the password into its own browser. The AI only ever gets page snapshots with
// password values removed, never the password itself.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hikoyoshi/keyward/internal/vault"
)

const (
	PendingTimeout = 2 * time.Minute  // unanswered requests are refused
	OnceDuration   = 15 * time.Minute // "允許這次"
	MaxGrant       = 12 * time.Hour
	MinGrant       = 15 * time.Minute
	endedKeep      = 10 * time.Minute // finished requests stay visible to get_status this long

	maxLog = 200
)

// loginSettle is how long to wait after submitting before judging the page (tests set it to 0).
var loginSettle = 3 * time.Second

// ssoReturnWait is how long a login page on another address may take to send the browser back.
var ssoReturnWait = 10 * time.Second

// Request phases, as reported to the AI.
const (
	PhasePending   = "pending_approval"
	PhaseLoggingIn = "logging_in"
	PhaseNeedsUser = "needs_user" // MFA, CAPTCHA or an unusual login page: the person finishes it in the browser
	PhaseLoggedIn  = "logged_in"
	PhaseDenied    = "denied"
	PhaseTimeout   = "timeout"
	PhaseExpired   = "expired"
	PhaseStopped   = "stopped"
	PhaseFailed    = "failed"
)

// Error codes returned to the AI.
const (
	CodeVaultLocked    = "vault_locked"
	CodeUnauthorized   = "unauthorized"
	CodeNotAllowed     = "not_allowed"
	CodeBadSession     = "bad_session"
	CodeOriginMismatch = "origin_mismatch"
	CodeSetupFailed    = "setup_failed"
	CodeNoForm         = "no_form_found"
	CodePasswordField  = "password_field"
	CodeBrowser        = "browser_error"
)

// More lock reasons, which only matter to AI work.
const (
	ReasonStopAll  = "stop_all"
	ReasonShutdown = "shutdown"
	ReasonRestore  = "restore"
)

var (
	ErrPasswordField = errors.New("password field")
	ErrStaleRef      = errors.New("element reference is from an older snapshot")
	ErrNoSuchRef     = errors.New("no element with that reference")
	ErrNotPassword   = errors.New("the password ref is not a password field")
	ErrNotTextField  = errors.New("the account ref is not a text field")
	ErrFieldOrigin   = errors.New("the field is in a frame from another origin")
)

// Browser is Keyward's own browser. Only the core talks to it; the AI never gets its debugging port.
type Browser interface {
	NewTab(ctx context.Context) (Tab, error)
	Close()
}

type Tab interface {
	Navigate(ctx context.Context, url string) error
	Origin(ctx context.Context) (string, error)
	// FillLogin types the account and password into the visible login form and submits it.
	// It returns false when no login form was found.
	FillLogin(ctx context.Context, account, password string) (bool, error)
	// FillFields types into the fields the AI pointed at (either ref may be empty) and submits.
	// The password goes only into a real password field, and only into a page or frame whose
	// origin is in origins.
	FillFields(ctx context.Context, accountRef, passwordRef, account, password string, origins []string) error
	// NeedsUser reports whether a password or one-time-code field is still showing.
	NeedsUser(ctx context.Context) (bool, error)
	Snapshot(ctx context.Context) (Snapshot, error)
	Click(ctx context.Context, ref string) error
	Type(ctx context.Context, ref, text string) error
	Close()
}

// Snapshot is what the AI sees of a page. Field values of password inputs are never included.
type Snapshot struct {
	URL      string    `json:"url"`
	Title    string    `json:"title"`
	Text     string    `json:"text"`
	Elements []Element `json:"elements"`
}

type Element struct {
	Ref   string `json:"ref"`
	Role  string `json:"role"`
	Name  string `json:"name,omitempty"`
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

type aiGrant struct {
	ClientID, ItemID string
	Until            time.Time
	KeepOnWinLock    bool
	PauseIdle        bool
}

type aiSession struct {
	ID, ClientID, ClientName, ItemID, ItemName, Origin string
	Phase                                              string
	Note                                               string // shown in Keyward, in Chinese
	Created, Expires, Ended                            time.Time
	GrantKey                                           string
	tab                                                Tab
	secret                                             string // the password, kept only to redact snapshots
	changed                                            chan struct{}
}

type AILogEntry struct {
	Time   int64  `json:"time"`
	Client string `json:"client"`
	Site   string `json:"site"`
	Action string `json:"action"`
	Result string `json:"result"`
}

type aiState struct {
	clients   []vault.AIClient // loaded at unlock and kept while locked, so running work can still authenticate
	sessions  map[string]*aiSession
	grants    map[string]*aiGrant
	log       []AILogEntry
	winLocked bool
}

func newAI() aiState {
	return aiState{sessions: map[string]*aiSession{}, grants: map[string]*aiGrant{}}
}

func grantKey(clientID, itemID string) string { return clientID + "|" + itemID }

func active(phase string) bool {
	return phase == PhasePending || phase == PhaseLoggingIn || phase == PhaseNeedsUser || phase == PhaseLoggedIn
}

func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *Service) notifyAI(kind string) {
	if s.opt.OnAIEvent != nil {
		go s.opt.OnAIEvent(kind)
	}
}

// aiLog records what happened, never secrets. Caller holds s.mu.
func (s *Service) aiLog(client, site, action, result string) {
	s.ai.log = append(s.ai.log, AILogEntry{Time: s.now().Unix(), Client: client, Site: site, Action: action, Result: result})
	if len(s.ai.log) > maxLog {
		s.ai.log = s.ai.log[len(s.ai.log)-maxLog:]
	}
}

// setPhase changes a session's phase and wakes anyone waiting on it. Caller holds s.mu.
func (s *Service) setPhase(x *aiSession, phase, note string) {
	x.Phase, x.Note = phase, note
	if !active(phase) && x.Ended.IsZero() {
		x.Ended = s.now()
		x.secret = ""
	}
	close(x.changed)
	x.changed = make(chan struct{})
}

// endSession stops a session and returns its tab for the caller to close outside the lock. Caller holds s.mu.
func (s *Service) endSession(x *aiSession, phase, note string) Tab {
	if !active(x.Phase) {
		return nil
	}
	s.setPhase(x, phase, note)
	t := x.tab
	x.tab = nil
	return t
}

func closeTabs(tabs []Tab) {
	for _, t := range tabs {
		if t != nil {
			go t.Close()
		}
	}
}

// ---------- pairing ----------

type AIPairing struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Token string `json:"token"` // shown once; only its hash is stored
}

type AIClientInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Created int64  `json:"created"`
}

func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte("passpw/ai-token/v1|" + token))
	return h[:]
}

// AIAddClient pairs a new AI tool and returns its token once.
func (s *Service) AIAddClient(name string) (AIPairing, error) {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 40 {
		return AIPairing{}, uerr(CodeInvalid, "請輸入 1–40 字的名稱。")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return AIPairing{}, internal(err)
	}
	p := AIPairing{ID: randomID(8), Name: name, Token: "kw_" + base64.RawURLEncoding.EncodeToString(raw)}
	c := vault.AIClient{ID: p.ID, Name: name, TokenHash: tokenHash(p.Token), Created: s.now().Unix()}
	v := s.cur()
	if err := v.UpdateSettings(func(st *vault.Settings) { st.AIClients = append(st.AIClients, c) }); err != nil {
		return AIPairing{}, mapErr(err)
	}
	s.mu.Lock()
	s.reloadClients()
	s.aiLog(name, "", "新增 AI 連線", "完成")
	s.mu.Unlock()
	s.notifyAI("clients")
	return p, nil
}

// AIRevokeClient removes a paired tool and stops its work.
func (s *Service) AIRevokeClient(id string) error {
	v := s.cur()
	if err := v.UpdateSettings(func(st *vault.Settings) {
		kept := st.AIClients[:0]
		for _, c := range st.AIClients {
			if c.ID != id {
				kept = append(kept, c)
			}
		}
		st.AIClients = kept
	}); err != nil {
		return mapErr(err)
	}
	s.mu.Lock()
	var tabs []Tab
	name := ""
	for _, c := range s.ai.clients {
		if c.ID == id {
			name = c.Name
		}
	}
	for _, x := range s.ai.sessions {
		if x.ClientID == id {
			tabs = append(tabs, s.endSession(x, PhaseStopped, "AI 連線已撤銷"))
		}
	}
	for k, g := range s.ai.grants {
		if g.ClientID == id {
			delete(s.ai.grants, k)
		}
	}
	s.reloadClients()
	s.aiLog(name, "", "撤銷 AI 連線", "相關工作已停止")
	s.mu.Unlock()
	closeTabs(tabs)
	s.notifyAI("clients")
	return nil
}

// reloadClients copies the paired tools from settings. Caller holds s.mu; the vault must be unlocked.
func (s *Service) reloadClients() {
	if st, err := s.v.Settings(); err == nil {
		s.ai.clients = append([]vault.AIClient(nil), st.AIClients...)
	}
}

// AuthClient maps a token to a paired tool. Before the first unlock nothing is paired as far as Keyward knows.
func (s *Service) AuthClient(token string) (id, name string, err error) {
	h := tokenHash(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.ai.clients {
		if subtle.ConstantTimeCompare(h, c.TokenHash) == 1 {
			return c.ID, c.Name, nil
		}
	}
	if s.v.Locked() && len(s.ai.clients) == 0 {
		return "", "", uerr(CodeVaultLocked, "Keyward is locked. Ask the user to unlock it.")
	}
	return "", "", uerr(CodeUnauthorized, "This AI connection is not paired with Keyward or was revoked.")
}

// ---------- AI-facing calls ----------

type AILogin struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Site             string `json:"site"`
	AccountAlias     string `json:"account_alias"`
	RequiresApproval bool   `json:"requires_approval"`
}

func (s *Service) AIListLogins(clientID string) ([]AILogin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v.Locked() {
		return nil, uerr(CodeVaultLocked, "Keyward is locked. Ask the user to unlock it.")
	}
	items, err := s.v.Items()
	if err != nil {
		return nil, mapErr(err)
	}
	now := s.now()
	out := []AILogin{}
	for _, it := range items {
		if it.Type != vault.TypeLogin || !it.AI {
			continue
		}
		g := s.ai.grants[grantKey(clientID, it.ID)]
		out = append(out, AILogin{ID: it.ID, Name: it.Name, Site: it.Origin, AccountAlias: it.Alias, RequiresApproval: g == nil || !now.Before(g.Until)})
	}
	return out, nil
}

type AIRequestResult struct {
	RequestID        string `json:"request_id"`
	Status           string `json:"status"`
	Site             string `json:"site"`
	ExpiresInSeconds int    `json:"expires_in_seconds,omitempty"`
	Message          string `json:"message"`
	Note             string `json:"note,omitempty"` // what Keyward told the user, e.g. why it needs them
}

var aiMessages = map[string]string{
	PhasePending:   "Waiting for the user to approve in Keyward (up to 2 minutes). Call get_status with this request_id to wait for the decision.",
	PhaseLoggingIn: "Approved. Keyward is filling in the login in its own browser. Call get_status to wait.",
	PhaseNeedsUser: "The login is not finished. If note says the form was not found, take a snapshot and call fill_credentials with account_ref and password_ref. For MFA or CAPTCHA the user finishes it in the Keyward browser window; call get_status to wait.",
	PhaseLoggedIn:  "Logged in. Use snapshot, click, type and navigate with this request_id. You never receive the password.",
	PhaseDenied:    "The user denied this request.",
	PhaseTimeout:   "The user did not answer within 2 minutes.",
	PhaseExpired:   "The approval period ended. Request a new login if you still need the site.",
	PhaseStopped:   "Stopped by the user or because Keyward was locked.",
	PhaseFailed:    "The login could not be completed.",
}

func (s *Service) result(x *aiSession) AIRequestResult {
	r := AIRequestResult{RequestID: x.ID, Status: x.Phase, Site: x.Origin, Message: aiMessages[x.Phase]}
	if x.Phase == PhaseNeedsUser || x.Phase == PhaseFailed {
		r.Note = x.Note
	}
	if x.Phase == PhaseLoggedIn || x.Phase == PhaseNeedsUser || x.Phase == PhaseLoggingIn {
		if left := x.Expires.Sub(s.now()); left > 0 {
			r.ExpiresInSeconds = int(left / time.Second)
		}
	}
	return r
}

// AIRequestLogin asks for a login and waits up to wait for the outcome.
func (s *Service) AIRequestLogin(ctx context.Context, clientID, itemID string, wait time.Duration) (AIRequestResult, error) {
	s.mu.Lock()
	if s.v.Locked() {
		s.mu.Unlock()
		return AIRequestResult{}, uerr(CodeVaultLocked, "Keyward is locked. Ask the user to unlock it.")
	}
	it, err := s.v.Item(itemID)
	if err != nil || it.Type != vault.TypeLogin || !it.AI {
		s.mu.Unlock()
		return AIRequestResult{}, uerr(CodeNotAllowed, "This item does not exist or is not open to AI login. Use list_logins.")
	}
	clientName := s.clientName(clientID)
	for _, x := range s.ai.sessions {
		if x.ClientID == clientID && x.ItemID == itemID && active(x.Phase) {
			s.mu.Unlock()
			return s.waitResult(ctx, x, wait), nil
		}
	}
	now := s.now()
	x := &aiSession{ID: randomID(8), ClientID: clientID, ClientName: clientName, ItemID: it.ID, ItemName: it.Name, Origin: it.Origin,
		Phase: PhasePending, Created: now, changed: make(chan struct{})}
	s.ai.sessions[x.ID] = x
	if g := s.ai.grants[grantKey(clientID, itemID)]; g != nil && now.Before(g.Until) {
		x.Phase, x.Expires, x.GrantKey = PhaseLoggingIn, g.Until, grantKey(clientID, itemID)
		s.aiLog(clientName, it.Name, "要求登入", "網站授權內自動允許")
		go s.doLogin(x.ID)
	} else {
		x.Note = "等待你的核准"
		s.aiLog(clientName, it.Name, "要求登入", "等待核准")
		s.notifyAI("request")
	}
	s.mu.Unlock()
	return s.waitResult(ctx, x, wait), nil
}

func (s *Service) clientName(id string) string {
	for _, c := range s.ai.clients {
		if c.ID == id {
			return c.Name
		}
	}
	return "AI"
}

// AIGetStatus reports a request's state, waiting up to wait while it is still moving.
func (s *Service) AIGetStatus(ctx context.Context, clientID, reqID string, wait time.Duration) (AIRequestResult, error) {
	x, err := s.ownSession(clientID, reqID)
	if err != nil {
		return AIRequestResult{}, err
	}
	s.recheckNeedsUser(ctx, x)
	return s.waitResult(ctx, x, wait), nil
}

func (s *Service) ownSession(clientID, reqID string) (*aiSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := s.ai.sessions[reqID]
	if x == nil || x.ClientID != clientID {
		return nil, uerr(CodeBadSession, "Unknown request_id. Use request_login first.")
	}
	return x, nil
}

func (s *Service) waitResult(ctx context.Context, x *aiSession, wait time.Duration) AIRequestResult {
	s.mu.Lock()
	ch, phase := x.changed, x.Phase
	s.mu.Unlock()
	if phase == PhasePending || phase == PhaseLoggingIn || phase == PhaseNeedsUser {
		t := time.NewTimer(wait)
		select {
		case <-ch:
		case <-t.C:
		case <-ctx.Done():
		}
		t.Stop()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.result(x)
}

// recheckNeedsUser moves a session to logged_in once the person has finished signing in.
func (s *Service) recheckNeedsUser(ctx context.Context, x *aiSession) {
	s.mu.Lock()
	tab, origin := x.tab, x.Origin
	if x.Phase != PhaseNeedsUser || tab == nil {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	cur, err1 := tab.Origin(ctx)
	needs, err2 := tab.NeedsUser(ctx)
	if err1 != nil || err2 != nil || cur != origin || needs {
		return
	}
	s.mu.Lock()
	if x.Phase == PhaseNeedsUser {
		s.setPhase(x, PhaseLoggedIn, "已登入，AI 工作中")
		s.aiLog(x.ClientName, x.ItemName, "登入完成", "logged_in")
	}
	s.mu.Unlock()
	s.notifyAI("session")
}

// loggedIn returns the session's tab when it may be operated by the AI: once logged in, and also
// while the login waits on the person, so the AI can point Keyward at a form it did not recognize.
func (s *Service) loggedIn(clientID, reqID string) (*aiSession, Tab, error) {
	x, err := s.ownSession(clientID, reqID)
	if err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if (x.Phase != PhaseLoggedIn && x.Phase != PhaseNeedsUser) || x.tab == nil {
		return nil, nil, uerr(CodeBadSession, "This request is not logged in (status: "+x.Phase+").")
	}
	return x, x.tab, nil
}

func (s *Service) AISnapshot(ctx context.Context, clientID, reqID string) (Snapshot, error) {
	x, tab, err := s.loggedIn(clientID, reqID)
	if err != nil {
		return Snapshot{}, err
	}
	snap, err := tab.Snapshot(ctx)
	if err != nil {
		return Snapshot{}, uerr(CodeBrowser, "Could not read the page.")
	}
	s.mu.Lock()
	secret := x.secret
	s.mu.Unlock()
	return redact(snap, secret), nil
}

// redact removes the stored password wherever it appears, e.g. after a site's "show password" button.
func redact(snap Snapshot, secret string) Snapshot {
	if secret == "" {
		return snap
	}
	const mask = "●●●"
	r := func(v string) string { return strings.ReplaceAll(v, secret, mask) }
	snap.URL, snap.Title, snap.Text = r(snap.URL), r(snap.Title), r(snap.Text)
	for i := range snap.Elements {
		e := &snap.Elements[i]
		e.Name, e.Value = r(e.Name), r(e.Value)
	}
	return snap
}

func (s *Service) AIClick(ctx context.Context, clientID, reqID, ref string) error {
	x, tab, err := s.loggedIn(clientID, reqID)
	if err != nil {
		return err
	}
	if err := tab.Click(ctx, ref); err != nil {
		return refErr(err)
	}
	_ = x
	return nil
}

func (s *Service) AIType(ctx context.Context, clientID, reqID, ref, text string) error {
	x, tab, err := s.loggedIn(clientID, reqID)
	if err != nil {
		return err
	}
	if err := tab.Type(ctx, ref, text); err != nil {
		if errors.Is(err, ErrPasswordField) {
			s.mu.Lock()
			s.aiLog(x.ClientName, x.ItemName, "在密碼欄位輸入", "已拒絕")
			s.mu.Unlock()
			return uerr(CodePasswordField, "Typing into password fields is not allowed. Use fill_credentials on the site's own login page.")
		}
		return refErr(err)
	}
	return nil
}

func refErr(err error) error {
	switch {
	case errors.Is(err, ErrStaleRef), errors.Is(err, ErrNoSuchRef):
		return uerr(CodeBadSession, "That element reference is no longer valid. Take a new snapshot.")
	default:
		return uerr(CodeBrowser, "The browser action failed.")
	}
}

func (s *Service) AINavigate(ctx context.Context, clientID, reqID, raw string) error {
	_, tab, err := s.loggedIn(clientID, reqID)
	if err != nil {
		return err
	}
	u, perr := url.Parse(strings.TrimSpace(raw))
	if perr != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return uerr(CodeInvalid, "Only absolute http or https URLs can be opened.")
	}
	if err := tab.Navigate(ctx, u.String()); err != nil {
		return uerr(CodeBrowser, "Could not open that page.")
	}
	return nil
}

// AIFillCredentials enters the login on the current page, only if it belongs to the item's exact origin
// (or its login page). With refs, the AI chooses the fields; Keyward still does the typing.
func (s *Service) AIFillCredentials(ctx context.Context, clientID, reqID, accountRef, passwordRef string) (string, error) {
	x, tab, err := s.loggedIn(clientID, reqID)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	if s.v.Locked() {
		s.aiLog(x.ClientName, x.ItemName, "要求填入帳密", "vault_locked")
		s.mu.Unlock()
		return "", uerr(CodeVaultLocked, "Keyward is locked, so it cannot fill the login now. Ask the user to unlock it.")
	}
	it, ierr := s.v.Item(x.ItemID)
	s.mu.Unlock()
	if ierr != nil || !it.AI {
		return "", uerr(CodeNotAllowed, "This item is no longer open to AI login.")
	}
	origin, err := tab.Origin(ctx)
	if err != nil {
		return "", uerr(CodeBrowser, "Could not read the page address.")
	}
	if !fillOrigin(it, origin) {
		s.mu.Lock()
		s.aiLog(x.ClientName, x.ItemName, "要求填入帳密（"+origin+"）", "origin_mismatch")
		s.mu.Unlock()
		return "", uerr(CodeOriginMismatch, "The current page ("+origin+") is not "+fillOrigins(it)+"; Keyward only fills the login there. If this is the site's own sign-in page, ask the user to set it as the item's login page address in Keyward.")
	}
	if accountRef != "" || passwordRef != "" {
		err := tab.FillFields(ctx, accountRef, passwordRef, it.Account, it.Password, fillOriginList(it))
		result := "filled"
		switch {
		case err == nil:
		case errors.Is(err, ErrNotPassword):
			result, err = "not_password_field", uerr(CodeInvalid, "password_ref must be a password input. Take a new snapshot and pick the field with type password.")
		case errors.Is(err, ErrNotTextField):
			result, err = "not_text_field", uerr(CodeInvalid, "account_ref must be a text, email or tel input that is not a password field.")
		case errors.Is(err, ErrFieldOrigin):
			result, err = "origin_mismatch", uerr(CodeOriginMismatch, "That field is in a frame from another address; Keyward only fills "+fillOrigins(it)+".")
		default:
			result, err = "error", refErr(err)
		}
		s.mu.Lock()
		if err == nil {
			x.secret = it.Password
		}
		s.aiLog(x.ClientName, x.ItemName, "要求填入指定欄位", result)
		s.mu.Unlock()
		if err != nil {
			return "", err
		}
		return "filled", nil
	}
	ok, err := tab.FillLogin(ctx, it.Account, it.Password)
	if err != nil {
		return "", uerr(CodeBrowser, "Filling the login failed.")
	}
	s.mu.Lock()
	x.secret = it.Password
	result := "filled"
	if !ok {
		result = "no_form_found"
	}
	s.aiLog(x.ClientName, x.ItemName, "要求填入帳密", result)
	s.mu.Unlock()
	if !ok {
		return "", uerr(CodeNoForm, "No login form was found on this page.")
	}
	return "filled", nil
}

func (s *Service) AIClose(clientID, reqID string) error {
	x, err := s.ownSession(clientID, reqID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	tab := s.endSession(x, PhaseStopped, "AI 已結束工作")
	if tab != nil {
		s.aiLog(x.ClientName, x.ItemName, "結束工作", "已關閉")
	}
	s.mu.Unlock()
	closeTabs([]Tab{tab})
	s.notifyAI("session")
	return nil
}

// doLogin opens the site in Keyward's browser and fills the login.
func (s *Service) doLogin(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s.mu.Lock()
	x := s.ai.sessions[id]
	if x == nil || x.Phase != PhaseLoggingIn {
		s.mu.Unlock()
		return
	}
	if s.v.Locked() {
		s.setPhase(x, PhaseStopped, "密碼庫已鎖定，登入取消")
		s.mu.Unlock()
		return
	}
	it, err := s.v.Item(x.ItemID)
	browser := s.opt.Browser
	s.mu.Unlock()
	fail := func(phase, note string, tab Tab) {
		s.mu.Lock()
		if active(x.Phase) {
			s.setPhase(x, phase, note)
			s.aiLog(x.ClientName, x.ItemName, "登入", note)
		}
		s.mu.Unlock()
		if tab != nil {
			tab.Close()
		}
		s.notifyAI("session")
	}
	if err != nil {
		fail(PhaseFailed, "項目已不存在", nil)
		return
	}
	if browser == nil {
		fail(PhaseFailed, "找不到 Google Chrome（AI 代理登入需要 Chrome）", nil)
		return
	}
	tab, err := browser.NewTab(ctx)
	if err != nil {
		fail(PhaseFailed, "無法開啟專用瀏覽器", nil)
		return
	}
	s.mu.Lock()
	if x.Phase != PhaseLoggingIn { // stopped while the browser was starting
		s.mu.Unlock()
		tab.Close()
		return
	}
	x.tab = tab
	s.mu.Unlock()

	if err := tab.Navigate(ctx, it.URL); err != nil {
		fail(PhaseFailed, "無法開啟登入頁", nil)
		s.closeSessionTab(x)
		return
	}
	note := ""
	if origin, err := tab.Origin(ctx); err != nil || !fillOrigin(it, origin) {
		note = "登入頁跳到其它網址（" + origin + "），Keyward 不在那裡填入密碼；請在專用瀏覽器自行登入。若這是網站的單一登入頁，可在項目的「登入頁網址」填入它"
	} else if ok, err := tab.FillLogin(ctx, it.Account, it.Password); err != nil || !ok {
		note = "找不到登入欄位，請在專用瀏覽器自行登入"
	} else {
		time.Sleep(loginSettle)
		// Single sign-on bounces back to the site after the form; give it a moment.
		cur, err := tab.Origin(ctx)
		for end := time.Now().Add(ssoReturnWait); err == nil && cur != it.Origin && cur == it.LoginOrigin && time.Now().Before(end); {
			time.Sleep(250 * time.Millisecond)
			cur, err = tab.Origin(ctx)
		}
		if needs, err2 := tab.NeedsUser(ctx); err2 != nil || needs {
			note = "需要你在專用瀏覽器完成網站驗證（例如簡訊碼、驗證器或 CAPTCHA）"
		} else if err != nil || cur != it.Origin {
			note = "送出後停在其它網址（" + cur + "），請在專用瀏覽器確認是否已登入"
		}
	}
	s.mu.Lock()
	if x.Phase == PhaseLoggingIn {
		x.secret = it.Password
		if note != "" {
			s.setPhase(x, PhaseNeedsUser, note)
			s.aiLog(x.ClientName, x.ItemName, "登入", "等待本人完成驗證")
		} else {
			s.setPhase(x, PhaseLoggedIn, "已登入，AI 工作中")
			s.aiLog(x.ClientName, x.ItemName, "登入", "logged_in")
		}
	}
	s.mu.Unlock()
	s.notifyAI("session")
}

// fillOrigin reports whether Keyward may fill the item's login on a page from origin.
func fillOrigin(it vault.Item, origin string) bool {
	return origin != "" && (origin == it.Origin || origin == it.LoginOrigin)
}

func fillOriginList(it vault.Item) []string {
	if it.LoginOrigin != "" {
		return []string{it.Origin, it.LoginOrigin}
	}
	return []string{it.Origin}
}

func fillOrigins(it vault.Item) string {
	if it.LoginOrigin != "" {
		return it.Origin + " or " + it.LoginOrigin
	}
	return it.Origin
}

func (s *Service) closeSessionTab(x *aiSession) {
	s.mu.Lock()
	t := x.tab
	x.tab = nil
	s.mu.Unlock()
	if t != nil {
		t.Close()
	}
}

// ---------- the person's side (Keyward window) ----------

type AIRequestView struct {
	ID       string `json:"id"`
	Client   string `json:"client"`
	ItemID   string `json:"itemId"`
	Site     string `json:"site"`
	Name     string `json:"name"`
	Alias    string `json:"alias"`
	GrantMin int    `json:"grantMin"`
	Created  int64  `json:"created"`
	Left     int    `json:"left"` // seconds until it times out
}

type AISessionView struct {
	ID        string `json:"id"`
	Client    string `json:"client"`
	Name      string `json:"name"`
	Site      string `json:"site"`
	Phase     string `json:"phase"`
	Note      string `json:"note"`
	Expires   int64  `json:"expires"`
	GrantKey  string `json:"grantKey,omitempty"`
	KeepOnWin bool   `json:"keepOnWin"`
	PauseIdle bool   `json:"pauseIdle"`
}

type AIGrantView struct {
	Key       string `json:"key"`
	Client    string `json:"client"`
	Name      string `json:"name"`
	Until     int64  `json:"until"`
	KeepOnWin bool   `json:"keepOnWin"`
	PauseIdle bool   `json:"pauseIdle"`
}

type AIOverview struct {
	Browser    bool            `json:"browser"`
	Pending    []AIRequestView `json:"pending"`
	Sessions   []AISessionView `json:"sessions"`
	Grants     []AIGrantView   `json:"grants"`
	Clients    []AIClientInfo  `json:"clients"`
	Log        []AILogEntry    `json:"log"`
	PausesIdle bool            `json:"pausesIdle"`
}

func (s *Service) AIOverview() (AIOverview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v.Locked() {
		return AIOverview{}, uerr(CodeLocked, "密碼庫已鎖定。")
	}
	now := s.now()
	o := AIOverview{Browser: s.opt.Browser != nil, Pending: []AIRequestView{}, Sessions: []AISessionView{}, Grants: []AIGrantView{}, Clients: []AIClientInfo{}, Log: []AILogEntry{}, PausesIdle: s.aiPausesIdle(now)}
	for _, x := range s.ai.sessions {
		if x.Phase == PhasePending {
			v := AIRequestView{ID: x.ID, Client: x.ClientName, ItemID: x.ItemID, Site: x.Origin, Name: x.ItemName, Created: x.Created.Unix(),
				Left: int((PendingTimeout - now.Sub(x.Created)) / time.Second)}
			if it, err := s.v.Item(x.ItemID); err == nil {
				v.Alias, v.GrantMin = it.Alias, it.GrantMin
			}
			o.Pending = append(o.Pending, v)
		} else if active(x.Phase) {
			v := AISessionView{ID: x.ID, Client: x.ClientName, Name: x.ItemName, Site: x.Origin, Phase: x.Phase, Note: x.Note, Expires: x.Expires.Unix(), GrantKey: x.GrantKey}
			if g := s.ai.grants[x.GrantKey]; g != nil {
				v.KeepOnWin, v.PauseIdle = g.KeepOnWinLock, g.PauseIdle
			}
			o.Sessions = append(o.Sessions, v)
		}
	}
	for k, g := range s.ai.grants {
		if now.Before(g.Until) {
			name := g.ItemID
			if it, err := s.v.Item(g.ItemID); err == nil {
				name = it.Name
			}
			o.Grants = append(o.Grants, AIGrantView{Key: k, Client: s.clientName(g.ClientID), Name: name, Until: g.Until.Unix(), KeepOnWin: g.KeepOnWinLock, PauseIdle: g.PauseIdle})
		}
	}
	for _, c := range s.ai.clients {
		o.Clients = append(o.Clients, AIClientInfo{ID: c.ID, Name: c.Name, Created: c.Created})
	}
	for i := len(s.ai.log) - 1; i >= 0; i-- {
		o.Log = append(o.Log, s.ai.log[i])
	}
	sort.Slice(o.Pending, func(i, j int) bool { return o.Pending[i].Created < o.Pending[j].Created })
	sort.Slice(o.Sessions, func(i, j int) bool { return o.Sessions[i].Expires < o.Sessions[j].Expires })
	sort.Slice(o.Grants, func(i, j int) bool { return o.Grants[i].Until < o.Grants[j].Until })
	return o, nil
}

type AIApproval struct {
	Mode          string `json:"mode"` // "once" or "site"
	Minutes       int    `json:"minutes"`
	KeepOnWinLock bool   `json:"keepOnWinLock"`
	PauseIdle     bool   `json:"pauseIdle"`
}

func (s *Service) AIApprove(reqID string, a AIApproval) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v.Locked() {
		return uerr(CodeLocked, "密碼庫已鎖定。")
	}
	x := s.ai.sessions[reqID]
	if x == nil || x.Phase != PhasePending {
		return uerr(CodeNotFound, "這個要求已結束或不存在。")
	}
	now := s.now()
	s.lastActive = now
	switch a.Mode {
	case "once":
		x.Expires = now.Add(OnceDuration)
		s.aiLog(x.ClientName, x.ItemName, "核准登入", "這次 15 分鐘")
	case "site":
		d := time.Duration(a.Minutes) * time.Minute
		if d < MinGrant || d > MaxGrant {
			return uerr(CodeInvalid, "授權時間需在 15 分鐘到 12 小時之間。")
		}
		k := grantKey(x.ClientID, x.ItemID)
		s.ai.grants[k] = &aiGrant{ClientID: x.ClientID, ItemID: x.ItemID, Until: now.Add(d), KeepOnWinLock: a.KeepOnWinLock, PauseIdle: a.PauseIdle}
		x.Expires, x.GrantKey = now.Add(d), k
		opts := ""
		if a.KeepOnWinLock {
			opts += "，Windows 鎖定時保留"
		}
		if a.PauseIdle {
			opts += "，暫停閒置鎖定"
		}
		s.aiLog(x.ClientName, x.ItemName, "核准登入", "此網站 "+itoaMinutes(a.Minutes)+opts)
	default:
		return uerr(CodeInvalid, "核准方式不正確。")
	}
	s.setPhase(x, PhaseLoggingIn, "Keyward 正在填入帳密並登入")
	go s.doLogin(x.ID)
	s.notifyAI("session")
	return nil
}

func itoaMinutes(m int) string {
	if m%60 == 0 {
		return strconv.Itoa(m/60) + " 小時"
	}
	return strconv.Itoa(m) + " 分鐘"
}

func (s *Service) AIDeny(reqID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := s.ai.sessions[reqID]
	if x == nil || x.Phase != PhasePending {
		return uerr(CodeNotFound, "這個要求已結束或不存在。")
	}
	s.setPhase(x, PhaseDenied, "已拒絕")
	s.aiLog(x.ClientName, x.ItemName, "拒絕登入", "denied")
	s.notifyAI("session")
	return nil
}

// AIStop ends one session from the Keyward window.
func (s *Service) AIStop(id string) error {
	s.mu.Lock()
	x := s.ai.sessions[id]
	if x == nil {
		s.mu.Unlock()
		return uerr(CodeNotFound, "這個工作已結束。")
	}
	tab := s.endSession(x, PhaseStopped, "已由你停止")
	s.aiLog(x.ClientName, x.ItemName, "停止 AI 工作", "已停止")
	s.mu.Unlock()
	closeTabs([]Tab{tab})
	s.notifyAI("session")
	return nil
}

// AIUserDone marks a needs_user session as logged in after the person finished in the browser.
func (s *Service) AIUserDone(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := s.ai.sessions[id]
	if x == nil || x.Phase != PhaseNeedsUser {
		return uerr(CodeNotFound, "這個工作不在等待你完成驗證。")
	}
	s.setPhase(x, PhaseLoggedIn, "已登入，AI 工作中")
	s.aiLog(x.ClientName, x.ItemName, "本人完成網站驗證", "logged_in")
	s.notifyAI("session")
	return nil
}

// AIExtendGrant adds time after the current end, never more than MaxGrant from now.
func (s *Service) AIExtendGrant(key string, minutes int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v.Locked() {
		return uerr(CodeLocked, "密碼庫已鎖定。")
	}
	g := s.ai.grants[key]
	now := s.now()
	if g == nil || !now.Before(g.Until) {
		return uerr(CodeNotFound, "這個網站授權已結束。")
	}
	d := time.Duration(minutes) * time.Minute
	if d < MinGrant || d > MaxGrant {
		return uerr(CodeInvalid, "延長時間需在 15 分鐘到 12 小時之間。")
	}
	until := g.Until.Add(d)
	if limit := now.Add(MaxGrant); until.After(limit) {
		until = limit
	}
	g.Until = until
	for _, x := range s.ai.sessions {
		if x.GrantKey == key && active(x.Phase) {
			x.Expires = until
		}
	}
	s.aiLog(s.clientName(g.ClientID), g.ItemID, "延長網站授權", "到 "+until.Local().Format("15:04"))
	s.notifyAI("session")
	return nil
}

func (s *Service) AIRevokeGrant(key string) error {
	s.mu.Lock()
	g := s.ai.grants[key]
	if g == nil {
		s.mu.Unlock()
		return uerr(CodeNotFound, "這個網站授權已結束。")
	}
	delete(s.ai.grants, key)
	var tabs []Tab
	for _, x := range s.ai.sessions {
		if x.GrantKey == key {
			tabs = append(tabs, s.endSession(x, PhaseStopped, "網站授權已撤銷"))
		}
	}
	s.aiLog(s.clientName(g.ClientID), g.ItemID, "撤銷網站授權", "相關工作已停止")
	s.mu.Unlock()
	closeTabs(tabs)
	s.notifyAI("session")
	return nil
}

// ---------- rules tied to locking ----------

// aiOnLock applies what each kind of lock means for AI work and returns tabs to close. Caller holds s.mu.
//   - idle / manual: logged-in work continues; requests and unfinished logins are cancelled.
//   - Windows lock: only logged-in work on grants marked "keep on Windows lock" continues.
//   - sleep, "lock all and stop", shutdown, restore: everything stops.
func (s *Service) aiOnLock(reason string) []Tab {
	var tabs []Tab
	keep := map[string]bool{}
	for _, x := range s.ai.sessions {
		if !active(x.Phase) {
			continue
		}
		switch reason {
		case ReasonIdle, ReasonManual:
			if x.Phase != PhaseLoggedIn {
				tabs = append(tabs, s.endSession(x, PhaseStopped, "密碼庫已鎖定"))
			}
		case ReasonWindows:
			g := s.ai.grants[x.GrantKey]
			if x.Phase == PhaseLoggedIn && g != nil && g.KeepOnWinLock && s.now().Before(g.Until) {
				keep[x.GrantKey] = true
			} else {
				tabs = append(tabs, s.endSession(x, PhaseStopped, "Windows 已鎖定"))
			}
		default:
			tabs = append(tabs, s.endSession(x, PhaseStopped, "全部停止"))
		}
	}
	switch reason {
	case ReasonIdle, ReasonManual:
	case ReasonWindows:
		for k := range s.ai.grants {
			if !keep[k] {
				delete(s.ai.grants, k)
			}
		}
	default:
		s.ai.grants = map[string]*aiGrant{}
	}
	if len(tabs) > 0 {
		s.aiLog("", "", "鎖定："+reasonLabel(reason), "已停止 "+strconv.Itoa(len(tabs))+" 個工作")
		s.notifyAI("session")
	}
	return tabs
}

func reasonLabel(r string) string {
	return map[string]string{ReasonIdle: "閒置", ReasonManual: "手動鎖定", ReasonWindows: "Windows 鎖定", ReasonSleep: "休眠",
		ReasonStopAll: "全部鎖定並停止", ReasonShutdown: "關閉程式", ReasonRestore: "從備份還原"}[r]
}

// aiPausesIdle: a grant marked "pause idle lock" with logged-in work keeps the vault unlocked. Caller holds s.mu.
func (s *Service) aiPausesIdle(now time.Time) bool {
	for _, x := range s.ai.sessions {
		if x.Phase != PhaseLoggedIn {
			continue
		}
		if g := s.ai.grants[x.GrantKey]; g != nil && g.PauseIdle && now.Before(g.Until) {
			return true
		}
	}
	return false
}

// aiTick handles timeouts and expiry. Caller holds s.mu; returns tabs to close.
func (s *Service) aiTick(now time.Time) []Tab {
	var tabs []Tab
	changed := false
	for id, x := range s.ai.sessions {
		switch {
		case x.Phase == PhasePending && now.Sub(x.Created) >= PendingTimeout:
			s.setPhase(x, PhaseTimeout, "逾時未回應")
			s.aiLog(x.ClientName, x.ItemName, "登入要求", "逾時自動拒絕")
			changed = true
		case active(x.Phase) && x.Phase != PhasePending && !x.Expires.IsZero() && !now.Before(x.Expires):
			tabs = append(tabs, s.endSession(x, PhaseExpired, "授權到期"))
			s.aiLog(x.ClientName, x.ItemName, "AI 工作", "授權到期")
			changed = true
		case !active(x.Phase) && now.Sub(x.Ended) > endedKeep:
			delete(s.ai.sessions, id)
		}
	}
	for k, g := range s.ai.grants {
		if !now.Before(g.Until) {
			delete(s.ai.grants, k)
			changed = true
		}
	}
	if changed {
		s.notifyAI("session")
	}
	return tabs
}

// aiItemChanged stops AI work on an item whose site, account or password changed, or that was closed to AI.
func (s *Service) aiItemChanged(itemID, name, why string) {
	s.mu.Lock()
	var tabs []Tab
	for _, x := range s.ai.sessions {
		if x.ItemID == itemID {
			tabs = append(tabs, s.endSession(x, PhaseStopped, why))
		}
	}
	for k, g := range s.ai.grants {
		if g.ItemID == itemID {
			delete(s.ai.grants, k)
		}
	}
	if len(tabs) > 0 {
		s.aiLog("", name, "停止相關 AI 工作", why)
	}
	s.mu.Unlock()
	closeTabs(tabs)
	s.notifyAI("session")
}

// AIAutoPair pairs name and lets configure write the new token into the AI tool's own settings.
// If configure fails, the new pairing is revoked again. If it succeeds, older pairings with the same
// name are revoked: the tool now holds only the new token. It returns how many were replaced.
func (s *Service) AIAutoPair(name string, configure func(token string) error) (int, error) {
	p, err := s.AIAddClient(name)
	if err != nil {
		return 0, err
	}
	if err := configure(p.Token); err != nil {
		s.AIRevokeClient(p.ID)
		return 0, uerr(CodeSetupFailed, err.Error())
	}
	s.mu.Lock()
	var old []string
	for _, c := range s.ai.clients {
		if c.Name == p.Name && c.ID != p.ID {
			old = append(old, c.ID)
		}
	}
	s.mu.Unlock()
	for _, id := range old {
		s.AIRevokeClient(id)
	}
	return len(old), nil
}
