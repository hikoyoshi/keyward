package core

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hikoyoshi/keyward/internal/vault"
)

func init() { loginSettle, ssoReturnWait = 0, 0 }

type fakeTab struct {
	mu          sync.Mutex
	origin      string
	needsUser   bool
	noForm      bool
	filled      int
	afterFill   string // origin the page moves to after the form is sent
	fillOrigins []string
	closed      bool
	snap        Snapshot
	navigated   []string
}

func (t *fakeTab) Navigate(_ context.Context, u string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.navigated = append(t.navigated, u)
	return nil
}
func (t *fakeTab) Origin(context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.origin, nil
}
func (t *fakeTab) FillLogin(_ context.Context, account, password string) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.noForm {
		return false, nil
	}
	t.filled++
	if t.afterFill != "" {
		t.origin = t.afterFill
	}
	return true, nil
}
func (t *fakeTab) NeedsUser(context.Context) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.needsUser, nil
}
func (t *fakeTab) Snapshot(context.Context) (Snapshot, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.snap, nil
}
func (t *fakeTab) Click(_ context.Context, ref string) error {
	if ref == "old" {
		return ErrStaleRef
	}
	return nil
}
func (t *fakeTab) FillFields(_ context.Context, accountRef, passwordRef, _, _ string, origins []string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case passwordRef == "search":
		return ErrNotPassword
	case accountRef == "pw":
		return ErrNotTextField
	case passwordRef == "foreign":
		return ErrFieldOrigin
	case accountRef == "old" || passwordRef == "old":
		return ErrStaleRef
	}
	t.filled++
	t.fillOrigins = origins
	return nil
}
func (t *fakeTab) Type(_ context.Context, ref, _ string) error {
	if ref == "pw" {
		return ErrPasswordField
	}
	return nil
}
func (t *fakeTab) Close() { t.mu.Lock(); t.closed = true; t.mu.Unlock() }

// isClosed waits briefly: tabs are closed in the background, outside the service lock.
func (t *fakeTab) isClosed() bool {
	for i := 0; i < 50; i++ {
		t.mu.Lock()
		c := t.closed
		t.mu.Unlock()
		if c {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

type fakeBrowser struct {
	mu   sync.Mutex
	tabs []*fakeTab
	next func(*fakeTab) // adjusts each new tab
}

func (b *fakeBrowser) NewTab(context.Context) (Tab, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := &fakeTab{origin: "https://work.example.com"}
	if b.next != nil {
		b.next(t)
	}
	b.tabs = append(b.tabs, t)
	return t, nil
}
func (b *fakeBrowser) Close() {}
func (b *fakeBrowser) last() *fakeTab {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tabs[len(b.tabs)-1]
}

const sitePw = "Work-Secret!42"

type aiEnv struct {
	*env
	br     *fakeBrowser
	client string
	token  string
	item   string
	events int
	evMu   sync.Mutex
}

func setupAI(t *testing.T) *aiEnv {
	t.Helper()
	br := &fakeBrowser{}
	a := &aiEnv{br: br}
	a.env = setupWith(t, func(o *Options) {
		o.Browser = br
		o.OnAIEvent = func(string) { a.evMu.Lock(); a.events++; a.evMu.Unlock() }
	})
	d, err := a.s.Save(Input{Type: vault.TypeLogin, Name: "Work", URL: "https://work.example.com/login", Alias: "job", Account: "me@example.com", Password: sitePw, AI: true, GrantMin: 60})
	if err != nil {
		t.Fatal(err)
	}
	a.item = d.ID
	p, err := a.s.AIAddClient("Claude Code")
	if err != nil {
		t.Fatal(err)
	}
	a.client, a.token = p.ID, p.Token
	return a
}

var bg = context.Background()

const short = 2 * time.Second

func (a *aiEnv) request(t *testing.T) AIRequestResult {
	t.Helper()
	r, err := a.s.AIRequestLogin(bg, a.client, a.item, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// approve answers the pending request and waits for the login to settle.
func (a *aiEnv) approve(t *testing.T, id string, ap AIApproval) AIRequestResult {
	t.Helper()
	if err := a.s.AIApprove(id, ap); err != nil {
		t.Fatal(err)
	}
	r, err := a.s.AIGetStatus(bg, a.client, id, short)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (a *aiEnv) loggedIn(t *testing.T, ap AIApproval) string {
	t.Helper()
	r := a.request(t)
	if r.Status != PhasePending {
		t.Fatalf("request: %+v", r)
	}
	r = a.approve(t, r.RequestID, ap)
	if r.Status != PhaseLoggedIn {
		t.Fatalf("after approve: %+v", r)
	}
	return r.RequestID
}

func status(t *testing.T, a *aiEnv, id string) string {
	t.Helper()
	r, err := a.s.AIGetStatus(bg, a.client, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	return r.Status
}

func TestPairingAndAuth(t *testing.T) {
	a := setupAI(t)
	if id, name, err := a.s.AuthClient(a.token); err != nil || id != a.client || name != "Claude Code" {
		t.Fatalf("auth: %s %s %v", id, name, err)
	}
	if _, _, err := a.s.AuthClient("ppw_wrong"); code(err) != CodeUnauthorized {
		t.Fatalf("wrong token: %v", err)
	}
	// Pairings survive locking (running work still authenticates) and restarts.
	a.s.Lock(ReasonManual)
	if _, _, err := a.s.AuthClient(a.token); err != nil {
		t.Fatal("auth while locked after an unlock should work")
	}
	a.s.Unlock(master)
	if err := a.s.AIRevokeClient(a.client); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.s.AuthClient(a.token); code(err) != CodeUnauthorized {
		t.Fatalf("revoked token: %v", err)
	}
	if _, err := a.s.AIAddClient("  "); code(err) != CodeInvalid {
		t.Fatal("empty name accepted")
	}
}

func TestTokenNotStoredInPlain(t *testing.T) {
	a := setupAI(t)
	st, _ := a.s.cur().Settings()
	if len(st.AIClients) != 1 || strings.Contains(string(st.AIClients[0].TokenHash), a.token) || len(st.AIClients[0].TokenHash) != 32 {
		t.Fatalf("stored client: %+v", st.AIClients)
	}
}

func TestListLogins(t *testing.T) {
	a := setupAI(t)
	a.s.Save(Input{Type: vault.TypeLogin, Name: "Private", URL: "https://private.example.com", Alias: "me", Account: "x", Password: "p-1"})
	a.s.Save(Input{Type: vault.TypePassword, Name: "Wi-Fi", Password: "w-1"})
	l, err := a.s.AIListLogins(a.client)
	if err != nil || len(l) != 1 || l[0].Name != "Work" || l[0].Site != "https://work.example.com" || !l[0].RequiresApproval {
		t.Fatalf("list: %+v %v", l, err)
	}
	a.s.Lock(ReasonManual)
	if _, err := a.s.AIListLogins(a.client); code(err) != CodeVaultLocked {
		t.Fatalf("locked: %v", err)
	}
	if _, err := a.s.AIRequestLogin(bg, a.client, a.item, 0); code(err) != CodeVaultLocked {
		t.Fatalf("request while locked: %v", err)
	}
}

func TestApproveOnceLogsInAndRedacts(t *testing.T) {
	a := setupAI(t)
	r := a.request(t)
	if r.Status != PhasePending || a.events == 0 {
		t.Fatalf("pending: %+v events=%d", r, a.events)
	}
	ov, _ := a.s.AIOverview()
	if len(ov.Pending) != 1 || ov.Pending[0].Alias != "job" || ov.Pending[0].GrantMin != 60 {
		t.Fatalf("overview pending: %+v", ov.Pending)
	}
	r = a.approve(t, r.RequestID, AIApproval{Mode: "once"})
	if r.Status != PhaseLoggedIn || r.ExpiresInSeconds != 900 {
		t.Fatalf("logged in: %+v", r)
	}
	tab := a.br.last()
	if tab.filled != 1 || tab.navigated[0] != "https://work.example.com/login" {
		t.Fatalf("tab: %+v", tab)
	}
	// The site echoes the password (e.g. after "show password"): it must not reach the AI.
	tab.snap = Snapshot{URL: "https://work.example.com/account", Text: "Your password is " + sitePw,
		Elements: []Element{{Ref: "e1", Role: "textbox", Name: "Password", Value: sitePw}}}
	snap, err := a.s.AISnapshot(bg, a.client, r.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(snap.Text+snap.Elements[0].Value, sitePw) {
		t.Fatalf("password leaked: %+v", snap)
	}
	if err := a.s.AIType(bg, a.client, r.RequestID, "pw", "x"); code(err) != CodePasswordField {
		t.Fatalf("type into password: %v", err)
	}
	if err := a.s.AIClick(bg, a.client, r.RequestID, "old"); code(err) != CodeBadSession {
		t.Fatalf("stale ref: %v", err)
	}
	if err := a.s.AINavigate(bg, a.client, r.RequestID, "javascript:alert(1)"); code(err) != CodeInvalid {
		t.Fatalf("javascript url: %v", err)
	}
	if err := a.s.AINavigate(bg, a.client, r.RequestID, "https://work.example.com/reports"); err != nil {
		t.Fatal(err)
	}
	// Another paired tool cannot use this session.
	other, _ := a.s.AIAddClient("Codex")
	if _, err := a.s.AISnapshot(bg, other.ID, r.RequestID); code(err) != CodeBadSession {
		t.Fatalf("other client: %v", err)
	}
	if err := a.s.AIClose(a.client, r.RequestID); err != nil || !tab.isClosed() {
		t.Fatalf("close: %v closed=%v", err, tab.isClosed())
	}
	if status(t, a, r.RequestID) != PhaseStopped {
		t.Fatal("closed session should report stopped")
	}
}

func TestDenyAndTimeout(t *testing.T) {
	a := setupAI(t)
	r := a.request(t)
	a.s.AIDeny(r.RequestID)
	if status(t, a, r.RequestID) != PhaseDenied {
		t.Fatal("deny")
	}
	r = a.request(t)
	a.advance(PendingTimeout)
	if status(t, a, r.RequestID) != PhaseTimeout {
		t.Fatal("timeout")
	}
	if err := a.s.AIApprove(r.RequestID, AIApproval{Mode: "once"}); code(err) != CodeNotFound {
		t.Fatalf("approve after timeout: %v", err)
	}
	if len(a.br.tabs) != 0 {
		t.Fatal("no browser tab should open without approval")
	}
}

func TestSiteGrantSkipsApprovalAndExpires(t *testing.T) {
	a := setupAI(t)
	r := a.request(t)
	if err := a.s.AIApprove(r.RequestID, AIApproval{Mode: "site", Minutes: 5}); code(err) != CodeInvalid {
		t.Fatal("grant under 15 minutes accepted")
	}
	if err := a.s.AIApprove(r.RequestID, AIApproval{Mode: "site", Minutes: 13 * 60}); code(err) != CodeInvalid {
		t.Fatal("grant over 12 hours accepted")
	}
	a.approve(t, r.RequestID, AIApproval{Mode: "site", Minutes: 60})
	a.s.AIClose(a.client, r.RequestID)
	// Within the grant, a new request goes straight to login.
	r2, _ := a.s.AIRequestLogin(bg, a.client, a.item, short)
	if r2.Status != PhaseLoggedIn {
		t.Fatalf("second request: %+v", r2)
	}
	if l, _ := a.s.AIListLogins(a.client); l[0].RequiresApproval {
		t.Fatal("list should show no approval needed during the grant")
	}
	tab := a.br.last()
	a.s.Touch()
	for i := 0; i < 61; i++ { // keep the person active so idle lock does not interfere
		a.advance(time.Minute)
		a.s.Touch()
	}
	if status(t, a, r2.RequestID) != PhaseExpired || !tab.isClosed() {
		t.Fatal("grant end should end the session and close its tab")
	}
	if l, _ := a.s.AIListLogins(a.client); !l[0].RequiresApproval {
		t.Fatal("approval needed again after the grant")
	}
}

func TestExtendGrant(t *testing.T) {
	a := setupAI(t)
	r := a.request(t)
	a.approve(t, r.RequestID, AIApproval{Mode: "site", Minutes: 60})
	ov, _ := a.s.AIOverview()
	key, until := ov.Grants[0].Key, ov.Grants[0].Until
	a.s.AIExtendGrant(key, 120)
	ov, _ = a.s.AIOverview()
	if ov.Grants[0].Until != until+7200 || ov.Sessions[0].Expires != ov.Grants[0].Until {
		t.Fatalf("extend: %+v", ov)
	}
	a.s.AIExtendGrant(key, 12*60)
	ov, _ = a.s.AIOverview()
	if limit := a.clock.Add(MaxGrant).Unix(); ov.Grants[0].Until != limit {
		t.Fatalf("cap: got %d want %d", ov.Grants[0].Until, limit)
	}
}

func TestNeedsUserFlows(t *testing.T) {
	a := setupAI(t)
	a.br.next = func(t *fakeTab) { t.needsUser = true }
	r := a.request(t)
	r = a.approve(t, r.RequestID, AIApproval{Mode: "once"})
	if r.Status != PhaseNeedsUser {
		t.Fatalf("mfa: %+v", r)
	}
	// The AI may look at the page while waiting, e.g. to point Keyward at an unrecognized form.
	if _, err := a.s.AISnapshot(bg, a.client, r.RequestID); err != nil {
		t.Fatalf("snapshot while waiting on the person: %v", err)
	}
	// The person finishes MFA; get_status notices.
	tab := a.br.last()
	tab.mu.Lock()
	tab.needsUser = false
	tab.mu.Unlock()
	if status(t, a, r.RequestID) != PhaseLoggedIn {
		t.Fatal("recheck after MFA")
	}

	// Redirect to another origin (e.g. SSO): Keyward does not fill there.
	a.br.next = func(t *fakeTab) { t.origin = "https://login.sso.example" }
	a.s.AIClose(a.client, r.RequestID)
	r = a.request(t)
	r = a.approve(t, r.RequestID, AIApproval{Mode: "once"})
	if r.Status != PhaseNeedsUser || a.br.last().filled != 0 {
		t.Fatalf("redirect: %+v filled=%d", r, a.br.last().filled)
	}
	if err := a.s.AIUserDone(r.RequestID); err != nil || status(t, a, r.RequestID) != PhaseLoggedIn {
		t.Fatalf("user done: %v", err)
	}
}

func TestFillCredentialsRules(t *testing.T) {
	a := setupAI(t)
	id := a.loggedIn(t, AIApproval{Mode: "site", Minutes: 60})
	tab := a.br.last()
	if res, err := a.s.AIFillCredentials(bg, a.client, id, "", ""); err != nil || res != "filled" || tab.filled != 2 {
		t.Fatalf("fill: %s %v filled=%d", res, err, tab.filled)
	}
	tab.mu.Lock()
	tab.origin = "https://work.example.com.evil.test"
	tab.mu.Unlock()
	if _, err := a.s.AIFillCredentials(bg, a.client, id, "", ""); code(err) != CodeOriginMismatch || tab.filled != 2 {
		t.Fatalf("lookalike origin: %v", err)
	}
	tab.mu.Lock()
	tab.origin = "https://work.example.com"
	tab.mu.Unlock()
	a.s.Lock(ReasonIdle)
	if _, err := a.s.AIFillCredentials(bg, a.client, id, "", ""); code(err) != CodeVaultLocked {
		t.Fatalf("fill while locked: %v", err)
	}
	if status(t, a, id) != PhaseLoggedIn {
		t.Fatal("idle lock keeps logged-in work")
	}
}

func TestLockKinds(t *testing.T) {
	cases := []struct {
		name     string
		lock     func(a *aiEnv)
		keepOnce bool // a "once" approval survives
		keepSite bool // a site grant without the Windows option survives
		keepWin  bool // a site grant marked "keep on Windows lock" survives
	}{
		{"manual", func(a *aiEnv) { a.s.Lock(ReasonManual) }, true, true, true},
		{"idle", func(a *aiEnv) { a.advance(5 * time.Minute) }, true, true, true},
		{"windows", func(a *aiEnv) { a.winLock = true; a.advance(time.Second) }, false, false, true},
		{"sleep", func(a *aiEnv) { a.clock = a.clock.Add(time.Hour); a.s.Tick() }, false, false, false},
		{"stop all", func(a *aiEnv) { a.s.Lock(ReasonStopAll) }, false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := setupAI(t)
			other, _ := a.s.Save(Input{Type: vault.TypeLogin, Name: "Docs", URL: "https://work.example.com/docs", Alias: "d", Account: "d@x", Password: "d-1", AI: true})
			third, _ := a.s.Save(Input{Type: vault.TypeLogin, Name: "Wiki", URL: "https://work.example.com/wiki", Alias: "w", Account: "w@x", Password: "w-1", AI: true})
			fourth, _ := a.s.Save(Input{Type: vault.TypeLogin, Name: "Mail", URL: "https://work.example.com/mail", Alias: "m", Account: "m@x", Password: "m-1", AI: true})
			once := a.loggedIn(t, AIApproval{Mode: "once"})
			a.item = other.ID
			site := a.loggedIn(t, AIApproval{Mode: "site", Minutes: 60})
			a.item = third.ID
			win := a.loggedIn(t, AIApproval{Mode: "site", Minutes: 60, KeepOnWinLock: true})
			a.item = fourth.ID
			pending := a.request(t) // still waiting for approval: always cancelled
			a.s.Touch()
			c.lock(a)
			check := func(id string, keep bool) {
				got := status(t, a, id)
				if keep != (got == PhaseLoggedIn) {
					t.Errorf("%s: status %s, keep=%v", id, got, keep)
				}
			}
			check(once, c.keepOnce)
			check(site, c.keepSite)
			check(win, c.keepWin)
			if s := status(t, a, pending.RequestID); active(s) {
				t.Errorf("pending request still %s", s)
			}
		})
	}
}

func TestWindowsLockWhileAlreadyLocked(t *testing.T) {
	a := setupAI(t)
	id := a.loggedIn(t, AIApproval{Mode: "once"})
	a.s.Lock(ReasonManual) // logged-in work continues
	if status(t, a, id) != PhaseLoggedIn {
		t.Fatal("manual lock should keep the session")
	}
	a.winLock = true
	a.advance(time.Second)
	if status(t, a, id) != PhaseStopped {
		t.Fatal("Windows lock must stop work even when the vault was already locked")
	}
}

func TestPauseIdleDuringGrant(t *testing.T) {
	a := setupAI(t)
	id := a.loggedIn(t, AIApproval{Mode: "site", Minutes: 30, PauseIdle: true})
	a.advance(20 * time.Minute) // nobody touches Keyward
	if a.s.Status().Locked {
		t.Fatal("idle lock should pause while the grant is active")
	}
	if res, err := a.s.AIFillCredentials(bg, a.client, id, "", ""); err != nil || res != "filled" {
		t.Fatalf("re-login during pause: %v", err)
	}
	a.advance(10 * time.Minute) // the grant ends
	if status(t, a, id) != PhaseExpired {
		t.Fatal("grant should have ended")
	}
	if a.s.Status().Locked {
		t.Fatal("the idle timer starts over when the pause ends, it must not lock at once")
	}
	a.advance(5 * time.Minute)
	if !a.s.Status().Locked {
		t.Fatal("idle lock resumes after the pause")
	}
	// Windows lock still applies during a pause.
	b := setupAI(t)
	bid := b.loggedIn(t, AIApproval{Mode: "site", Minutes: 30, PauseIdle: true})
	b.winLock = true
	b.advance(time.Second)
	if !b.s.Status().Locked || status(t, b, bid) != PhaseStopped {
		t.Fatal("Windows lock overrides the idle pause")
	}
}

func TestPauseIdleNeedsLoggedInWork(t *testing.T) {
	a := setupAI(t)
	a.br.next = func(t *fakeTab) { t.needsUser = true }
	r := a.request(t)
	a.approve(t, r.RequestID, AIApproval{Mode: "site", Minutes: 60, PauseIdle: true})
	a.advance(5 * time.Minute)
	if !a.s.Status().Locked {
		t.Fatal("no logged-in work yet, so idle lock applies")
	}
}

func TestItemChangesEndAIWork(t *testing.T) {
	for _, change := range []string{"password", "account", "login url", "ai off", "delete", "note only"} {
		t.Run(change, func(t *testing.T) {
			a := setupAI(t)
			id := a.loggedIn(t, AIApproval{Mode: "site", Minutes: 60})
			in := Input{ID: a.item, Type: vault.TypeLogin, Name: "Work", URL: "https://work.example.com/login", Alias: "job", Account: "me@example.com", AI: true, GrantMin: 60}
			switch change {
			case "password":
				in.Password = "Changed!pw1"
			case "account":
				in.Account = "other@example.com"
			case "login url":
				in.LoginURL = "https://sso.example.com/login"
			case "ai off":
				in.AI = false
			case "note only":
				in.Note = "just a note"
			}
			if change == "delete" {
				a.s.Delete(a.item)
			} else if _, err := a.s.Save(in); err != nil {
				t.Fatal(err)
			}
			want := PhaseStopped
			if change == "note only" {
				want = PhaseLoggedIn
			}
			if got := status(t, a, id); got != want {
				t.Fatalf("status %s, want %s", got, want)
			}
		})
	}
}

func TestRestoreDropsPairings(t *testing.T) {
	a := setupAI(t)
	file := export(t, a.env)
	a.s.Lock(ReasonManual)
	a.s.PreviewRestore(file, bpw)
	if _, err := a.s.Restore("Restored!pw1", "Restored!pw1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.s.AuthClient(a.token); code(err) != CodeUnauthorized {
		t.Fatalf("pairing survived restore: %v", err)
	}
}

func TestNoBrowser(t *testing.T) {
	a := setupAI(t)
	a.s.opt.Browser = nil
	r := a.request(t)
	r = a.approve(t, r.RequestID, AIApproval{Mode: "once"})
	if r.Status != PhaseFailed {
		t.Fatalf("without a browser: %+v", r)
	}
}

func TestConfigSnippets(t *testing.T) {
	exe := `C:\Program Files\Keyward\keyward-mcp.exe`
	sn := AIConfigSnippets(exe, "kw_TOKEN")
	if len(sn) != 5 {
		t.Fatalf("snippets: %d", len(sn))
	}
	for _, s := range sn {
		if !strings.Contains(s.Text, "kw_TOKEN") {
			t.Errorf("%s has no token", s.Tool)
		}
	}
	if want := `claude mcp add keyward --scope user --transport stdio --env KEYWARD_TOKEN=kw_TOKEN -- "` + exe + `"`; sn[0].Text != want {
		t.Errorf("claude: %s", sn[0].Text)
	}
	if !strings.Contains(sn[1].Text, "command = '"+exe+"'") {
		t.Errorf("codex: %s", sn[1].Text)
	}
}

// A site that signs in on another address (single sign-on) works once that address is set on the item.
func TestLoginPageOnAnotherOrigin(t *testing.T) {
	a := setupAI(t)
	const sso = "https://identity.example.edu:8443"
	a.br.next = func(t *fakeTab) { t.origin = sso; t.afterFill = "https://work.example.com" }

	// Not set yet: Keyward refuses to fill and tells both sides why.
	r := a.request(t)
	r = a.approve(t, r.RequestID, AIApproval{Mode: "once"})
	if r.Status != PhaseNeedsUser || a.br.last().filled != 0 || !strings.Contains(r.Note, "登入頁網址") {
		t.Fatalf("unset login page: %+v", r)
	}
	a.s.AIClose(a.client, r.RequestID)

	d, err := a.s.Get(a.item)
	if err != nil {
		t.Fatal(err)
	}
	in := Input{ID: a.item, Type: vault.TypeLogin, Name: d.Name, URL: d.URL, LoginURL: sso + "/nidp/sso", Alias: d.Alias, Account: d.Account, AI: true, GrantMin: 60}
	if d, err = a.s.Save(in); err != nil || d.LoginURL != sso+"/nidp/sso" {
		t.Fatalf("save login url: %+v %v", d, err)
	}
	id := a.loggedIn(t, AIApproval{Mode: "site", Minutes: 60})
	tab := a.br.last()
	if tab.filled != 1 {
		t.Fatalf("filled %d", tab.filled)
	}

	// The site later sends the AI back to the sign-on page: fill_credentials works there, nowhere else.
	tab.mu.Lock()
	tab.origin = sso
	tab.mu.Unlock()
	if res, err := a.s.AIFillCredentials(bg, a.client, id, "", ""); err != nil || res != "filled" {
		t.Fatalf("fill at login page: %s %v", res, err)
	}
	tab.mu.Lock()
	tab.origin = "https://identity.example.edu"
	tab.mu.Unlock()
	if _, err := a.s.AIFillCredentials(bg, a.client, id, "", ""); code(err) != CodeOriginMismatch {
		t.Fatalf("other port must not match: %v", err)
	}
}

// Sent the form but the sign-on page never sent us back: the person checks, and get_status only
// reports logged_in once the page is back on the site itself.
func TestLoginPageDoesNotReturn(t *testing.T) {
	a := setupAI(t)
	const sso = "https://identity.example.edu:8443"
	d, _ := a.s.Get(a.item)
	if _, err := a.s.Save(Input{ID: a.item, Type: vault.TypeLogin, Name: d.Name, URL: d.URL, LoginURL: sso, Alias: d.Alias, Account: d.Account, AI: true, GrantMin: 60}); err != nil {
		t.Fatal(err)
	}
	a.br.next = func(t *fakeTab) { t.origin = sso }
	r := a.request(t)
	r = a.approve(t, r.RequestID, AIApproval{Mode: "once"})
	if r.Status != PhaseNeedsUser {
		t.Fatalf("stuck on sign-on page: %+v", r)
	}
	if status(t, a, r.RequestID) != PhaseNeedsUser {
		t.Fatal("no password field on the sign-on page is not a finished login")
	}
	tab := a.br.last()
	tab.mu.Lock()
	tab.origin = "https://work.example.com"
	tab.mu.Unlock()
	if status(t, a, r.RequestID) != PhaseLoggedIn {
		t.Fatal("back on the site")
	}
}

// The AI picks the fields from its snapshot; Keyward checks them and does the typing.
func TestFillWithRefs(t *testing.T) {
	a := setupAI(t)
	a.br.next = func(t *fakeTab) { t.noForm = true; t.needsUser = true }
	r := a.request(t)
	r = a.approve(t, r.RequestID, AIApproval{Mode: "once"})
	if r.Status != PhaseNeedsUser || !strings.Contains(r.Note, "找不到登入欄位") {
		t.Fatalf("unrecognized form: %+v", r)
	}
	id, tab := r.RequestID, a.br.last()
	fill := func(acc, pw string) error {
		_, err := a.s.AIFillCredentials(bg, a.client, id, acc, pw)
		return err
	}
	if err := fill("user", "search"); code(err) != CodeInvalid {
		t.Fatalf("password into a non-password field: %v", err)
	}
	if err := fill("pw", "pass"); code(err) != CodeInvalid {
		t.Fatalf("account into the password field: %v", err)
	}
	if err := fill("", "foreign"); code(err) != CodeOriginMismatch {
		t.Fatalf("field in a foreign frame: %v", err)
	}
	if err := fill("old", "pass"); code(err) != CodeBadSession {
		t.Fatalf("stale ref: %v", err)
	}
	if tab.filled != 0 {
		t.Fatal("nothing may be typed after a refused request")
	}
	if err := fill("user", "pass"); err != nil || tab.filled != 1 || len(tab.fillOrigins) != 1 || tab.fillOrigins[0] != "https://work.example.com" {
		t.Fatalf("fill with refs: %v %d %v", err, tab.filled, tab.fillOrigins)
	}
	// The page moved on: get_status notices the login is done.
	tab.mu.Lock()
	tab.needsUser = false
	tab.mu.Unlock()
	if status(t, a, id) != PhaseLoggedIn {
		t.Fatal("logged in after the AI-guided fill")
	}

	// Still only on the site's own address.
	tab.mu.Lock()
	tab.origin = "https://evil.example"
	tab.mu.Unlock()
	if err := fill("user", "pass"); code(err) != CodeOriginMismatch || tab.filled != 1 {
		t.Fatalf("other page: %v", err)
	}
	a.s.Lock(ReasonIdle)
	tab.mu.Lock()
	tab.origin = "https://work.example.com"
	tab.mu.Unlock()
	if err := fill("user", "pass"); code(err) != CodeVaultLocked {
		t.Fatalf("locked: %v", err)
	}
}

func TestAIAutoPair(t *testing.T) {
	a := setupAI(t) // already paired "Claude Code" once
	var got string
	n, err := a.s.AIAutoPair("Claude Code", func(token string) error { got = token; return nil })
	if err != nil || n != 1 || !strings.HasPrefix(got, "kw_") {
		t.Fatalf("replace: %d %v %q", n, err, got)
	}
	if _, _, err := a.s.AuthClient(a.token); code(err) != CodeUnauthorized {
		t.Fatal("the replaced token still works")
	}
	if _, _, err := a.s.AuthClient(got); err != nil {
		t.Fatalf("new token: %v", err)
	}
	// The tool's config could not be written: no pairing is left behind.
	before, _ := a.s.AIOverview()
	if _, err := a.s.AIAutoPair("Codex", func(string) error { return errors.New("找不到 Codex") }); code(err) != CodeSetupFailed {
		t.Fatalf("failed setup: %v", err)
	}
	after, _ := a.s.AIOverview()
	if len(after.Clients) != len(before.Clients) {
		t.Fatalf("pairing left after a failed setup: %+v", after.Clients)
	}
}
