// Package browser drives Keyward's own Chrome window for AI login.
// Only the Keyward core holds the DevTools connection; the AI never receives it.
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/kb"

	"github.com/hikoyoshi/keyward/internal/core"
)

// Find returns the installed Google Chrome, or "" when there is none.
// Keyward controls the browser over a private pipe (no debugging port). Edge does not start in that
// mode on Windows, so AI login needs Chrome.
func Find() string {
	for _, p := range []string{
		filepath.Join(os.Getenv("ProgramFiles"), `Google\Chrome\Application\chrome.exe`),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Google\Chrome\Application\chrome.exe`),
		filepath.Join(os.Getenv("LOCALAPPDATA"), `Google\Chrome\Application\chrome.exe`),
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

type Options struct {
	ExecPath string
	TempRoot string // where the throwaway browser profile goes; removed on Close
	// InsecureCerts accepts self-signed certificates. Tests only: never set it in the app.
	InsecureCerts bool
	Headless      bool // tests only
}

// Manager starts the browser on first use and restarts it if the person closed the window.
type Manager struct {
	mu      sync.Mutex
	opt     Options
	dir     string
	cancel  []context.CancelFunc
	browser context.Context
}

func New(opt Options) *Manager { return &Manager{opt: opt} }

func (m *Manager) start() error {
	if m.browser != nil && m.browser.Err() == nil {
		return nil
	}
	m.stopLocked()
	if err := os.MkdirAll(m.opt.TempRoot, 0o700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(m.opt.TempRoot, "browser-")
	if err != nil {
		return err
	}
	m.dir = dir
	opts := []chromedp.ExecAllocatorOption{
		chromedp.ExecPath(m.opt.ExecPath),
		chromedp.UserDataDir(dir),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.WindowSize(1200, 860),
		// A fresh, private profile: no sync, sign-in, extensions or saved passwords.
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("password-store", "basic"),
		chromedp.Flag("disable-features", "PasswordManagerOnboarding,AutofillServerCommunication,msEdgeWelcomePage,msImplicitSignin,Translate"),
		chromedp.Flag("no-service-autorun", true),
	}
	if m.opt.InsecureCerts {
		opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
	}
	if m.opt.Headless {
		opts = append(opts, chromedp.Flag("headless", "new"))
	}
	alloc, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	bctx, cancelBrowser := chromedp.NewContext(alloc)
	// The first Run starts the browser; it must not carry a timeout.
	if err := chromedp.Do(bctx); err != nil {
		cancelBrowser()
		cancelAlloc()
		os.RemoveAll(dir)
		return err
	}
	m.browser, m.cancel = bctx, []context.CancelFunc{cancelBrowser, cancelAlloc}
	return nil
}

func (m *Manager) stopLocked() {
	for _, c := range m.cancel {
		c()
	}
	m.cancel, m.browser = nil, nil
	if m.dir != "" {
		// The browser may still be writing for a moment after it exits.
		for i := 0; i < 20; i++ {
			if os.RemoveAll(m.dir) == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		m.dir = ""
	}
}

// Close ends the browser and deletes its profile.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
}

// CleanStale removes profiles left behind by a crash. Call it at startup before any tab opens.
func CleanStale(root string) {
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "browser-") {
			os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
}

func (m *Manager) NewTab(ctx context.Context) (core.Tab, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.start(); err != nil {
		return nil, err
	}
	tctx, cancel := chromedp.NewContext(m.browser)
	if err := chromedp.Do(tctx); err != nil {
		cancel()
		return nil, err
	}
	return &tab{ctx: tctx, cancel: cancel}, nil
}

type tab struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex // one action at a time per tab
	ver    int        // snapshot version; element refs carry it
}

func (t *tab) run(ctx context.Context, d time.Duration, actions ...chromedp.Action[chromedp.Void]) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, cancel := context.WithTimeout(t.ctx, d)
	defer cancel()
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	return chromedp.Do(c, actions...)
}

func eval[T any](t *tab, ctx context.Context, js string) (T, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, cancel := context.WithTimeout(t.ctx, 15*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	return chromedp.Run(c, chromedp.Evaluate[T](js))
}

func (t *tab) Navigate(ctx context.Context, url string) error {
	return t.run(ctx, 45*time.Second, chromedp.Navigate(url), chromedp.WaitReady(chromedp.CSS("body")))
}

func (t *tab) Origin(ctx context.Context) (string, error) {
	return eval[string](t, ctx, `location.origin`)
}

func (t *tab) Close() { t.cancel() }

// jsLib is shared page-side helpers. Visible means rendered and not hidden.
// docs walks into iframes of the page's own origin (many single sign-on pages put the form in one);
// frames from other origins are out of reach and never searched.
const jsLib = `
var pw = window.__keyward || (window.__keyward = {
  docs: function(){
    var out = [];
    (function walk(d){
      out.push(d);
      Array.prototype.forEach.call(d.querySelectorAll('iframe,frame'), function(f){
        try { var cd = f.contentDocument; if(cd && cd.location.origin === location.origin && cd.documentElement) walk(cd); } catch(e) {}
      });
    })(document);
    return out;
  },
  all: function(sel){ var r = []; pw.docs().forEach(function(d){ r = r.concat(Array.prototype.slice.call(d.querySelectorAll(sel))); }); return r; },
  find: function(sel){ return pw.all(sel)[0] || null; },
  visible: function(el){
    if(!el || !el.getClientRects().length) return false;
    var w = el.ownerDocument.defaultView, s = w.getComputedStyle(el);
    if(s.visibility === 'hidden' || s.display === 'none' || el.disabled) return false;
    return !w.frameElement || pw.visible(w.frameElement);
  },
  isPassword: function(el){ return !!el && el.tagName === 'INPUT' && (el.type === 'password' || el.getAttribute('data-keyward-fill') === 'pass'); },
  // focus readies an element for real keystrokes, inside frames too.
  focus: function(sel, clear){
    var e = pw.find(sel); if(!e) return false;
    e.scrollIntoView({block: 'center'}); e.focus();
    if(clear && 'value' in e){ e.value = ''; e.dispatchEvent(new Event('input', {bubbles: true})); }
    return e.ownerDocument.activeElement === e;
  },
  // point returns the element's center in top-page coordinates.
  point: function(sel){
    var e = pw.find(sel); if(!e) return null;
    e.scrollIntoView({block: 'center'});
    var r = e.getBoundingClientRect(), x = r.left + r.width / 2, y = r.top + r.height / 2, w = e.ownerDocument.defaultView;
    while(w.frameElement){ var f = w.frameElement, fr = f.getBoundingClientRect(); x += fr.left + f.clientLeft; y += fr.top + f.clientTop; w = w.parent; }
    return {x: x, y: y};
  },
  fields: function(){
    var ins = pw.all('input').filter(pw.visible);
    var pass = ins.filter(function(e){ return e.type === 'password'; })[0] || null;
    var userTypes = ['text','email','tel',''];
    var pool = ins.filter(function(e){ return userTypes.indexOf(e.type) >= 0 && !/search|captcha|code|otp/i.test(e.name + ' ' + e.id + ' ' + (e.autocomplete||'')); });
    var user = null;
    if(pass){
      var form = pass.form;
      var before = pool.filter(function(e){ return e.ownerDocument === pass.ownerDocument && (!form || e.form === form) && (e.compareDocumentPosition(pass) & Node.DOCUMENT_POSITION_FOLLOWING); });
      user = before[before.length-1] || null;
    } else {
      user = pool.filter(function(e){ return /user|email|login|account|帳號/i.test(e.name + ' ' + e.id + ' ' + (e.autocomplete||'') + ' ' + e.type + ' ' + (e.placeholder||'')); })[0] || pool[0] || null;
    }
    pw.all('[data-keyward-fill]').forEach(function(e){ e.removeAttribute('data-keyward-fill'); });
    if(user) user.setAttribute('data-keyward-fill','user');
    if(pass) pass.setAttribute('data-keyward-fill','pass');
    return {user: !!user, pass: !!pass};
  }
});`

type fieldsFound struct {
	User bool `json:"user"`
	Pass bool `json:"pass"`
}

const userSel, passSel = `[data-keyward-fill="user"]`, `[data-keyward-fill="pass"]`

func (t *tab) findFields(ctx context.Context) (fieldsFound, error) {
	return eval[fieldsFound](t, ctx, jsLib+`; pw.fields()`)
}

// typeInto focuses the element (it may sit in a frame) and sends real keystrokes.
func (t *tab) typeInto(ctx context.Context, sel, text string, submit bool) error {
	ok, err := eval[bool](t, ctx, jsLib+`; pw.focus(`+jsString(sel)+`, true)`)
	if err != nil {
		return err
	}
	if !ok {
		return core.ErrNoSuchRef
	}
	steps := []chromedp.Action[chromedp.Void]{chromedp.KeyEvent(text)}
	if submit {
		steps = append(steps, chromedp.KeyEvent(kb.Enter))
	}
	return t.run(ctx, 20*time.Second, steps...)
}

func jsString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// FillLogin handles one-page logins and the "account first, then password" kind.
func (t *tab) FillLogin(ctx context.Context, account, password string) (bool, error) {
	f, err := t.findFields(ctx)
	if err != nil {
		return false, err
	}
	if !f.Pass && f.User && account != "" {
		if err := t.typeInto(ctx, userSel, account, true); err != nil {
			return false, err
		}
		for i := 0; i < 20 && !f.Pass; i++ { // wait for the password step
			time.Sleep(250 * time.Millisecond)
			if f, err = t.findFields(ctx); err != nil {
				return false, err
			}
		}
		f.User = false // already entered on the first step
	}
	if !f.Pass {
		return false, nil
	}
	if f.User && account != "" {
		if err := t.typeInto(ctx, userSel, account, false); err != nil {
			return false, err
		}
	}
	if err := t.typeInto(ctx, passSel, password, true); err != nil {
		return false, err
	}
	// Give the site a moment to navigate after submitting.
	time.Sleep(500 * time.Millisecond)
	t.run(ctx, 20*time.Second, chromedp.WaitReady(chromedp.CSS("body")))
	return true, nil
}

const checkFieldJS = `; (function(sel, origins, wantPass){
  var e = pw.find(sel); if(!e || !pw.visible(e)) return 'missing';
  if(origins.indexOf(e.ownerDocument.location.origin) < 0) return 'origin';
  if(wantPass) return e.tagName === 'INPUT' && e.type === 'password' ? 'ok' : 'not_password';
  return e.tagName === 'INPUT' && ['text','email','tel'].indexOf(e.type) >= 0 && !pw.isPassword(e) ? 'ok' : 'not_text';
})(%s, %s, %t)`

// FillFields types the login into fields the AI chose from the latest snapshot.
func (t *tab) FillFields(ctx context.Context, accountRef, passwordRef, account, password string, origins []string) error {
	type field struct {
		ref, text string
		pass      bool
	}
	var fields []field
	if accountRef != "" {
		fields = append(fields, field{accountRef, account, false})
	}
	if passwordRef != "" {
		fields = append(fields, field{passwordRef, password, true})
	}
	o, _ := json.Marshal(origins)
	sels := make([]string, len(fields))
	for i, f := range fields {
		sel, err := t.checkRef(ctx, f.ref)
		if err != nil {
			return err
		}
		res, err := eval[string](t, ctx, jsLib+fmt.Sprintf(checkFieldJS, jsString(sel), o, f.pass))
		if err != nil {
			return err
		}
		switch res {
		case "ok":
		case "origin":
			return core.ErrFieldOrigin
		case "not_password":
			return core.ErrNotPassword
		case "not_text":
			return core.ErrNotTextField
		default:
			return core.ErrNoSuchRef
		}
		sels[i] = sel
	}
	for i, f := range fields {
		if err := t.typeInto(ctx, sels[i], f.text, i == len(fields)-1); err != nil {
			return err
		}
	}
	time.Sleep(500 * time.Millisecond)
	t.run(ctx, 20*time.Second, chromedp.WaitReady(chromedp.CSS("body")))
	return nil
}

func (t *tab) NeedsUser(ctx context.Context) (bool, error) {
	return eval[bool](t, ctx, jsLib+`;
  pw.all('input').filter(pw.visible).some(function(e){
    return e.type === 'password' || e.autocomplete === 'one-time-code';
  })`)
}

const snapshotJS = `
(function(ver){
  var out = {url: location.href, title: document.title, text: '', elements: []};
  pw.all('[data-keyward-ref]').forEach(function(e){ e.removeAttribute('data-keyward-ref'); });
  var sel = 'a[href],button,input,select,textarea,[role=button],[role=link],[role=checkbox],[role=tab],[role=menuitem],[onclick]';
  var n = 0;
  pw.all(sel).forEach(function(el){
    if(n >= 400 || !pw.visible(el) || (el.tagName === 'INPUT' && el.type === 'hidden')) return;
    var ref = 's' + ver + '-' + (++n);
    el.setAttribute('data-keyward-ref', ref);
    var tag = el.tagName.toLowerCase();
    var role = el.getAttribute('role') || ({a:'link', button:'button', select:'combobox', textarea:'textbox'}[tag]) || (tag === 'input' ? ({checkbox:'checkbox', radio:'radio', submit:'button', button:'button', image:'button', reset:'button'}[el.type] || 'textbox') : tag);
    var label = el.getAttribute('aria-label') || (el.labels && el.labels[0] && el.labels[0].innerText) || el.getAttribute('placeholder') || el.getAttribute('title') || '';
    var name = (label || (tag === 'input' ? el.value : el.innerText) || '').replace(/\s+/g,' ').trim().slice(0, 120);
    var e = {ref: ref, role: role, name: name};
    if(tag === 'input') e.type = el.type;
    if(tag === 'input' || tag === 'textarea' || tag === 'select'){
      if(pw.isPassword(el)) { e.type = 'password'; e.name = name === el.value ? 'password' : name; }  // never the value
      else if(el.type === 'checkbox' || el.type === 'radio') e.value = el.checked ? 'checked' : '';
      else e.value = (el.value || '').slice(0, 200);
    }
    out.elements.push(e);
  });
  out.text = pw.docs().map(function(d){ return d.body && (d === document || pw.visible(d.defaultView.frameElement)) ? d.body.innerText : ''; }).join('\n').replace(/\n{3,}/g, '\n\n').slice(0, 8000);
  return out;
})(%d)`

func (t *tab) Snapshot(ctx context.Context) (core.Snapshot, error) {
	t.mu.Lock()
	t.ver++
	ver := t.ver
	t.mu.Unlock()
	js := jsLib + ";" + fmt.Sprintf(snapshotJS, ver)
	snap, err := eval[core.Snapshot](t, ctx, js)
	if err != nil && ctx.Err() == nil {
		// Usually the page was still navigating (e.g. right after a login); wait for it once.
		time.Sleep(500 * time.Millisecond)
		t.run(ctx, 15*time.Second, chromedp.WaitReady(chromedp.CSS("body")))
		snap, err = eval[core.Snapshot](t, ctx, js)
	}
	return snap, err
}

// checkRef verifies a ref belongs to the latest snapshot and still exists; it returns its selector.
func (t *tab) checkRef(ctx context.Context, ref string) (string, error) {
	t.mu.Lock()
	ver := t.ver
	t.mu.Unlock()
	parts := strings.SplitN(strings.TrimPrefix(ref, "s"), "-", 2)
	if len(parts) != 2 {
		return "", core.ErrNoSuchRef
	}
	if v, err := strconv.Atoi(parts[0]); err != nil || v != ver {
		return "", core.ErrStaleRef
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return "", core.ErrNoSuchRef
	}
	sel := `[data-keyward-ref="` + ref + `"]`
	ok, err := eval[bool](t, ctx, jsLib+`; !!pw.find('`+sel+`')`)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", core.ErrNoSuchRef
	}
	return sel, nil
}

func (t *tab) Click(ctx context.Context, ref string) error {
	sel, err := t.checkRef(ctx, ref)
	if err != nil {
		return err
	}
	p, err := eval[*struct{ X, Y float64 }](t, ctx, jsLib+`; pw.point('`+sel+`')`)
	if err != nil {
		return err
	}
	if p == nil {
		return core.ErrNoSuchRef
	}
	return t.run(ctx, 15*time.Second, chromedp.MouseClickXY(p.X, p.Y))
}

func (t *tab) Type(ctx context.Context, ref, text string) error {
	sel, err := t.checkRef(ctx, ref)
	if err != nil {
		return err
	}
	isPw, err := eval[bool](t, ctx, jsLib+`; pw.isPassword(pw.find('`+sel+`'))`)
	if err != nil {
		return err
	}
	if isPw {
		return core.ErrPasswordField
	}
	return t.typeInto(ctx, sel, text, false)
}

var _ core.Browser = (*Manager)(nil)
