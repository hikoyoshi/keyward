package browser

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hikoyoshi/keyward/internal/core"
	"github.com/hikoyoshi/keyward/internal/testsite"
)

const sitePw = "Site-Secret!77"

func newSite(t *testing.T) (*Manager, string) {
	t.Helper()
	exe := Find()
	if exe == "" || testing.Short() {
		t.Skip("no Chrome, or -short")
	}
	srv := httptest.NewTLSServer(testsite.Handler(sitePw))
	t.Cleanup(srv.Close)
	m := New(Options{ExecPath: exe, TempRoot: t.TempDir(), InsecureCerts: true, Headless: true})
	t.Cleanup(m.Close)
	return m, srv.URL
}

func open(t *testing.T, m *Manager, url string) core.Tab {
	t.Helper()
	ctx := context.Background()
	tab, err := m.NewTab(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tab.Close)
	if err := tab.Navigate(ctx, url); err != nil {
		t.Fatal(err)
	}
	return tab
}

func TestLoginSnapshotAndGuards(t *testing.T) {
	m, base := newSite(t)
	ctx := context.Background()
	tab := open(t, m, base+"/login")
	if o, _ := tab.Origin(ctx); o != base {
		t.Fatalf("origin %q want %q", o, base)
	}
	if needs, _ := tab.NeedsUser(ctx); !needs {
		t.Fatal("login page has a password field")
	}
	ok, err := tab.FillLogin(ctx, testsite.User, sitePw)
	if err != nil || !ok {
		t.Fatalf("fill: %v %v", ok, err)
	}
	if needs, _ := tab.NeedsUser(ctx); needs {
		snap, _ := tab.Snapshot(ctx)
		t.Fatalf("still on a login page after fill: %s", snap.Text)
	}
	snap, err := tab.Snapshot(ctx)
	if err != nil || !strings.Contains(snap.Text, "歡迎，"+testsite.User) {
		t.Fatalf("app page: %+v %v", snap, err)
	}

	// Type into a normal field and click a button using snapshot refs.
	ref := func(s core.Snapshot, role, name string) string {
		for _, e := range s.Elements {
			if e.Role == role && strings.Contains(e.Name, name) {
				return e.Ref
			}
		}
		t.Fatalf("no %s %q in %+v", role, name, s.Elements)
		return ""
	}
	if err := tab.Type(ctx, ref(snap, "textbox", "搜尋"), "報表"); err != nil {
		t.Fatal(err)
	}
	if err := tab.Click(ctx, ref(snap, "button", "搜尋")); err != nil {
		t.Fatal(err)
	}
	snap2, _ := tab.Snapshot(ctx)
	if !strings.Contains(snap2.Text, "已搜尋：報表") {
		t.Fatalf("click/type had no effect: %s", snap2.Text)
	}
	if err := tab.Click(ctx, ref(snap, "button", "搜尋")); !errors.Is(err, core.ErrStaleRef) {
		t.Fatalf("old ref: %v", err)
	}

	// The account page shows the password three ways; the browser layer drops the password input's value,
	// and the core removes the rest (checked in core tests). Here: no value for the password input.
	if err := tab.Navigate(ctx, base+"/account"); err != nil {
		t.Fatal(err)
	}
	acct, _ := tab.Snapshot(ctx)
	var pwEl *core.Element
	for i, e := range acct.Elements {
		if e.Type == "password" {
			pwEl = &acct.Elements[i]
		}
	}
	if pwEl == nil || pwEl.Value != "" || strings.Contains(pwEl.Name, sitePw) {
		t.Fatalf("password input exposed: %+v", pwEl)
	}
	if err := tab.Type(ctx, pwEl.Ref, "x"); !errors.Is(err, core.ErrPasswordField) {
		t.Fatalf("typing into password: %v", err)
	}
}

func TestMFAPageNeedsUser(t *testing.T) {
	m, base := newSite(t)
	ctx := context.Background()
	tab := open(t, m, base+"/login")
	if ok, err := tab.FillLogin(ctx, testsite.MFAUser, sitePw); err != nil || !ok {
		t.Fatalf("fill: %v %v", ok, err)
	}
	if needs, _ := tab.NeedsUser(ctx); !needs {
		t.Fatal("one-time-code page should need the user")
	}
}

func TestTwoStepLogin(t *testing.T) {
	m, base := newSite(t)
	ctx := context.Background()
	tab := open(t, m, base+"/two-step")
	if ok, err := tab.FillLogin(ctx, testsite.User, sitePw); err != nil || !ok {
		t.Fatalf("fill: %v %v", ok, err)
	}
	snap, _ := tab.Snapshot(ctx)
	if !strings.Contains(snap.Text, "歡迎") {
		t.Fatalf("two-step login did not finish: %s", snap.Text)
	}
}

func TestNoFormAndRestart(t *testing.T) {
	m, base := newSite(t)
	ctx := context.Background()
	tab := open(t, m, base+"/logout") // redirects to /login
	tab.Navigate(ctx, base+"/nope")
	if ok, err := tab.FillLogin(ctx, testsite.User, sitePw); err != nil || ok {
		t.Fatalf("no form: %v %v", ok, err)
	}
	// If the browser goes away (the person closed it), the next tab starts a new one.
	m.Close()
	c, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	tab2, err := m.NewTab(c)
	if err != nil {
		t.Fatal(err)
	}
	tab2.Close()
}

// Single sign-on pages often keep the form in nested iframes of their own origin.
func TestLoginInsideFrames(t *testing.T) {
	m, base := newSite(t)
	ctx := context.Background()
	tab := open(t, m, base+"/sso")
	if needs, _ := tab.NeedsUser(ctx); !needs {
		t.Fatal("password field inside the frames was not seen")
	}
	snap, err := tab.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var btn string
	for _, e := range snap.Elements {
		if e.Role == "button" && strings.Contains(e.Name, "框架內按鈕") {
			btn = e.Ref
		}
		if e.Type == "password" && e.Value != "" {
			t.Fatalf("password value in snapshot: %+v", e)
		}
	}
	if btn == "" {
		t.Fatalf("frame elements missing: %+v", snap.Elements)
	}
	if err := tab.Click(ctx, btn); err != nil {
		t.Fatal(err)
	}
	if snap, _ = tab.Snapshot(ctx); !strings.Contains(snap.Text, "框架內按鈕已按下") {
		t.Fatalf("click inside frame had no effect: %q", snap.Text)
	}
	ok, err := tab.FillLogin(ctx, testsite.User, sitePw)
	if err != nil || !ok {
		t.Fatalf("fill: %v %v", ok, err)
	}
	if snap, _ = tab.Snapshot(ctx); !strings.Contains(snap.Text, "歡迎，"+testsite.User) {
		t.Fatalf("not logged in after framed form: %q %s", snap.URL, snap.Text)
	}
}

func TestFillFieldsByRef(t *testing.T) {
	m, base := newSite(t)
	ctx := context.Background()
	tab := open(t, m, base+"/sso")
	snap, err := tab.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var user, pass, btn string
	for _, e := range snap.Elements {
		switch {
		case e.Type == "text" && strings.Contains(e.Name, "帳號"):
			user = e.Ref
		case e.Type == "password":
			pass = e.Ref
		case e.Role == "button" && strings.Contains(e.Name, "框架內按鈕"):
			btn = e.Ref
		}
	}
	if user == "" || pass == "" || btn == "" {
		t.Fatalf("refs missing: %+v", snap.Elements)
	}
	origins := []string{base}
	if err := tab.FillFields(ctx, "", user, testsite.User, sitePw, origins); !errors.Is(err, core.ErrNotPassword) {
		t.Fatalf("password into a text field: %v", err)
	}
	if err := tab.FillFields(ctx, pass, "", testsite.User, sitePw, origins); !errors.Is(err, core.ErrNotTextField) {
		t.Fatalf("account into the password field: %v", err)
	}
	if err := tab.FillFields(ctx, "", btn, testsite.User, sitePw, origins); !errors.Is(err, core.ErrNotPassword) {
		t.Fatalf("password into a button: %v", err)
	}
	if err := tab.FillFields(ctx, user, pass, testsite.User, sitePw, []string{"https://elsewhere.example"}); !errors.Is(err, core.ErrFieldOrigin) {
		t.Fatalf("field origin not allowed: %v", err)
	}
	if err := tab.FillFields(ctx, user, "s999-1", testsite.User, sitePw, origins); !errors.Is(err, core.ErrStaleRef) {
		t.Fatalf("stale ref: %v", err)
	}
	if err := tab.FillFields(ctx, user, pass, testsite.User, sitePw, origins); err != nil {
		t.Fatal(err)
	}
	if snap, _ = tab.Snapshot(ctx); !strings.Contains(snap.Text, "歡迎，"+testsite.User) {
		t.Fatalf("not logged in: %q %s", snap.URL, snap.Text)
	}
}

// Local development sites run on plain http; the same fill works there.
func TestLocalHTTPSite(t *testing.T) {
	if Find() == "" || testing.Short() {
		t.Skip("no Chrome, or -short")
	}
	srv := httptest.NewServer(testsite.Handler(sitePw))
	t.Cleanup(srv.Close)
	m := New(Options{ExecPath: Find(), TempRoot: t.TempDir(), Headless: true})
	t.Cleanup(m.Close)
	ctx := context.Background()
	tab := open(t, m, srv.URL+"/two-step")
	if o, _ := tab.Origin(ctx); o != srv.URL {
		t.Fatalf("origin %q want %q", o, srv.URL)
	}
	if ok, err := tab.FillLogin(ctx, testsite.User, sitePw); err != nil || !ok {
		t.Fatalf("fill: %v %v", ok, err)
	}
	if snap, _ := tab.Snapshot(ctx); !strings.Contains(snap.Text, "歡迎，"+testsite.User) {
		t.Fatalf("not logged in: %s", snap.Text)
	}
}
