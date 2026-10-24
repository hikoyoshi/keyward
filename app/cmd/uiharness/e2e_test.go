package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hikoyoshi/keyward/internal/browser"
	"github.com/hikoyoshi/keyward/internal/core"
	"github.com/hikoyoshi/keyward/internal/ipc"
	"github.com/hikoyoshi/keyward/internal/testsite"
)

const e2eSitePw = "E2E-Site!pw9"

// TestMCPEndToEnd drives the whole chain an AI tool uses: an MCP client starts the real keyward-mcp.exe,
// which talks over the named pipe to the Keyward core, which drives a real Chrome on a fake HTTPS site.
// The password must never appear in anything the AI receives.
func TestMCPEndToEnd(t *testing.T) {
	exe := browser.Find()
	if exe == "" || testing.Short() {
		t.Skip("needs Google Chrome")
	}
	dir := t.TempDir()
	mcpExe := filepath.Join(dir, "keyward-mcp.exe")
	if out, err := exec.Command("go", "build", "-o", mcpExe, "../keyward-mcp").CombinedOutput(); err != nil {
		t.Fatalf("build keyward-mcp: %v\n%s", err, out)
	}
	site := httptest.NewTLSServer(testsite.Handler(e2eSitePw))
	defer site.Close()

	br := browser.New(browser.Options{ExecPath: exe, TempRoot: filepath.Join(dir, "browser"), InsecureCerts: true, Headless: true})
	h, err := newHarness(filepath.Join(dir, "data"), br)
	if err != nil {
		t.Fatal(err)
	}
	defer h.svc.Shutdown()
	s := h.svc
	if err := s.Setup("E2E-Master!1", "E2E-Master!1"); err != nil {
		t.Fatal(err)
	}
	item, err := s.Save(core.Input{Type: "login", Name: "示範網站", URL: site.URL + "/login", Alias: "測試帳號", Account: testsite.User, Password: e2eSitePw, AI: true})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := s.AIAddClient("Claude Code")
	if err != nil {
		t.Fatal(err)
	}
	suffix := "-e2e-" + time.Now().Format("150405.000")
	name, _ := ipc.PipeName(suffix)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	go ipc.Serve(ctx, name, s.HandleAgent)
	time.Sleep(200 * time.Millisecond)

	cmd := exec.Command(mcpExe, "-pipe-suffix", suffix)
	cmd.Env = append(os.Environ(), "KEYWARD_TOKEN="+pair.Token)
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "1"}, nil)
	cs, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	var seen strings.Builder // everything the AI received
	callTool := func(tool string, args map[string]any) (string, bool) {
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		text := res.Content[0].(*mcp.TextContent).Text
		seen.WriteString(text)
		return text, res.IsError
	}
	decode := func(text string, v any) {
		t.Helper()
		if err := json.Unmarshal([]byte(text), v); err != nil {
			t.Fatalf("decode %q: %v", text, err)
		}
	}

	tools, err := cs.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 9 {
		t.Fatalf("tools: %v %v", tools, err)
	}

	text, _ := callTool("list_logins", nil)
	var logins []core.AILogin
	decode(text, &logins)
	if len(logins) != 1 || logins[0].ID != item.ID || !logins[0].RequiresApproval {
		t.Fatalf("list_logins: %s", text)
	}

	// The person approves while the AI waits inside request_login.
	go func() {
		for i := 0; i < 100; i++ {
			time.Sleep(100 * time.Millisecond)
			if ov, _ := s.AIOverview(); len(ov.Pending) == 1 {
				s.AIApprove(ov.Pending[0].ID, core.AIApproval{Mode: "site", Minutes: 30})
				return
			}
		}
	}()
	text, _ = callTool("request_login", map[string]any{"item_id": item.ID})
	var r core.AIRequestResult
	decode(text, &r)
	for i := 0; i < 5 && r.Status != core.PhaseLoggedIn; i++ {
		text, _ = callTool("get_status", map[string]any{"request_id": r.RequestID})
		decode(text, &r)
	}
	if r.Status != core.PhaseLoggedIn {
		t.Fatalf("not logged in: %s", text)
	}
	req := map[string]any{"request_id": r.RequestID}

	text, _ = callTool("snapshot", req)
	if !strings.Contains(text, "歡迎") {
		t.Fatalf("snapshot after login: %s", text)
	}
	if _, isErr := callTool("navigate", map[string]any{"request_id": r.RequestID, "url": site.URL + "/account"}); isErr {
		t.Fatal("navigate failed")
	}
	text, _ = callTool("snapshot", req)
	var snap core.Snapshot
	decode(text, &snap)
	pwRef := ""
	for _, e := range snap.Elements {
		if e.Type == "password" {
			pwRef = e.Ref
		}
	}
	if pwRef == "" || !strings.Contains(snap.Text, "●●●") {
		t.Fatalf("account page snapshot: %s", text)
	}
	if text, isErr := callTool("type", map[string]any{"request_id": r.RequestID, "ref": pwRef, "text": "x"}); !isErr || !strings.HasPrefix(text, "password_field") {
		t.Fatalf("type into password: %s", text)
	}
	if text, isErr := callTool("navigate", map[string]any{"request_id": r.RequestID, "url": "javascript:alert(1)"}); !isErr {
		t.Fatalf("javascript url: %s", text)
	}

	// Logged out by the site: fill_credentials logs back in on the site's own page.
	callTool("navigate", map[string]any{"request_id": r.RequestID, "url": site.URL + "/logout"})
	if text, isErr := callTool("fill_credentials", req); isErr || !strings.Contains(text, "filled") {
		t.Fatalf("fill_credentials: %s", text)
	}
	text, _ = callTool("snapshot", req)
	if !strings.Contains(text, "歡迎") {
		t.Fatalf("after re-login: %s", text)
	}

	// Locked Keyward: listing and filling are refused, the running session continues.
	s.Lock(core.ReasonManual)
	if text, isErr := callTool("list_logins", nil); !isErr || !strings.HasPrefix(text, "vault_locked") {
		t.Fatalf("list while locked: %s", text)
	}
	if text, isErr := callTool("fill_credentials", req); !isErr || !strings.HasPrefix(text, "vault_locked") {
		t.Fatalf("fill while locked: %s", text)
	}
	if _, isErr := callTool("snapshot", req); isErr {
		t.Fatal("logged-in work should continue after a manual lock")
	}
	callTool("close_session", req)
	if text, isErr := callTool("snapshot", req); !isErr {
		t.Fatalf("snapshot after close: %s", text)
	}

	// A wrong token is refused before anything else.
	bad := exec.Command(mcpExe, "-pipe-suffix", suffix)
	bad.Env = append(os.Environ(), "KEYWARD_TOKEN=kw_not-paired")
	cs2, err := mcp.NewClient(&mcp.Implementation{Name: "e2e-bad", Version: "1"}, nil).Connect(ctx, &mcp.CommandTransport{Command: bad}, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, _ := cs2.CallTool(ctx, &mcp.CallToolParams{Name: "list_logins"})
	if !res.IsError || !strings.HasPrefix(res.Content[0].(*mcp.TextContent).Text, "unauthorized") {
		t.Fatalf("bad token: %+v", res.Content[0])
	}
	cs2.Close()

	if strings.Contains(seen.String(), e2eSitePw) {
		t.Fatal("the site password reached the AI")
	}
}
