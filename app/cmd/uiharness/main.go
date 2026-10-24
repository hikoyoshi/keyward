// Command uiharness serves the desktop UI in a normal browser for automated walkthroughs.
// It uses the real vault and core service; only the Wails bridge, the clipboard and the clock are replaced.
// Test tool only: it listens on 127.0.0.1, uses a throwaway data folder and must never hold real secrets.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hikoyoshi/keyward/internal/aisetup"
	"github.com/hikoyoshi/keyward/internal/browser"
	"github.com/hikoyoshi/keyward/internal/core"
	"github.com/hikoyoshi/keyward/internal/ipc"
	"github.com/hikoyoshi/keyward/internal/testsite"
	"github.com/hikoyoshi/keyward/internal/vault"
	"github.com/hikoyoshi/keyward/internal/winsys"
)

type fakeClip struct {
	mu   sync.Mutex
	text string
	seq  uint32
}

func (c *fakeClip) SetSecret(t string) (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.text, c.seq = t, c.seq+1
	return c.seq, nil
}

func (c *fakeClip) ClearIf(seq uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if seq == c.seq {
		c.text = ""
	}
}

// fakeMailer keeps mail in memory so walkthroughs can read the codes; nothing leaves the process.
type fakeMailer struct {
	mu   sync.Mutex
	sent []map[string]any
	fail bool
}

func (m *fakeMailer) Send(cfg core.SMTPConfig, to string, cm core.CodeMail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return fmt.Errorf("535 5.7.8 (fake) authentication failed")
	}
	m.sent = append(m.sent, map[string]any{"to": to, "purpose": cm.Purpose, "code": cm.Code, "expires": cm.Expires.Unix(), "smtpHost": cfg.Host})
	return nil
}

type harness struct {
	pick     string // stands in for the native file dialogs
	savePath string
	mu       sync.Mutex
	offset   time.Duration
	winLock  bool
	events   [][2]string
	clip     *fakeClip
	mail     *fakeMailer
	setup    aisetup.Env
	svc      *core.Service
}

func (h *harness) now() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return time.Now().Add(h.offset) }

func main() {
	data := flag.String("data", "", "throwaway data folder (required)")
	dist := flag.String("dist", "frontend/dist", "UI folder")
	port := flag.Int("port", 8717, "loopback port")
	useBrowser := flag.Bool("browser", false, "drive a real Chrome for AI login (accepts the fake site's self-signed certificate)")
	sitePort := flag.Int("testsite", 8743, "port of the fake HTTPS login site (with -browser)")
	sitePw := flag.String("testsite-password", "Demo-Site!2026", "password the fake site accepts")
	pipeSuffix := flag.String("pipe-suffix", "-harness", "named pipe suffix for keyward-mcp.exe -pipe-suffix")
	headless := flag.Bool("headless", false, "run the AI browser without a window")
	flag.Parse()
	if *data == "" {
		log.Fatal("-data is required so the real vault is never touched")
	}
	var br core.Browser
	if *useBrowser {
		exe := browser.Find()
		if exe == "" {
			log.Fatal("-browser needs Google Chrome")
		}
		root := filepath.Join(*data, "browser")
		browser.CleanStale(root)
		br = browser.New(browser.Options{ExecPath: exe, TempRoot: root, InsecureCerts: true, Headless: *headless})
		go func() {
			srv := httptest.NewUnstartedServer(testsite.Handler(*sitePw))
			l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *sitePort))
			if err != nil {
				log.Fatal(err)
			}
			srv.Listener = l
			srv.StartTLS()
			log.Printf("fake login site: %s/login  (%s / %s)", srv.URL, testsite.User, *sitePw)
		}()
	}
	h, err := newHarness(*data, br)
	if err != nil {
		log.Fatal(err)
	}
	if name, err := ipc.PipeName(*pipeSuffix); err == nil {
		go ipc.Serve(context.Background(), name, h.svc.HandleAgent)
		log.Printf("agent pipe: %s", name)
	}
	go func() {
		for range time.Tick(time.Second) {
			h.svc.Tick()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/", h.api)
	mux.HandleFunc("/harness.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		w.Write([]byte(shim))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			b, err := os.ReadFile(filepath.Join(*dist, "index.html"))
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			html := strings.Replace(string(b), `<script src="app.js">`, `<script src="/harness.js"></script><script src="app.js">`, 1)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(html))
			return
		}
		http.FileServer(http.Dir(*dist)).ServeHTTP(w, r)
	})
	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	log.Printf("UI harness (fake data only): http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, hostOnly(addr, mux)))
}

// newHarness opens (or creates) the throwaway vault in dir with fake clipboard, clock and mailer.
// event queues a notification for the page, like Wails' EventsEmit.
func (h *harness) event(name, data string) {
	h.mu.Lock()
	h.events = append(h.events, [2]string{name, data})
	h.mu.Unlock()
}

func newHarness(dir string, br core.Browser) (*harness, error) {
	v, err := vault.Open(filepath.Join(dir, "vault.db"))
	if err != nil {
		return nil, err
	}
	h := &harness{clip: &fakeClip{}, mail: &fakeMailer{}, setup: fakeSetupEnv(filepath.Join(dir, "fakehome"))}
	h.svc = core.New(v, core.Options{
		VaultPath:     filepath.Join(dir, "vault.db"),
		Clipboard:     h.clip,
		Now:           h.now,
		SessionLocked: func() (bool, bool) { h.mu.Lock(); defer h.mu.Unlock(); return h.winLock, true },
		OnLock:        func(r string) { h.event("locked", r) },
		OnAIEvent:     func(k string) { h.event("ai", k) },
		Browser:       br,
		Protector:     winsys.DPAPI{}, // real DPAPI, but only over the throwaway vault
		Mailer:        h.mail,
	})
	return h, nil
}

// fakeSetupEnv is a pretend user profile for AI auto-setup: Claude Code, Codex and OpenCode are
// "installed" there and the claude command only records its arguments. Real configs are never touched.
func fakeSetupEnv(home string) aisetup.Env {
	for _, d := range []string{filepath.Join(home, "AppData", "npm"), filepath.Join(home, ".codex"), filepath.Join(home, ".config", "opencode")} {
		os.MkdirAll(d, 0o700)
	}
	os.WriteFile(filepath.Join(home, "AppData", "npm", "claude.cmd"), nil, 0o600)
	oc := filepath.Join(home, ".config", "opencode", "opencode.json")
	if _, err := os.Stat(oc); err != nil {
		os.WriteFile(oc, []byte(`{
  "$schema": "https://opencode.ai/config.json",
  "model": "demo/model"
}
`), 0o600)
	}
	log := filepath.Join(home, "claude-calls.txt")
	return aisetup.Env{Home: home, AppData: filepath.Join(home, "AppData"),
		LookPath: func(string) (string, error) { return "", os.ErrNotExist },
		Now:      time.Now,
		Run: func(name string, args ...string) (string, error) {
			f, _ := os.OpenFile(log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
			fmt.Fprintln(f, strings.Join(args, " "))
			f.Close()
			if len(args) > 1 && args[1] == "get" {
				return "No MCP server found", errors.New("exit 1")
			}
			return "ok", nil
		}}
}

func hostOnly(addr string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != addr && r.Host != strings.Replace(addr, "127.0.0.1", "localhost", 1) {
			http.Error(w, "forbidden", 403)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (h *harness) api(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/")
	var args []json.RawMessage
	json.NewDecoder(r.Body).Decode(&args)
	str := func(i int) string {
		var s string
		if i < len(args) {
			json.Unmarshal(args[i], &s)
		}
		return s
	}
	num := func(i int) int {
		var n int
		if i < len(args) {
			json.Unmarshal(args[i], &n)
		}
		return n
	}
	var res any
	var err error
	s := h.svc
	switch name {
	case "Status":
		res = s.Status()
	case "Setup":
		err = s.Setup(str(0), str(1))
	case "Unlock":
		err = s.Unlock(str(0))
	case "Lock":
		s.Lock(core.ReasonManual)
	case "Touch":
		s.Touch()
	case "List":
		res, err = s.List(str(0), str(1))
	case "Get":
		res, err = s.Get(str(0))
	case "Save":
		var in core.Input
		if len(args) > 0 {
			json.Unmarshal(args[0], &in)
		}
		res, err = s.Save(in)
	case "Delete":
		err = s.Delete(str(0))
	case "Reveal":
		res, err = s.Reveal(str(0), str(1))
	case "Copy":
		err = s.Copy(str(0), str(1))
	case "Generate":
		var sym bool
		if len(args) > 1 {
			json.Unmarshal(args[1], &sym)
		}
		res = core.Generate(num(0), sym)
	case "ChangeMaster":
		err = s.ChangeMaster(str(0), str(1), str(2))
	case "SetIdleMinutes":
		err = s.SetIdleMinutes(num(0))
	case "ExportBackup":
		if err = s.PrepareExport(str(0), str(1), str(2)); err == nil {
			if h.savePath == "" {
				res = map[string]any{"cancelled": true}
			} else {
				var info any
				info, err = s.ExportBackup(h.savePath, str(1))
				res = map[string]any{"path": h.savePath, "info": info}
			}
		}
	case "PickBackupFile":
		res = filepath.Base(h.pick)
		if h.pick == "" {
			res = ""
		}
	case "PreviewRestore":
		res, err = s.PreviewRestore(h.pick, str(0))
	case "Restore":
		res, err = s.Restore(str(0), str(1))
	case "CancelRestore":
		s.CancelRestore()
	case "PickCSV":
		if h.pick == "" {
			res = core.CSVPreview{}
		} else {
			res, err = s.PreviewCSV(h.pick)
		}
	case "ImportCSV":
		res, err = s.ImportCSV()
	case "DeleteImportedCSV":
		err = s.DeleteImportedCSV()
	case "SendCode":
		res, err = s.SendCode(str(0), str(1))
	case "UnlockWithCode":
		var reset bool
		if len(args) > 1 {
			json.Unmarshal(args[1], &reset)
		}
		err = s.UnlockWithCode(str(0), reset)
	case "VerifyCode":
		err = s.VerifyCode(str(0), str(1), str(2))
	case "Authorize":
		err = s.Authorize(str(0), str(1))
	case "StartEmailSetup":
		var in core.EmailInput
		if len(args) > 0 {
			json.Unmarshal(args[0], &in)
		}
		res, err = s.StartEmailSetup(in)
	case "FinishEmailSetup":
		res, err = s.FinishEmailSetup(str(0))
	case "EmailSettings":
		res, err = s.EmailSettings()
	case "CancelEmailSetup":
		s.CancelEmailSetup()
	case "DisableEmail":
		err = s.DisableEmail()
	case "AIOverview":
		res, err = s.AIOverview()
	case "AIApprove":
		var ap core.AIApproval
		if len(args) > 1 {
			json.Unmarshal(args[1], &ap)
		}
		err = s.AIApprove(str(0), ap)
	case "AIDeny":
		err = s.AIDeny(str(0))
	case "AIStop":
		err = s.AIStop(str(0))
	case "AIUserDone":
		err = s.AIUserDone(str(0))
	case "AIExtendGrant":
		err = s.AIExtendGrant(str(0), num(1))
	case "AIRevokeGrant":
		err = s.AIRevokeGrant(str(0))
	case "AIRevokeClient":
		err = s.AIRevokeClient(str(0))
	case "LockAll":
		s.Lock(core.ReasonStopAll)
	case "SetLanguage":
		s.SetLanguage(str(0))
	case "AIDetectTools":
		res = aisetup.Detect(h.setup)
	case "AIAutoSetup":
		exe, _ := filepath.Abs(filepath.Join("build", "keyward-mcp.exe"))
		var r aisetup.Result
		n, e := s.AIAutoPair(str(0), func(token string) error {
			var err error
			r, err = aisetup.Apply(h.setup, str(0), exe, token)
			return err
		})
		res, err = map[string]any{"tool": r.Tool, "where": r.Where, "backup": r.Backup, "removedLegacy": r.Removed, "restart": r.Restart, "replaced": n}, e
	case "AIAddClient":
		var p core.AIPairing
		if p, err = s.AIAddClient(str(0)); err == nil {
			exe, _ := filepath.Abs(filepath.Join("build", "keyward-mcp.exe"))
			res = map[string]any{"pairing": p, "snippets": core.AIConfigSnippets(exe, p.Token), "exe": exe, "exeFound": true}
		}
	case "ResetMaster":
		err = s.ResetMaster(str(0), str(1))
	// ---- harness controls ----
	case "_pick": // next file a dialog "chooses"; empty means cancel
		h.pick = r.URL.Query().Get("path")
	case "_savepath":
		h.savePath = r.URL.Query().Get("path")
	case "_mail": // everything the fake mailer "sent", newest last
		h.mail.mu.Lock()
		res = h.mail.sent
		h.mail.mu.Unlock()
	case "_mailfail": // make the next sends fail like a rejected SMTP login
		h.mail.mu.Lock()
		h.mail.fail = r.URL.Query().Get("on") == "1"
		h.mail.mu.Unlock()
	case "_events":
		h.mu.Lock()
		res, h.events = h.events, nil
		h.mu.Unlock()
	case "_clipboard":
		h.clip.mu.Lock()
		res = h.clip.text
		h.clip.mu.Unlock()
	case "_advance": // move the clock forward one second per tick, like real time
		sec, _ := strconv.Atoi(r.URL.Query().Get("sec"))
		for i := 0; i < sec; i++ {
			h.mu.Lock()
			h.offset += time.Second
			h.mu.Unlock()
			s.Tick()
		}
	case "_sleep": // jump the clock without ticks, as when the PC sleeps
		h.mu.Lock()
		h.offset += 2 * time.Hour
		h.mu.Unlock()
		s.Tick()
	case "_winlock":
		h.mu.Lock()
		h.winLock = r.URL.Query().Get("on") == "1"
		h.mu.Unlock()
		s.Tick()
	default:
		http.Error(w, "unknown", 404)
		return
	}
	out := map[string]any{"result": res}
	if err != nil {
		out["error"] = err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// shim stands in for the Wails bridge: window.go.main.App.X(...) and runtime.EventsOn.
const shim = `
(() => {
 const call = async (name, args) => {
  const r = await fetch('/api/' + name, {method:'POST', body: JSON.stringify(args)});
  const d = await r.json();
  if (d.error) throw new Error(d.error);
  return d.result;
 };
 const methods = ['Status','Setup','Unlock','Lock','Touch','List','Get','Save','Delete','Reveal','Copy','Generate','ChangeMaster','SetIdleMinutes','ExportBackup','PickBackupFile','PreviewRestore','Restore','CancelRestore','PickCSV','ImportCSV','DeleteImportedCSV','SendCode','UnlockWithCode','VerifyCode','Authorize','StartEmailSetup','FinishEmailSetup','EmailSettings','CancelEmailSetup','DisableEmail','ResetMaster','AIOverview','AIApprove','AIDeny','AIStop','AIUserDone','AIExtendGrant','AIRevokeGrant','AIRevokeClient','AIAddClient','AIDetectTools','AIAutoSetup','SetLanguage','LockAll'];
 const App = {}; for (const m of methods) App[m] = (...a) => call(m, a);
 window.go = {main: {App}};
 const handlers = {};
 window.runtime = {EventsOn: (n, fn) => { (handlers[n] ||= []).push(fn); }};
 setInterval(async () => { for (const [n, d] of (await call('_events', [])) || []) (handlers[n] || []).forEach(f => f(d)); }, 500);
 window.harness = (name, q = '') => fetch('/api/' + name + q, {method:'POST', body:'[]'}).then(r => r.json()).then(d => d.result);
})();
`
