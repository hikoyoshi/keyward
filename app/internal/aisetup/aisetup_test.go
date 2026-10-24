package aisetup

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const token = "kw_TESTTOKEN"

type fakeEnv struct {
	Env
	calls [][]string
	get   string // output of "claude mcp get passpw"
}

func setup(t *testing.T) (*fakeEnv, string) {
	t.Helper()
	home := t.TempDir()
	f := &fakeEnv{}
	f.Env = Env{Home: home, AppData: filepath.Join(home, "AppData"),
		LookPath: func(string) (string, error) { return "", errors.New("none") },
		Now:      func() time.Time { return time.Date(2026, 10, 23, 9, 0, 0, 0, time.Local) },
		Run: func(name string, args ...string) (string, error) {
			f.calls = append(f.calls, append([]string{name}, args...))
			if len(args) >= 2 && args[1] == "get" {
				if f.get == "" {
					return "No MCP server found", errors.New("exit 1")
				}
				return f.get, nil
			}
			return "ok", nil
		}}
	exe := filepath.Join(home, "Keyward", "keyward-mcp.exe")
	os.MkdirAll(filepath.Dir(exe), 0o700)
	os.WriteFile(exe, []byte("x"), 0o600)
	return f, exe
}

func write(t *testing.T, path, s string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o700)
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDetect(t *testing.T) {
	f, _ := setup(t)
	byName := func() map[string]Tool {
		m := map[string]Tool{}
		for _, x := range Detect(f.Env) {
			m[x.Name] = x
		}
		return m
	}
	m := byName()
	if m[ClaudeCode].Auto || m[Codex].Auto || m[OpenCode].Auto || m[Hermes].Auto {
		t.Fatalf("nothing installed: %+v", m)
	}
	write(t, filepath.Join(f.AppData, "npm", "claude.cmd"), "")
	os.MkdirAll(filepath.Join(f.Home, ".codex"), 0o700)
	os.MkdirAll(filepath.Join(f.Home, ".config", "opencode"), 0o700)
	write(t, filepath.Join(f.Home, ".hermes", "config.yaml"), "")
	m = byName()
	if !m[ClaudeCode].Auto || !m[Codex].Auto || !m[OpenCode].Auto {
		t.Fatalf("installed: %+v", m)
	}
	if !m[Hermes].Found || m[Hermes].Auto {
		t.Fatalf("Hermes stays manual: %+v", m[Hermes])
	}
}

func TestClaudeCode(t *testing.T) {
	f, exe := setup(t)
	write(t, filepath.Join(f.AppData, "npm", "claude.cmd"), "")
	f.get = "passpw:\n  Command: D:\\PASS_PW\\app\\build\\passpw-mcp.exe\n"
	r, err := Apply(f.Env, ClaudeCode, exe, token)
	if err != nil || !r.Removed {
		t.Fatalf("%+v %v", r, err)
	}
	last := strings.Join(f.calls[len(f.calls)-1][1:], " ")
	if want := "mcp add keyward --scope user --transport stdio --env KEYWARD_TOKEN=" + token + " -- " + exe; last != want {
		t.Fatalf("add:\n%s\nwant\n%s", last, want)
	}
	// An unrelated "passpw" entry is someone else's: leave it.
	f.calls, f.get = nil, "passpw:\n  Command: npx other-tool\n"
	if r, _ := Apply(f.Env, ClaudeCode, exe, token); r.Removed {
		t.Fatal("removed an entry that is not ours")
	}
	for _, c := range f.calls {
		if strings.Join(c[1:4], " ") == "mcp remove passpw" {
			t.Fatal("removed an entry that is not ours")
		}
	}
}

func TestCodexKeepsOtherSettings(t *testing.T) {
	f, exe := setup(t)
	path := filepath.Join(f.Home, ".codex", "config.toml")
	orig := "model = \"gpt\"\r\n\r\n[mcp_servers.node_repl]\r\ncommand = 'C:\\x\\node.exe'\r\n\r\n" +
		"[mcp_servers.passpw]\r\ncommand = 'D:\\PASS_PW\\app\\build\\passpw-mcp.exe'\r\n\r\n[mcp_servers.passpw.env]\r\nPASSPW_TOKEN = \"ppw_old\"\r\n\r\n" +
		"[mcp_servers.keyward]\r\ncommand = 'old'\r\n\r\n[mcp_servers.keyward.env]\r\nKEYWARD_TOKEN = \"kw_old\"\r\n\r\n[features]\r\nx = true\r\n"
	write(t, path, orig)
	r, err := Apply(f.Env, Codex, exe, token)
	if err != nil || !r.Removed || r.Backup == "" {
		t.Fatalf("%+v %v", r, err)
	}
	got := read(t, path)
	for _, want := range []string{"model = \"gpt\"", "[mcp_servers.node_repl]", "[features]", "x = true",
		"[mcp_servers.keyward]\r\ncommand = '" + exe + "'", "[mcp_servers.keyward.env]\r\nKEYWARD_TOKEN = '" + token + "'"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in\n%s", want, got)
		}
	}
	for _, gone := range []string{"passpw", "kw_old", "'old'"} {
		if strings.Contains(got, gone) {
			t.Fatalf("%q still there:\n%s", gone, got)
		}
	}
	if strings.Count(got, "[mcp_servers.keyward]") != 1 {
		t.Fatalf("duplicate table:\n%s", got)
	}
	if read(t, r.Backup) != orig {
		t.Fatal("backup differs from the original")
	}
	// Running it again stays a single entry.
	f.Now = func() time.Time { return time.Date(2026, 10, 23, 9, 1, 0, 0, time.Local) }
	Apply(f.Env, Codex, exe, token)
	if strings.Count(read(t, path), "[mcp_servers.keyward]") != 1 {
		t.Fatal("second run duplicated the table")
	}
}

func TestCodexNewFileAndQuote(t *testing.T) {
	f, _ := setup(t)
	os.MkdirAll(filepath.Join(f.Home, ".codex"), 0o700)
	exe := filepath.Join(f.Home, "it's here", "keyward-mcp.exe")
	write(t, exe, "x")
	r, err := Apply(f.Env, Codex, exe, token)
	if err != nil || r.Backup != "" {
		t.Fatalf("%+v %v", r, err)
	}
	b, _ := json.Marshal(exe)
	if got := read(t, r.Where); !strings.Contains(got, "command = "+string(b)) {
		t.Fatalf("path with a quote:\n%s", got)
	}
}

func TestOpenCodeKeepsOrderAndOthers(t *testing.T) {
	f, exe := setup(t)
	path := filepath.Join(f.Home, ".config", "opencode", "opencode.json")
	orig := `{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "pencil": {"type": "local", "command": ["p.exe"], "enabled": true},
    "passpw": {"type": "local", "command": ["D:\\PASS_PW\\app\\build\\passpw-mcp.exe"], "environment": {"PASSPW_TOKEN": "ppw_old"}}
  },
  "model": "x/y",
  "provider": {}
}`
	write(t, path, orig)
	r, err := Apply(f.Env, OpenCode, exe, token)
	if err != nil || !r.Removed || r.Backup == "" {
		t.Fatalf("%+v %v", r, err)
	}
	got := read(t, path)
	var d struct {
		MCP map[string]struct {
			Type        string            `json:"type"`
			Command     []string          `json:"command"`
			Environment map[string]string `json:"environment"`
			Enabled     bool              `json:"enabled"`
		} `json:"mcp"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal([]byte(got), &d); err != nil {
		t.Fatal(err)
	}
	k := d.MCP["keyward"]
	if k.Type != "local" || len(k.Command) != 1 || k.Command[0] != exe || k.Environment["KEYWARD_TOKEN"] != token || !k.Enabled {
		t.Fatalf("entry: %+v", k)
	}
	if _, ok := d.MCP["passpw"]; ok || d.MCP["pencil"].Command[0] != "p.exe" || d.Model != "x/y" {
		t.Fatalf("others changed:\n%s", got)
	}
	if strings.Index(got, `"$schema"`) > strings.Index(got, `"mcp"`) || strings.Index(got, `"mcp"`) > strings.Index(got, `"model"`) {
		t.Fatalf("key order changed:\n%s", got)
	}
}

func TestOpenCodeRefusesComments(t *testing.T) {
	f, exe := setup(t)
	path := filepath.Join(f.Home, ".config", "opencode", "opencode.json")
	orig := "{\n  // my settings\n  \"model\": \"x\"\n}\n"
	write(t, path, orig)
	if _, err := Apply(f.Env, OpenCode, exe, token); err == nil {
		t.Fatal("rewrote a file with comments")
	}
	if read(t, path) != orig {
		t.Fatal("file changed")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("left files behind: %d", len(entries))
	}
}

func TestMissingExe(t *testing.T) {
	f, _ := setup(t)
	os.MkdirAll(filepath.Join(f.Home, ".codex"), 0o700)
	if _, err := Apply(f.Env, Codex, filepath.Join(f.Home, "nope.exe"), token); err == nil {
		t.Fatal("no keyward-mcp.exe")
	}
	if _, err := os.Stat(filepath.Join(f.Home, ".codex", "config.toml")); err == nil {
		t.Fatal("wrote config without the exe")
	}
}
