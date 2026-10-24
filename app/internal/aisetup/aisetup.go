// Package aisetup writes Keyward's MCP entry into an AI tool's own configuration, so the person
// does not have to copy a command or a token by hand. Every file it changes is backed up first and
// replaced atomically; anything it cannot change safely is left alone and reported, and the person
// can still use the manual snippet.
package aisetup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ServerName is the MCP server name Keyward registers under.
const ServerName = "keyward"

// legacyName is the entry the project's old name (PASS_PW) registered; it is removed when it
// still points at passpw-mcp.exe.
const legacyName = "passpw"

const tokenEnv = "KEYWARD_TOKEN"

// Env is where the AI tools live. Tests point it at a temporary folder and a fake runner.
type Env struct {
	Home      string // %USERPROFILE%
	AppData   string // %APPDATA%
	CodexHome string // %CODEX_HOME%, if set
	LookPath  func(string) (string, error)
	// Run executes a command without a console window and returns its combined output.
	Run func(name string, args ...string) (string, error)
	Now func() time.Time
}

// System is the real environment.
func System() Env {
	home, _ := os.UserHomeDir()
	return Env{Home: home, AppData: os.Getenv("APPDATA"), CodexHome: os.Getenv("CODEX_HOME"),
		LookPath: exec.LookPath, Run: runHidden, Now: time.Now}
}

// Tool is one AI tool as found on this computer.
type Tool struct {
	Name   string `json:"name"`   // as shown in Keyward, e.g. "Codex"
	Found  bool   `json:"found"`  // installed or configured on this computer
	Auto   bool   `json:"auto"`   // Keyward can set it up by itself
	Where  string `json:"where"`  // the file or command it uses
	Reason string `json:"reason"` // why automatic setup is not offered, in Chinese
}

// Result says what was changed.
type Result struct {
	Tool    string `json:"tool"`
	Where   string `json:"where"`
	Backup  string `json:"backup,omitempty"`
	Removed bool   `json:"removedLegacy,omitempty"` // an old PASS_PW entry was removed too
	Restart string `json:"restart"`                 // what the person should do next
}

const (
	ClaudeCode = "Claude Code"
	Codex      = "Codex"
	OpenCode   = "OpenCode"
	Hermes     = "Hermes Agent"
)

// Detect reports each supported tool.
func Detect(e Env) []Tool {
	tools := []Tool{}
	if p := e.claudePath(); p != "" {
		tools = append(tools, Tool{Name: ClaudeCode, Found: true, Auto: true, Where: p})
	} else {
		tools = append(tools, Tool{Name: ClaudeCode, Reason: "找不到 claude 指令。"})
	}
	codex := e.codexConfig()
	_, err := os.Stat(filepath.Dir(codex))
	tools = append(tools, Tool{Name: Codex, Found: err == nil, Auto: err == nil, Where: codex, Reason: reasonIf(err != nil, "找不到 Codex 設定資料夾（%USERPROFILE%\\.codex）。")})
	oc, ocErr := e.openCodeConfig()
	tools = append(tools, Tool{Name: OpenCode, Found: ocErr == nil, Auto: ocErr == nil, Where: oc, Reason: reasonIf(ocErr != nil, errText(ocErr))})
	hermes := filepath.Join(e.Home, ".hermes", "config.yaml")
	_, herr := os.Stat(hermes)
	tools = append(tools, Tool{Name: Hermes, Found: herr == nil, Where: hermes,
		Reason: "Hermes Agent 在 Windows 上通常在 WSL 中執行，可能連不到 Keyward。"})
	return tools
}

func reasonIf(c bool, s string) string {
	if c {
		return s
	}
	return ""
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Apply registers exe with token in tool's configuration.
func Apply(e Env, tool, exe, token string) (Result, error) {
	if _, err := os.Stat(exe); err != nil {
		return Result{}, fmt.Errorf("找不到 %s，請把它放在 keyward.exe 同一個資料夾。", filepath.Base(exe))
	}
	switch tool {
	case ClaudeCode:
		return e.applyClaude(exe, token)
	case Codex:
		return e.applyCodex(exe, token)
	case OpenCode:
		return e.applyOpenCode(exe, token)
	}
	return Result{}, fmt.Errorf("%s 不支援自動設定，請使用手動設定。", tool)
}

// ---------- Claude Code: its own CLI ----------

func (e Env) claudePath() string {
	for _, n := range []string{"claude.cmd", "claude.exe", "claude"} {
		if p, err := e.LookPath(n); err == nil {
			return p
		}
	}
	for _, p := range []string{
		filepath.Join(e.AppData, "npm", "claude.cmd"),
		filepath.Join(e.Home, ".local", "bin", "claude.exe"),
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func (e Env) applyClaude(exe, token string) (Result, error) {
	claude := e.claudePath()
	if claude == "" {
		return Result{}, errors.New("找不到 claude 指令，請確認已安裝 Claude Code。")
	}
	r := Result{Tool: ClaudeCode, Where: "claude mcp（使用者範圍）", Restart: "請開一個新的 Claude Code 對話，新的設定才會載入。"}
	// Replace an earlier Keyward entry; remove the old PASS_PW one only if it is really ours.
	e.Run(claude, "mcp", "remove", ServerName, "-s", "user")
	if out, err := e.Run(claude, "mcp", "get", legacyName); err == nil && strings.Contains(strings.ToLower(out), "passpw-mcp") {
		if _, err := e.Run(claude, "mcp", "remove", legacyName, "-s", "user"); err == nil {
			r.Removed = true
		}
	}
	// The name goes before the options: --env takes every following word up to "--".
	out, err := e.Run(claude, "mcp", "add", ServerName, "--scope", "user", "--transport", "stdio",
		"--env", tokenEnv+"="+token, "--", exe)
	if err != nil {
		return Result{}, fmt.Errorf("claude mcp add 失敗：%s", strings.TrimSpace(strings.ReplaceAll(out, token, "kw_…")))
	}
	return r, nil
}

// ---------- Codex: ~/.codex/config.toml ----------

func (e Env) codexConfig() string {
	home := e.CodexHome
	if home == "" {
		home = filepath.Join(e.Home, ".codex")
	}
	return filepath.Join(home, "config.toml")
}

func (e Env) applyCodex(exe, token string) (Result, error) {
	path := e.codexConfig()
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		return Result{}, errors.New("找不到 Codex 設定資料夾，請先開啟過一次 Codex。")
	}
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Result{}, err
	}
	text, removed := codexWithout(string(old))
	if strings.TrimSpace(text) != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	nl := "\n"
	if bytes.Contains(old, []byte("\r\n")) {
		nl = "\r\n"
	}
	block := []string{
		"", "[mcp_servers." + ServerName + "]",
		"command = " + tomlString(exe),
		"args = []",
		"", "[mcp_servers." + ServerName + ".env]",
		tokenEnv + " = " + tomlString(token), "",
	}
	text = strings.TrimRight(text, "\r\n") + nl + strings.Join(block, nl)
	backup, err := e.write(path, old, []byte(text))
	if err != nil {
		return Result{}, err
	}
	return Result{Tool: Codex, Where: path, Backup: backup, Removed: removed, Restart: "請完全關閉 Codex 再重新開啟。"}, nil
}

// codexWithout drops our tables ([mcp_servers.keyward] and its sub-tables) and the old PASS_PW
// ones that still point at passpw-mcp.exe. A table runs until the next line that starts a table.
func codexWithout(text string) (string, bool) {
	lines := strings.SplitAfter(text, "\n")
	type table struct {
		name       string
		start, end int
	}
	var tables []table
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			if len(tables) > 0 {
				tables[len(tables)-1].end = i
			}
			tables = append(tables, table{name: strings.Trim(t, "[] \t"), start: i, end: len(lines)})
		}
	}
	owns := func(name, server string) bool {
		p := "mcp_servers." + server
		return name == p || strings.HasPrefix(name, p+".")
	}
	legacy := false
	for _, t := range tables {
		if t.name == "mcp_servers."+legacyName && strings.Contains(strings.ToLower(strings.Join(lines[t.start:t.end], "")), "passpw-mcp") {
			legacy = true
		}
	}
	drop := make([]bool, len(lines))
	for _, t := range tables {
		if owns(t.name, ServerName) || (legacy && owns(t.name, legacyName)) {
			for i := t.start; i < t.end; i++ {
				drop[i] = true
			}
		}
	}
	var b strings.Builder
	for i, l := range lines {
		if !drop[i] {
			b.WriteString(l)
		}
	}
	return b.String(), legacy
}

// tomlString writes a literal string (no escapes, so Windows paths stay readable) when it can.
func tomlString(s string) string {
	if !strings.ContainsAny(s, "'\r\n") {
		return "'" + s + "'"
	}
	b, _ := json.Marshal(s) // a JSON string is a valid TOML basic string for these characters
	return string(b)
}

// ---------- OpenCode: ~/.config/opencode/opencode.json ----------

func (e Env) openCodeConfig() (string, error) {
	dir := filepath.Join(e.Home, ".config", "opencode")
	if _, err := os.Stat(dir); err != nil {
		return filepath.Join(dir, "opencode.json"), errors.New("找不到 OpenCode 設定資料夾（%USERPROFILE%\\.config\\opencode）。")
	}
	if _, err := os.Stat(filepath.Join(dir, "opencode.jsonc")); err == nil {
		return filepath.Join(dir, "opencode.jsonc"), errors.New("OpenCode 使用含註解的 opencode.jsonc，為避免破壞註解，請使用手動設定。")
	}
	return filepath.Join(dir, "opencode.json"), nil
}

func (e Env) applyOpenCode(exe, token string) (Result, error) {
	path, err := e.openCodeConfig()
	if err != nil {
		return Result{}, err
	}
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Result{}, err
	}
	root := object{}
	if len(bytes.TrimSpace(old)) > 0 {
		if err := json.Unmarshal(old, &root); err != nil {
			return Result{}, errors.New("opencode.json 不是標準 JSON（可能含註解），為避免破壞內容，請使用手動設定。")
		}
	} else {
		root.set("$schema", json.RawMessage(`"https://opencode.ai/config.json"`))
	}
	mcp := object{}
	if raw, ok := root.get("mcp"); ok {
		if err := json.Unmarshal(raw, &mcp); err != nil {
			return Result{}, errors.New("opencode.json 的 mcp 區塊格式不是物件，請使用手動設定。")
		}
	}
	removed := false
	if raw, ok := mcp.get(legacyName); ok && strings.Contains(strings.ToLower(string(raw)), "passpw-mcp") {
		mcp.del(legacyName)
		removed = true
	}
	entry, _ := json.Marshal(struct {
		Type        string            `json:"type"`
		Command     []string          `json:"command"`
		Environment map[string]string `json:"environment"`
		Enabled     bool              `json:"enabled"`
	}{"local", []string{exe}, map[string]string{tokenEnv: token}, true})
	mcp.set(ServerName, entry)
	m, _ := json.Marshal(mcp)
	root.set("mcp", m)
	out, _ := json.Marshal(root)
	var pretty bytes.Buffer
	json.Indent(&pretty, out, "", "  ")
	pretty.WriteByte('\n')
	backup, err := e.write(path, old, pretty.Bytes())
	if err != nil {
		return Result{}, err
	}
	return Result{Tool: OpenCode, Where: path, Backup: backup, Removed: removed, Restart: "請重新啟動 OpenCode。"}, nil
}

// object is a JSON object that keeps its keys in order, so rewriting a config does not shuffle it.
type object struct {
	keys []string
	vals map[string]json.RawMessage
}

func (o *object) get(k string) (json.RawMessage, bool) { v, ok := o.vals[k]; return v, ok }
func (o *object) set(k string, v json.RawMessage) {
	if o.vals == nil {
		o.vals = map[string]json.RawMessage{}
	}
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}
func (o *object) del(k string) {
	delete(o.vals, k)
	for i, x := range o.keys {
		if x == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

func (o *object) UnmarshalJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	t, err := d.Token()
	if err != nil {
		return err
	}
	if t != json.Delim('{') {
		return errors.New("not an object")
	}
	*o = object{}
	for d.More() {
		kt, err := d.Token()
		if err != nil {
			return err
		}
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return err
		}
		o.set(kt.(string), v)
	}
	_, err = d.Token()
	return err
}

func (o object) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		b.Write(o.vals[k])
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// ---------- files ----------

// write backs up the current file (if any) next to it, then replaces it atomically.
func (e Env) write(path string, old, data []byte) (string, error) {
	backup := ""
	if old != nil {
		backup = path + ".keyward-backup-" + e.Now().Format("20060102-150405")
		if err := os.WriteFile(backup, old, 0o600); err != nil {
			return "", fmt.Errorf("無法備份原設定檔：%w", err)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".keyward-*.tmp")
	if err != nil {
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return backup, nil
}
