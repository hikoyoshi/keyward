package core

import (
	"encoding/json"
	"strings"
)

// AISnippet is a ready-to-paste MCP configuration for one AI tool.
type AISnippet struct {
	Tool  string `json:"tool"`
	Where string `json:"where"`
	Text  string `json:"text"`
}

// AIConfigSnippets builds the configuration that points an AI tool at keyward-mcp.exe with its token.
// The token lives in the tool's configuration; anyone who can read that file can use the pairing,
// which is why every login still needs approval in Keyward and pairings can be revoked.
func AIConfigSnippets(exe, token string) []AISnippet {
	q, _ := json.Marshal(exe)
	jsonCfg := func(v any) string {
		b, _ := json.MarshalIndent(v, "", "  ")
		return string(b)
	}
	return []AISnippet{
		{Tool: "Claude Code", Where: "在終端機執行一次", Text: `claude mcp add keyward --scope user --transport stdio --env KEYWARD_TOKEN=` + token + ` -- "` + exe + `"`},
		{Tool: "Codex", Where: `加到 %USERPROFILE%\.codex\config.toml`, Text: "[mcp_servers.keyward]\ncommand = '" + strings.ReplaceAll(exe, "'", "''") + "'\nenv = { KEYWARD_TOKEN = \"" + token + "\" }"},
		{Tool: "OpenCode", Where: "加到 opencode.json 的 mcp 區塊", Text: jsonCfg(map[string]any{"mcp": map[string]any{"keyward": map[string]any{
			"type": "local", "command": []string{exe}, "environment": map[string]string{"KEYWARD_TOKEN": token}}}})},
		{Tool: "Hermes Agent", Where: "加到 config.yaml 的 mcp_servers（格式以 Hermes 文件為準）", Text: "mcp_servers:\n  keyward:\n    command: " + string(q) + "\n    env:\n      KEYWARD_TOKEN: \"" + token + "\""},
		{Tool: "其它支援 MCP 的工具", Where: "常見的 mcpServers JSON 格式", Text: jsonCfg(map[string]any{"mcpServers": map[string]any{"keyward": map[string]any{
			"command": exe, "env": map[string]string{"KEYWARD_TOKEN": token}}}})},
	}
}
