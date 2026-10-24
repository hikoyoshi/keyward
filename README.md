# Keyward

**A personal password manager for Windows that lets AI agents log in to websites for you without ever seeing your passwords.**

[繁體中文說明](README.zh-TW.md)

Keyward (*key* + *steward*) keeps your website logins and other secrets in an encrypted vault on your own computer. When an AI coding agent such as Claude Code, Codex or OpenCode needs to work on a site that requires a login, it asks Keyward. You approve the request in Keyward, and Keyward fills the login into its own Chrome window. The AI then works with the logged-in page through a small set of tools, but the password never reaches the AI's conversation.

> Status: first version, used daily by the author on Windows 10/11. Tested end to end with Claude Code, Codex and OpenCode on a real site with single sign-on. Not audited. Use at your own risk.

## Features

**Password manager**
- Website logins, other passwords (Wi-Fi, licenses, PINs) and secure notes, encrypted with AES-256-GCM; the master password is stretched with Argon2id and never stored.
- Show or copy a password; the clipboard is cleared after 30 seconds and kept out of clipboard history and cloud sync.
- Password generator, search and type filters.
- Auto-lock when idle, when Windows locks and when the computer sleeps.
- A strength check for the master and backup passwords: common passwords and simple patterns are refused (zxcvbn estimate).
- Encrypted backups (`.keyward`) that restore on any computer with the backup password; restoring never overwrites the current vault.
- Import from Chrome, Edge, Firefox or Bitwarden CSV exports, with a preview and duplicate detection.
- Optional 6-digit codes by email (your own SMTP account) to unlock, to reveal a password, or to reset a forgotten master password.
- English and Traditional Chinese interface, chosen automatically from the Windows display language and switchable in Settings.

**AI agent login**
- A local MCP server (`keyward-mcp.exe`) that AI tools start over stdio. It talks to Keyward over a named pipe that only your Windows account can open, and every call carries a pairing token.
- **One-click setup** for Claude Code, Codex and OpenCode: Keyward writes its entry into the tool's own config (after backing the file up). Other MCP clients get a copy-paste snippet.
- An approval window for every login request: deny, allow once (15 minutes), or allow the site for a chosen time (up to 12 hours), optionally kept while Windows is locked and optionally pausing idle auto-lock.
- Tools for the AI: `list_logins`, `request_login`, `get_status`, `snapshot`, `click`, `type`, `navigate`, `fill_credentials`, `close_session`.
- Works with single sign-on pages (an optional "login page URL" per item) and with login forms inside iframes; the AI can point Keyward at fields it did not recognise, and Keyward still does the typing.
- Plain `http://` is accepted only for `localhost`, `127.0.0.1` and `[::1]`, for sites you are developing.
- "Lock all & stop" ends every AI session at once.

## How the password stays away from the AI

| Guarantee | How |
| --- | --- |
| No tool returns a password | The MCP tools have no command that reads one. Snapshots skip password field values, and any text on the page equal to the saved password is replaced with `●●●`. |
| The AI cannot type a password | `type` refuses password fields. Only `fill_credentials` enters the login, and Keyward does the typing. |
| Passwords only go to the right site | Keyward compares protocol, host and port exactly with the item's login URL (or its login page URL) before filling, including the origin of the frame that holds the field. |
| The AI cannot approve itself | Approval happens only in the Keyward window. There is no MCP command to approve, unlock or change settings. |
| No browser back door | Keyward drives Chrome over a private pipe (no remote-debugging port) with a fresh, temporary profile. There are no tools for JavaScript, cookies or screenshots. |

**What it does not protect against.** Keyward and your AI tools normally run under the same Windows account. An AI that can run arbitrary commands could, in theory, read Keyward's memory, the pairing token in its own config file, or the Windows-protected copy used for email unlock. Keyward makes sure passwords do not flow into the AI through its normal tools; it is not a defence against a deliberately malicious program. Keep your AI tool's own sandbox on, and approve only sites you are comfortable letting the AI use, because it can do anything you could do while logged in. If an AI tool can read your mailbox, do not turn on email codes.

## Install (portable)

1. Download `Keyward-portable-<date>.zip` from the [Releases](https://github.com/hikoyoshi/keyward/releases) page and unzip it to a folder you will keep, for example `D:\Tools\Keyward`. Do not move it later: AI tools remember the path of `keyward-mcp.exe`.
   To check the download, compare its SHA-256 with the `.sha256` file attached to the release:
   ```powershell
   (Get-FileHash .\Keyward-portable-<date>.zip -Algorithm SHA256).Hash
   ```
   The executables are not code-signed yet, so Windows SmartScreen may warn the first time you run them.
2. Run `keyward.exe` and create a master password: at least 8 characters with an uppercase letter and a symbol, and not easy to guess. Common passwords and simple patterns such as `Password1!` are refused; a strength meter shows how you are doing. A few unrelated words with digits and symbols (for example `Blue-Tiger-Rain-42!`) are both strong and memorable.
3. Export a backup from Settings and keep it on another drive.

Requirements: Windows 10 or 11 (WebView2 is built in). AI login needs Google Chrome. The vault lives in `%LOCALAPPDATA%\Keyward`, not in the program folder, so deleting the program folder does not delete your passwords.

## Connect an AI tool

1. Edit a website login and tick **Let paired AI tools ask to log in**.
2. Open **AI agent → Add AI connection** and pick your tool. If Keyward finds Claude Code, Codex or OpenCode, click **Auto setup**; otherwise use **Manual setup** and add the snippet to your tool.
3. Restart the AI tool (for Claude Code, start a new conversation) and ask it to log in to the site with Keyward.
4. Approve the request in the Keyward window. If the site asks for an SMS code, an authenticator or a CAPTCHA, finish that yourself in Keyward's Chrome window.

Hermes Agent usually runs in WSL on Windows, which cannot reach Keyward's named pipe; it is listed for manual setup only and is untested.

## Build from source

You need Go 1.25 or later on Windows. No cgo, Node or Wails CLI is required.

```bat
cd app
go test ./...
go build -tags desktop,production -ldflags "-H windowsgui -s -w" -o build\keyward.exe .
go build -ldflags "-s -w" -o build\keyward-mcp.exe .\cmd\keyward-mcp
```

`app\build-portable.cmd` runs the tests, builds both executables and writes `app\dist\Keyward-portable-<date>.zip`.

For development, `go run ./cmd/uiharness -data <scratch folder> -dist frontend/dist` serves the UI in a normal browser with a fake clipboard, mailer and clock; add `-browser -headless` for real Chrome against a built-in test site. Always pass `-data` with a throwaway folder when testing `keyward.exe` so you never touch your real vault.

Technical notes (in Chinese) are in [app/README.md](app/README.md); the design plan is [PLAN.md](PLAN.md).

## Project layout

| Path | What it is |
| --- | --- |
| `app/main.go`, `app/app.go` | Wails desktop app; methods bound to the window |
| `app/frontend/dist` | Plain HTML/CSS/JS interface; `i18n.js` holds the English text |
| `app/internal/vault` | Encrypted SQLite vault, backups |
| `app/internal/core` | All rules: locking, email codes, AI requests and grants |
| `app/internal/browser` | Chrome automation over a private pipe (chromedp) |
| `app/internal/ipc` | Named pipe restricted to the current Windows user |
| `app/internal/aisetup` | One-click MCP setup for Claude Code, Codex and OpenCode |
| `app/cmd/keyward-mcp` | MCP server started by AI tools |
| `app/cmd/uiharness` | Browser-based test harness for the UI |
| `prototype/` | Early clickable prototype with fake data |

## History

Keyward was first called PASS_PW. On its first start Keyward copies a vault from `%LOCALAPPDATA%\PASS_PW` to `%LOCALAPPDATA%\Keyward`, and it still restores `.passpw` backups.

## License

[MIT](LICENSE)
