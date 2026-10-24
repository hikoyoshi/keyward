# Keyward

**Windows 個人密碼管理器：讓 AI 代理替你登入網站，但永遠看不到你的密碼。**

[English](README.md)

Keyward（Key＋Steward，鑰匙管家）把你的網站帳密和其它機密加密保存在自己的電腦上。當 Claude Code、Codex、OpenCode 這類 AI 工具需要操作一個要登入的網站時，它會向 Keyward 提出要求；你在 Keyward 核准後，Keyward 在自己的 Chrome 視窗填入帳密。AI 之後透過幾個受限的工具操作已登入的頁面，密碼不會進入 AI 的對話。

> 狀態：第一版，作者在 Windows 10/11 上日常使用中。已用 Claude Code、Codex、OpenCode 在含單一登入（SSO）的真實網站完成登入實測。未經第三方安全稽核，請自行評估使用。

## 功能

**密碼管理**
- 網站登入、其它密碼（Wi-Fi、軟體授權、PIN）與安全備註，以 AES-256-GCM 加密；主密碼經 Argon2id 處理，不會以任何形式保存。
- 顯示或複製密碼；剪貼簿 30 秒後清除，並排除在剪貼簿歷程與雲端同步之外。
- 密碼產生器、搜尋與類型篩選。
- 閒置、Windows 鎖定、電腦休眠時自動鎖定。
- 加密備份（`.keyward`），只要備份密碼就能在任何電腦還原；還原時不會覆寫目前的密碼庫。
- 匯入 Chrome、Edge、Firefox、Bitwarden 匯出的 CSV，先預覽並略過重複項目。
- 選配的 Email 6 位數驗證碼（使用你自己的 SMTP 帳號）：可用來解鎖、顯示密碼，或重設忘記的主密碼。
- 中文與英文介面，依 Windows 顯示語言自動選擇，也可在設定切換。

**AI 代理登入**
- 本機 MCP 伺服器（`keyward-mcp.exe`）由 AI 工具以 stdio 啟動，再透過只有你的 Windows 帳號能開啟的具名管道連到 Keyward，每次呼叫都核對配對權杖。
- **一鍵自動設定** Claude Code、Codex、OpenCode：Keyward 先備份該工具的設定檔，再寫入自己的設定。其它支援 MCP 的工具可複製設定片段。
- 每次登入要求都跳出核准視窗：拒絕、允許這次（15 分鐘），或允許此網站一段時間（最長 12 小時），可選擇 Windows 鎖定時保留、授權期間暫停閒置自動鎖定。
- 給 AI 的工具：`list_logins`、`request_login`、`get_status`、`snapshot`、`click`、`type`、`navigate`、`fill_credentials`、`close_session`。
- 支援單一登入頁（每個項目可填選配的「登入頁網址」）與 iframe 內的登入表單；Keyward 認不出欄位時，AI 可以指出欄位，但輸入仍由 Keyward 完成。
- `http://` 只限 `localhost`、`127.0.0.1`、`[::1]`，供本機開發中的網站使用。
- 「全部鎖定並停止」可一次結束所有 AI 工作。

## 密碼怎麼不經過 AI

| 保證 | 做法 |
| --- | --- |
| 工具不會回傳密碼 | MCP 工具沒有讀取密碼的命令；頁面快照不含密碼欄位的值，頁面上出現與已存密碼相同的文字一律換成 `●●●`。 |
| AI 不能輸入密碼 | `type` 會拒絕密碼欄位；只有 `fill_credentials` 能填入帳密，而且是 Keyward 自己輸入。 |
| 密碼只填到正確網站 | 填入前完整比對協定、主機與連接埠是否與項目的登入網址（或登入頁網址）相同，連欄位所在 iframe 的來源也要相符。 |
| AI 不能自己核准 | 核准只能在 Keyward 視窗內進行；MCP 沒有核准、解鎖或修改設定的命令。 |
| 瀏覽器沒有後門 | Keyward 以私有管道控制 Chrome（不開遠端除錯連接埠），每次使用全新的暫存設定檔；沒有執行 JavaScript、讀取 Cookie 或截圖的工具。 |

**不保證的部分。** Keyward 和 AI 工具通常在同一個 Windows 帳號下執行。能執行任意指令的 AI 理論上可以讀取 Keyward 的記憶體、自己設定檔中的配對權杖，或 Email 解鎖用的 Windows 保護資料。Keyward 保證的是密碼不會透過正常工具流進 AI，而不是防禦刻意攻擊的惡意程式。請保持 AI 工具自帶的沙盒開啟，並只核准你放心讓 AI 操作的網站，因為 AI 登入後能做的事和你本人一樣。如果 AI 工具能讀取你的信箱，請不要啟用 Email 驗證碼。

## 安裝（portable 版）

1. 從 [Releases](https://github.com/hikoyoshi/keyward/releases) 下載 `Keyward-portable-日期.zip`，解壓到固定的資料夾（例如 `D:\Tools\Keyward`）。之後不要搬動，因為 AI 工具會記住 `keyward-mcp.exe` 的完整路徑。
2. 執行 `keyward.exe`，建立主密碼（至少 8 個字元，含大寫英文字母與特殊符號）。
3. 到「設定」匯出一份加密備份，存到另一個磁碟。

系統需求：Windows 10 或 11（內建 WebView2）。AI 代理登入需要 Google Chrome。密碼庫存放在 `%LOCALAPPDATA%\Keyward`，不在程式資料夾裡，刪除程式資料夾不會刪除密碼。

## 連接 AI 工具

1. 編輯網站登入項目，勾選「允許已配對的 AI 提出登入要求」。
2. 到「AI 代理」→「新增 AI 連線」選擇工具。偵測到 Claude Code、Codex 或 OpenCode 時按「自動設定」；其它工具按「手動設定」，把設定片段加到該工具。
3. 重新啟動 AI 工具（Claude Code 請開新對話），請它用 Keyward 登入網站。
4. 在 Keyward 視窗核准。網站若要求簡訊碼、驗證器或 CAPTCHA，請你在 Keyward 的 Chrome 視窗自行完成。

Hermes Agent 在 Windows 上通常在 WSL 中執行，連不到 Keyward 的具名管道，所以只提供手動設定，也尚未實測。

## 從原始碼建置

需要 Windows 上的 Go 1.25 以上版本；不需要 cgo、Node 或 Wails CLI。

```bat
cd app
go test ./...
go build -tags desktop,production -ldflags "-H windowsgui -s -w" -o build\keyward.exe .
go build -ldflags "-s -w" -o build\keyward-mcp.exe .\cmd\keyward-mcp
```

`app\build-portable.cmd` 會執行測試、建置兩個執行檔，並產生 `app\dist\Keyward-portable-日期.zip`。

開發時可執行 `go run ./cmd/uiharness -data <暫存資料夾> -dist frontend/dist`，在一般瀏覽器中操作介面（使用假的剪貼簿、郵件與時鐘）；加上 `-browser -headless` 會以真實 Chrome 對內建測試網站進行登入。測試 `keyward.exe` 時請一律加上 `-data` 指定暫存資料夾，避免碰到真正的密碼庫。

技術細節見 [app/README.md](app/README.md)，設計規劃見 [PLAN.md](PLAN.md)。

## 沿革

本專案原名 PASS_PW。Keyward 第一次啟動時會把 `%LOCALAPPDATA%\PASS_PW` 的密碼庫複製到 `%LOCALAPPDATA%\Keyward`，也仍然可以還原 `.passpw` 備份檔。

## 授權

[MIT](LICENSE)
