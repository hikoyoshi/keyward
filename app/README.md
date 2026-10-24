# Keyward 桌面程式（第一版，本機密碼管理）

依 [PLAN.md](../PLAN.md) 第 9 節實作：可以實際保存、查看、備份與還原自己的密碼，可選擇加上 Email 6 位數驗證碼，並讓已配對的 AI 工具在你核准後代為登入網站。

## 已有功能

- 首次設定主密碼（至少 8 個字元，並包含大寫英文字母與特殊符號；不修剪空白，空白不算特殊符號），之後每次開啟都是鎖定狀態。
- 三種項目：網站登入（HTTPS 網址，本機開發中的網站可用 http://localhost、127.0.0.1、[::1]；帳號別名、帳號、密碼、備註、AI 設定先保存）、其它密碼、安全備註。
- 搜尋（名稱、網址、別名、帳號；不搜尋密碼）與類型篩選。
- 顯示密碼 30 秒後自動遮罩，視窗失焦或隱藏時立即遮罩；解鎖或驗證後 60 秒內免再次輸入主密碼。
- 複製密碼：寫入時標記不進入 Windows 剪貼簿歷程與雲端剪貼簿；30 秒後、鎖定或關閉程式時，若剪貼簿仍是該密碼就清除，不會清掉你之後複製的內容。
- 密碼產生器（20 字元，crypto/rand）。
- 主密碼錯誤逐次等待 1、2、4… 秒（最多 30 秒）。
- 自動鎖定：閒置（1／5／15／30 分鐘，可設定）、Windows 鎖定、電腦休眠後。
- 變更主密碼（重新封裝資料金鑰，不重新加密項目）。
- 單一執行個體；關閉視窗即鎖定並結束。
- **加密備份**：設定 → 匯出備份。需重新輸入主密碼，另設備份密碼（規則同主密碼，可以相同）；寫入後立即讀回確認可以還原，失敗不留下檔案。之後有新增、修改、刪除或匯入時，清單上方提示「備份已過期」。
- **從備份還原**：首次設定畫面、鎖定畫面（忘記主密碼時）、設定頁都可進入。先顯示備份時間與筆數，再為新密碼庫設定主密碼。原本的 `vault.db` 不會被覆寫，而是改名為 `vault-before-restore-日期時間.db` 保留在同一資料夾，仍可用舊主密碼開啟。
- **Email 6 位數驗證碼（選配）**：見下方「Email 驗證碼」。
- **匯入 CSV**：支援 Chrome、Edge、Firefox、Bitwarden 匯出的欄位名稱。先預覽（不顯示密碼）：同網站同帳號視為重複並略過；非 HTTPS 或沒有帳號的項目改存為「其它密碼」並把原網址寫進備註；沒有密碼的列略過。匯入後可一鍵刪除該 CSV 檔（一般刪除，不保證從磁碟抹除）。

## Email 驗證碼（選配）

主密碼仍然必設；Email 驗證碼是替代方式，可用於：鎖定畫面解鎖、顯示／複製密碼前的本人驗證、忘記主密碼時驗證後設定新主密碼（舊主密碼隨即失效），以及變更信箱、停用 Email、匯出備份前的重新驗證。

- **設定**：設定 → 本人驗證 → 設定 Email 驗證碼。先重新輸入主密碼，再填自己的 SMTP（伺服器、587 STARTTLS 或 465 TLS、寄件帳號、應用程式密碼）與收件信箱 → 寄出測試驗證碼並輸入成功才啟用。變更信箱時應用程式密碼可留白沿用。
- **忘記主密碼**：鎖定畫面 → 忘記主密碼？用 Email 驗證後重設。驗證後 10 分鐘內可不輸入舊密碼設定新主密碼；若先按「稍後再說」，清單上方與設定頁會出現「設定新主密碼」入口直到時限結束。已經解鎖（例如用一般 Email 驗證碼解鎖）卻不記得主密碼時，可在設定頁「變更主密碼」按「忘記目前的主密碼？改寄 Email 驗證碼」，驗證後設定新主密碼；一組驗證碼只能重設一次。
- **規則**：6 位數（可 0 開頭，crypto/rand）；10 分鐘有效，從產生時起算，休眠或時鐘倒退都不延長（時鐘倒退直接作廢）；一次性，且綁定用途（解鎖／重設主密碼／顯示某一筆／某一個敏感操作／確認新信箱），用在別的用途算錯一次；同一組錯 5 次作廢，連續 3 組作廢後 Email 方式暫停 15 分鐘；重寄間隔至少 60 秒（上一組驗證碼已成功使用時，新的要求不受此限）、每小時最多 5 封（寄送失敗不計入）；寄新碼時舊碼立即失效；只在記憶體保存 HMAC（金鑰於程式啟動時隨機產生）與到期時間，程式重啟後所有待驗證碼失效。
- **收件人**：只寄到已綁定信箱，畫面遮罩顯示（例如 d***@example.com）；鎖定畫面不能改信箱。寄送失敗會顯示郵件伺服器的錯誤，並提供「改用主密碼」。
- **敏感操作**：變更信箱、停用 Email、匯出備份都要當下以主密碼或 Email 驗證碼重新驗證，不沿用解鎖後 60 秒內的免驗證；驗證只放行該一個操作一次（10 分鐘內），鎖定即失效。停用會刪除 Windows 保護的資料金鑰副本、寄信設定與待驗證碼。
- **信件**：固定範本（驗證碼、用途、到期時間、提醒不要告訴任何人），程式沒有寄其它信的功能。
- **保存方式**：啟用後，資料金鑰另以 Windows DPAPI（目前使用者，`CryptProtectData`，並以庫 ID 作為附加 entropy）封裝一份存在 `meta` 表；寄信設定（含應用程式密碼）也以 DPAPI 保存，因此鎖定時仍能寄信。驗證碼通過後才用 DPAPI 封裝解開資料金鑰。這兩份資料不會寫進備份檔，從備份還原的新密碼庫需要重新設定 Email。

**誠實說明**：驗證碼是 Keyward 的放行規則，不是加密金鑰。同一 Windows 帳號下執行的程式（包括能執行指令的 AI 工具）有機會直接呼叫 DPAPI，不經驗證碼解開資料。若 AI 能讀取該信箱，Email 驗證也擋不住 AI。在意這些情況請只用主密碼。換電腦、重灌或換 Windows 帳號後 DPAPI 封裝會無法解開，請改用主密碼並重新設定。

## AI 代理登入

AI 工具（Claude Code、Codex、OpenCode、Hermes Agent 等支援本機 MCP 的工具）可以要求 Keyward 登入網站，由你核准後，Keyward 在**自己控制的 Chrome 視窗**填入帳密。AI 只拿得到頁面內容，拿不到密碼。

### 使用步驟

1. 在項目編輯中勾選「允許已配對的 AI 提出登入要求」，可設定 AI 預設授權時間。
2. 「AI 代理」頁 → 新增 AI 連線 → 選工具。偵測到 Claude Code、Codex 或 OpenCode 時按 **自動設定**：Keyward 直接寫入該工具的設定（Claude Code 透過 `claude mcp add`；Codex 改 `%USERPROFILE%\.codex\config.toml`；OpenCode 改 `%USERPROFILE%\.config\opencode\opencode.json`），先備份原檔（`*.keyward-backup-日期`）、權杖不顯示，並移除舊名稱 PASS_PW 的設定、撤銷同一工具先前的連線。含註解的 `opencode.jsonc`、Hermes Agent 與其它工具則用 **手動設定**，依畫面片段加入（權杖只顯示一次）。`keyward-mcp.exe` 必須和 `keyward.exe` 放在同一資料夾。
3. AI 呼叫 `request_login` 時，Keyward 會跳到前景顯示核准視窗：拒絕、允許這次（15 分鐘），或允許此網站一段時間（30 分鐘～8 小時或自訂，最長 12 小時），並可勾選「Windows 鎖定時保留」「授權期間暫停閒置自動鎖定」。2 分鐘未回應自動拒絕。
4. 遇到簡訊碼、驗證器或 CAPTCHA，請在 Keyward 開的 Chrome 視窗自行完成；完成後 AI 查狀態時會自動發現，或在 AI 代理頁按「我已完成網站驗證」。
5. 任何時候可在 AI 代理頁停止單一工作、延長或撤銷網站授權、撤銷 AI 連線，或按「全部鎖定並停止」。鎖定畫面也有「停止所有 AI 工作」。

### MCP 工具

`list_logins`、`request_login`、`get_status`（最多等 25 秒）、`snapshot`（頁面文字與可操作元素，含 ref）、`click`、`type`、`navigate`、`fill_credentials`（可選 `account_ref`、`password_ref`：自動辨識失敗時，AI 依快照指出欄位，Keyward 負責輸入）、`close_session`。登入未完成（需要本人）時 AI 也能看快照與操作頁面，好協助指出欄位。

### 保護方式

- 工具結果不含密碼：快照不提供密碼欄位的值；頁面上任何與已存密碼相同的文字（例如網站的「顯示密碼」）一律換成 ●●●。
- `type` 不能輸入密碼欄位；`fill_credentials` 只在目前網址的來源（協定、主機、連接埠）與項目登入網址或登入頁網址完全相同時填入（不用字串比對），密碼庫鎖定時拒絕。AI 指定欄位時，密碼只會填入真正的密碼欄位（`type=password`），帳號只填入文字／Email／電話欄位，欄位所在 iframe 的來源也要相符，否則一個字都不輸入。
- `navigate` 只接受 http／https 網址（擋掉 `javascript:` 等）。沒有執行 JavaScript、讀 Cookie、截圖或連到瀏覽器除錯介面的工具。
- Keyward 透過**私有管道**（`--remote-debugging-pipe`）控制 Chrome，不開除錯連接埠；Chrome 使用每次新建的暫存設定檔，關閉 Keyward 時一併關閉並刪除，下次啟動清掉殘留。
- `keyward-mcp.exe` 經具名管道連到 Keyward；管道只允許目前 Windows 使用者開啟，每次呼叫都核對權杖（只存 SHA-256 雜湊於加密設定中），且 request_id 只能由建立它的連線使用。
- 鎖定規則：閒置或手動鎖定時，已登入的工作繼續到授權結束，待核准與未完成的登入取消，鎖定期間不能填入帳密或提出新登入；Windows 鎖定只保留勾選「Windows 鎖定時保留」的已登入工作；休眠、全部鎖定並停止、關閉程式、從備份還原時全部停止。勾選「暫停閒置自動鎖定」的授權有已登入工作時，閒置不會鎖定，結束後閒置計時重新開始。
- 修改項目的網址、帳號、密碼，關閉 AI 開關或刪除項目時，相關 AI 工作與授權立即停止。從備份還原的新密碼庫不保留 AI 連線。

### 限制

- **需要 Google Chrome。** Edge 在 Windows 上不接受私有管道模式，第一版不支援以 Edge 代理登入。
- 登入欄位自動辨識（單頁、先帳號後密碼兩種，也會找同網域 iframe 內的表單）；辨識失敗時可由 AI 指定欄位。其它網域的 iframe 讀不到。
- 網站會跳到另一個網址登入（學校、公司的單一登入 SSO，例如 portal.example.edu 跳到 sso.example.edu:8443）時，在項目的「登入頁網址（選填）」填入那個網址；Keyward 只在登入網址或登入頁網址填入密碼，沒填就停下來請你自行登入。
- 活動紀錄只保留在本次開啟期間的記憶體中（最多 200 筆），關閉程式即清除。
- 與 AI 工具在同一個 Windows 帳號時屬「未隔離」：能執行指令的 AI 理論上可讀取 Keyward 程序記憶體或設定檔中的權杖。Keyward 保證的是密碼不經由工具進入 AI 對話。

## Portable 版與從 PASS_PW 改名

- 執行 `build-portable.cmd` 會跑測試、建置兩個 exe，並產生 `dist\Keyward-portable-日期.zip`（內含 `keyward.exe`、`keyward-mcp.exe`、`README.txt`）。解壓到固定資料夾即可使用，不需要安裝。
- 程式資料夾放好後不要搬動：AI 工具設定裡記的是 `keyward-mcp.exe` 的完整路徑。
- 密碼庫不在程式資料夾，而在 `%LOCALAPPDATA%\Keyward`；換電腦請用「匯出備份 → 還原」。刪除程式資料夾不會刪除密碼庫。
- 本專案原名 PASS_PW。Keyward 第一次啟動時，若 `%LOCALAPPDATA%\Keyward` 還沒有密碼庫，會把 `%LOCALAPPDATA%\PASS_PW` 的密碼庫複製過來（舊資料夾原封不動，並放一個說明檔），主密碼、Email 驗證碼與項目都沿用。舊版 passpw.exe 開著時會先要求關閉。
- 改名後 AI 工具需要重新配對：MCP 名稱改為 `keyward`、程式改為 `keyward-mcp.exe`、環境變數改為 `KEYWARD_TOKEN`。舊的 `passpw` 設定可移除（`claude mcp remove passpw -s user`），並在「AI 代理」頁撤銷舊連線。
- 舊版 `.passpw` 備份檔仍可還原；新的備份副檔名為 `.keyward`。加密格式中的內部標籤保留舊名，所以舊資料不受影響。

## 資料與加密

- 位置：`%LOCALAPPDATA%\Keyward\vault.db`（WebView2 資料在同資料夾的 `WebView2`）。
- 隨機 256-bit 資料金鑰；主密碼經 Argon2id（t=3、64 MiB、4 執行緒，隨庫保存）封裝。
- 每個項目整筆以 AES-256-GCM 加密，AAD 綁定庫 ID、項目 ID 與修訂版本；設定也加密。資料表只有項目 ID、修訂版本與密文。
- 讀到較新或未知格式會拒絕開啟；KDF 參數有上限，避免被竄改的檔案耗盡資源。

### 備份檔格式（.keyward；舊名 PASS_PW 時期為 .passpw，仍可還原）

JSON 標頭（格式、版本、Argon2id 參數、salt）加上一段 AES-256-GCM 密文。標頭整體作為 AAD，竄改成本參數或任何位元都會解密失敗；建立時間、筆數與所有項目都在密文內。備份只依賴備份密碼，不依賴這台電腦，可在另一台電腦或另一個 Windows 帳號還原。讀取時限制檔案大小（64 MB）與 KDF 參數上限，拒絕較新版本或無效項目。

**請把備份檔另外存到隨身碟或其它磁碟，並記住備份密碼。** 沒有備份時，忘記主密碼或檔案損毀就無法找回資料。

## 建置與執行

需要 Go 1.25+ 與 Windows 10/11（內建 WebView2 Runtime）。不需要 cgo、gcc、Node 或 Wails CLI。

```powershell
Set-Location D:\PASS_PW\app
go test ./...
go build -tags desktop,production -ldflags "-H windowsgui -s -w" -o build\keyward.exe .
go build -ldflags "-s -w" -o build\keyward-mcp.exe .\cmd\keyward-mcp
.\build\keyward.exe
```

測試用其它資料夾（不碰正式密碼庫）：

```powershell
.\build\keyward.exe -data D:\temp\keyward-test
```

## 程式結構

| 路徑 | 內容 |
| --- | --- |
| `internal/vault` | 加密、SQLite（modernc.org/sqlite，純 Go）、項目驗證；含竄改、版本回滾、無明文落地等測試 |
| `internal/core` | 鎖定、閒置、Windows 鎖定／休眠偵測、60 秒免驗證、錯誤等待、剪貼簿清除規則；Email 驗證碼規則（`email.go`）與 SMTP 寄信（`smtp.go`，標準庫 `net/smtp`，可替換的 `Mailer` 介面） |
| `internal/winsys` | Win32：私密剪貼簿寫入、查詢工作階段是否鎖定、DPAPI 封裝 |
| `internal/core/ai.go` | AI 代理登入規則：要求／核准／授權狀態機、鎖定時的處理、配對權杖、快照遮蔽；`agentapi.go` 為管道請求分派，`aiconfig.go` 產生各 AI 工具設定片段 |
| `internal/browser` | 以 chromedp 經私有管道控制 Chrome：開分頁、自動填入登入、判斷是否需要本人驗證、快照、點擊、輸入 |
| `frontend/dist/i18n.js` | 英文介面：中英對照表；英文模式下畫面更新時即時翻譯文字與後端訊息（語言存在 WebView2 的 localStorage，並告知核心以決定 Email 與檔案對話框語言） |
| `internal/aisetup` | 自動設定：偵測 Claude Code／Codex／OpenCode，備份後寫入各自的 MCP 設定（保留其它內容與順序） |
| `internal/ipc` | 具名管道（go-winio），只允許目前 Windows 使用者；一次連線一個 JSON 請求 |
| `cmd/keyward-mcp` | AI 工具啟動的 MCP 伺服器（官方 MCP Go SDK，stdio），把 9 個工具轉送到 Keyward |
| `internal/testsite` | 測試用假網站（登入、兩步驟登入、MFA、會顯示密碼的頁面） |
| `app.go`、`main.go` | Wails 2 視窗；只綁定管理 API |
| `frontend/dist` | 介面（HTML／CSS／JavaScript，無建置步驟、無遠端資源） |
| `cmd/uiharness` | 測試工具：在一般瀏覽器用同一套介面與核心做自動化演練（假剪貼簿、可控時鐘、以 `_pick`／`_savepath` 代替檔案對話框；假寄信器不連網，`_mail` 讀出「寄出」的驗證碼、`_mailfail?on=1` 模擬寄送失敗）；只監聽 127.0.0.1，必須指定 `-data` 暫存資料夾；`-browser` 啟用真實 Chrome 與假網站（https://127.0.0.1:8743），管道後綴 `-harness` 可給 `keyward-mcp.exe -pipe-suffix -harness` 使用。`e2e_test.go` 以 MCP 用戶端啟動真正的 keyward-mcp.exe，經管道與 Chrome 走完整流程。`main_test.go` 不開連接埠，透過同一組 API 走過 Email 主要流程 |

## 與規劃的差異

- 介面用純 JavaScript，未用 TypeScript，以免第一版需要前端建置工具。
- 尚未設定 `%LOCALAPPDATA%\Keyward` 的明確 ACL（沿用使用者資料夾預設權限）。
- Windows 鎖定以每秒查詢工作階段狀態偵測；休眠以時鐘跳動超過 30 秒判斷。
- 程式圖示、安裝程式、程式碼簽章尚未處理。
- 首次設定畫面沒有「綁定 Email」步驟；建立密碼庫後到設定頁啟用。
- 寄信設定以 DPAPI 保存，不放在主密碼加密的設定中，否則鎖定時無法寄信。
