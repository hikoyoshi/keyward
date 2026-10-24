Keyward 個人密碼管理器（portable 版）
=====================================

Keyward（Key + Steward，鑰匙管家）保管你的網站與其它密碼，也能讓 AI 工具在你核准後
代為登入網站，而 AI 永遠拿不到密碼。原名 PASS_PW。English: README.txt

開始使用
--------
1. 把這個資料夾放到固定位置，例如 D:\Tools\Keyward，之後不要再搬動
   （AI 工具的設定會記住 keyward-mcp.exe 的完整路徑）。
2. 執行 keyward.exe。第一次會請你建立主密碼：至少 8 個字元，含大寫英文字母與特殊符號，
   而且不能太容易被猜到（Password1! 這類常見密碼會被拒絕，輸入時會顯示強度）。
3. 建議到「設定」匯出一份加密備份，存到隨身碟或其它磁碟。

介面語言依 Windows 顯示語言自動選擇（中文或英文），可在「設定 > 語言」切換。

從舊版 PASS_PW 升級
-------------------
- 先關閉 passpw.exe，再開 keyward.exe。Keyward 會自動複製舊密碼庫，主密碼、Email 驗證碼和
  所有項目都沿用。舊資料夾 %LOCALAPPDATA%\PASS_PW 不會被刪除，確認沒問題後可自行刪除。
- AI 工具要重新配對：在「AI 代理」頁撤銷舊連線，再按「新增 AI 連線」→「自動設定」，
  舊的 passpw 設定會一併移除。
- 舊的 .passpw 備份檔可以直接還原。

資料放在哪裡
------------
- 密碼庫：%LOCALAPPDATA%\Keyward\vault.db（加密），不在這個程式資料夾裡。
- 刪除程式資料夾不會刪除密碼庫；要徹底移除，請先匯出備份，再刪除 %LOCALAPPDATA%\Keyward。
- 換電腦：舊電腦「匯出備份」，新電腦開 Keyward 選「從備份還原」。

AI 代理登入
-----------
- 需要 Google Chrome。
- 在項目編輯中勾選「允許已配對的 AI 提出登入要求」，再到「AI 代理」頁新增 AI 連線。
  偵測到 Claude Code、Codex、OpenCode 時按「自動設定」即可（會先備份原設定檔），
  設定後重新啟動該 AI 工具。其它工具用「手動設定」。
- AI 要登入時 Keyward 會跳出核准視窗：拒絕、允許這次（15 分鐘）、允許此網站（可選時間）。
- 緊急時按右上角「全部鎖定並停止」。

忘記主密碼
----------
- 有啟用 Email 驗證碼：鎖定畫面選「忘記主密碼？用 Email 驗證後重設」；已解鎖時也可在
  設定頁「變更主密碼」改寄 Email 驗證碼。
- 沒有啟用 Email 驗證碼：只能從備份還原（需要備份密碼）。

系統需求：Windows 10 / 11（內建 WebView2）。
授權：MIT（LICENSE.txt）。原始碼：https://github.com/hikoyoshi/keyward
