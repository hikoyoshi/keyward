package main

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/hikoyoshi/keyward/internal/aisetup"
	"github.com/hikoyoshi/keyward/internal/browser"
	"github.com/hikoyoshi/keyward/internal/core"
	"github.com/hikoyoshi/keyward/internal/ipc"
	"github.com/hikoyoshi/keyward/internal/vault"
	"github.com/hikoyoshi/keyward/internal/winsys"
)

// App is the only object bound to the web UI. Every exported method is callable from JavaScript,
// so it exposes exactly the management API and nothing else.
type App struct {
	ctx         context.Context
	svc         *core.Service
	restorePath string // chosen in a native dialog; the web UI never supplies file paths
	lang        atomic.Value
}

func newApp(v *vault.Vault, vaultPath string) (*App, error) {
	clip, err := winsys.NewClipboard()
	if err != nil {
		return nil, err
	}
	a := &App{}
	opt := core.Options{
		VaultPath:     vaultPath,
		Clipboard:     clip,
		SessionLocked: winsys.SessionLocked,
		Protector:     winsys.DPAPI{},
		Mailer:        core.SMTPMailer{},
		OnLock: func(reason string) {
			if a.ctx != nil {
				runtime.EventsEmit(a.ctx, "locked", reason)
			}
		},
		OnAIEvent: a.onAIEvent,
	}
	// AI login uses Keyward's own Chrome with a throwaway profile next to the vault.
	if exe := browser.Find(); exe != "" {
		root := filepath.Join(filepath.Dir(vaultPath), "browser")
		browser.CleanStale(root)
		opt.Browser = browser.New(browser.Options{ExecPath: exe, TempRoot: root})
	}
	a.svc = core.New(v, opt)
	return a, nil
}

// onAIEvent refreshes the window; a new login request also brings Keyward to the front.
func (a *App) onAIEvent(kind string) {
	if a.ctx == nil {
		return
	}
	runtime.EventsEmit(a.ctx, "ai", kind)
	if kind == "request" {
		runtime.WindowUnminimise(a.ctx)
		runtime.WindowShow(a.ctx)
		// Windows often refuses to bring a background window forward; a brief always-on-top
		// raises it above the AI tool's window so the approval is seen.
		runtime.WindowSetAlwaysOnTop(a.ctx, true)
		go func() {
			time.Sleep(1500 * time.Millisecond)
			runtime.WindowSetAlwaysOnTop(a.ctx, false)
		}()
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	// The pipe keyward-mcp.exe connects to; only this Windows user can open it.
	if name, err := ipc.PipeName(""); err == nil {
		go ipc.Serve(ctx, name, a.svc.HandleAgent)
	}
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.svc.Tick()
			}
		}
	}()
}

// beforeClose locks and clears our clipboard content. Closing the window quits the app.
func (a *App) beforeClose(ctx context.Context) bool {
	a.svc.Shutdown()
	return false
}

func (a *App) secondInstance(options.SecondInstanceData) {
	runtime.WindowUnminimise(a.ctx)
	runtime.WindowShow(a.ctx)
}

func (a *App) Status() core.Status                            { return a.svc.Status() }
func (a *App) Setup(master, confirm string) error             { return a.svc.Setup(master, confirm) }
func (a *App) Unlock(master string) error                     { return a.svc.Unlock(master) }
func (a *App) Lock()                                          { a.svc.Lock(core.ReasonManual) }
func (a *App) Touch()                                         { a.svc.Touch() }
func (a *App) List(query, typ string) ([]core.Summary, error) { return a.svc.List(query, typ) }
func (a *App) Get(id string) (core.Detail, error)             { return a.svc.Get(id) }
func (a *App) Save(in core.Input) (core.Detail, error)        { return a.svc.Save(in) }
func (a *App) Delete(id string) error                         { return a.svc.Delete(id) }
func (a *App) Reveal(id, master string) (string, error)       { return a.svc.Reveal(id, master) }
func (a *App) Copy(id, master string) error                   { return a.svc.Copy(id, master) }
func (a *App) Generate(length int, symbols bool) string       { return core.Generate(length, symbols) }
func (a *App) ChangeMaster(current, next, confirm string) error {
	return a.svc.ChangeMaster(current, next, confirm)
}
func (a *App) SetIdleMinutes(m int) error { return a.svc.SetIdleMinutes(m) }

// ---------- email codes ----------
// SMTP calls can take seconds; Wails runs bound methods off the UI thread, so the window stays responsive.

func (a *App) SendCode(purpose, target string) (core.CodeSent, error) {
	return a.svc.SendCode(purpose, target)
}
func (a *App) UnlockWithCode(code string, reset bool) error {
	return a.svc.UnlockWithCode(code, reset)
}
func (a *App) VerifyCode(purpose, target, code string) error {
	return a.svc.VerifyCode(purpose, target, code)
}
func (a *App) Authorize(op, master string) error { return a.svc.Authorize(op, master) }
func (a *App) StartEmailSetup(in core.EmailInput) (core.CodeSent, error) {
	return a.svc.StartEmailSetup(in)
}
func (a *App) FinishEmailSetup(code string) (core.EmailStatus, error) {
	return a.svc.FinishEmailSetup(code)
}
func (a *App) EmailSettings() (core.EmailInput, error) { return a.svc.EmailSettings() }
func (a *App) CancelEmailSetup()                       { a.svc.CancelEmailSetup() }
func (a *App) DisableEmail() error                     { return a.svc.DisableEmail() }
func (a *App) ResetMaster(next, confirm string) error {
	return a.svc.ResetMaster(next, confirm)
}

// ---------- backup, restore and CSV import ----------

type ExportResult struct {
	Cancelled bool             `json:"cancelled"`
	Path      string           `json:"path"`
	Info      vault.BackupInfo `json:"info"`
}

// ExportBackup verifies first, then asks where to save, so a wrong password never opens a dialog.
func (a *App) ExportBackup(master, backupPw, confirm string) (ExportResult, error) {
	if err := a.svc.PrepareExport(master, backupPw, confirm); err != nil {
		return ExportResult{}, err
	}
	docs, _ := os.UserHomeDir()
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:            a.t("儲存加密備份", "Save encrypted backup"),
		DefaultDirectory: filepath.Join(docs, "Documents"),
		DefaultFilename:  "Keyward-" + time.Now().Format("20060102") + ".keyward",
		Filters:          []runtime.FileFilter{{DisplayName: a.t("Keyward 備份 (*.keyward)", "Keyward backup (*.keyward)"), Pattern: "*.keyward"}},
	})
	if err != nil || path == "" {
		return ExportResult{Cancelled: true}, nil
	}
	if filepath.Ext(path) == "" {
		path += ".keyward"
	}
	info, err := a.svc.ExportBackup(path, backupPw)
	return ExportResult{Path: path, Info: info}, err
}

// PickBackupFile returns the chosen file's name, or "" if cancelled.
func (a *App) PickBackupFile() string {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title:   a.t("選擇 Keyward 備份檔", "Choose a Keyward backup file"),
		Filters: []runtime.FileFilter{{DisplayName: a.t("Keyward 備份 (*.keyward, 舊版 *.passpw)", "Keyward backup (*.keyward, old *.passpw)"), Pattern: "*.keyward;*.passpw"}, {DisplayName: a.t("所有檔案", "All files"), Pattern: "*.*"}},
	})
	if err != nil || path == "" {
		return ""
	}
	a.restorePath = path
	return filepath.Base(path)
}

func (a *App) PreviewRestore(backupPw string) (vault.BackupInfo, error) {
	if a.restorePath == "" {
		return vault.BackupInfo{}, &core.UserError{Code: core.CodeInvalid, Msg: "請先選擇備份檔。"}
	}
	return a.svc.PreviewRestore(a.restorePath, backupPw)
}

func (a *App) Restore(master, confirm string) (core.RestoreResult, error) {
	return a.svc.Restore(master, confirm)
}

func (a *App) CancelRestore() { a.svc.CancelRestore(); a.restorePath = "" }

// PickCSV opens a CSV and returns its preview; an empty File means the dialog was cancelled.
func (a *App) PickCSV() (core.CSVPreview, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title:   a.t("選擇瀏覽器匯出的密碼 CSV", "Choose a password CSV exported by a browser"),
		Filters: []runtime.FileFilter{{DisplayName: "CSV (*.csv)", Pattern: "*.csv"}},
	})
	if err != nil || path == "" {
		return core.CSVPreview{}, nil
	}
	return a.svc.PreviewCSV(path)
}

func (a *App) ImportCSV() (core.ImportResult, error) { return a.svc.ImportCSV() }
func (a *App) DeleteImportedCSV() error              { return a.svc.DeleteImportedCSV() }

// ---------- AI agent login ----------

func (a *App) AIOverview() (core.AIOverview, error)          { return a.svc.AIOverview() }
func (a *App) AIApprove(id string, ap core.AIApproval) error { return a.svc.AIApprove(id, ap) }
func (a *App) AIDeny(id string) error                        { return a.svc.AIDeny(id) }
func (a *App) AIStop(id string) error                        { return a.svc.AIStop(id) }
func (a *App) AIUserDone(id string) error                    { return a.svc.AIUserDone(id) }
func (a *App) AIExtendGrant(key string, minutes int) error   { return a.svc.AIExtendGrant(key, minutes) }
func (a *App) AIRevokeGrant(key string) error                { return a.svc.AIRevokeGrant(key) }
func (a *App) AIRevokeClient(id string) error                { return a.svc.AIRevokeClient(id) }
func (a *App) LockAll()                                      { a.svc.Lock(core.ReasonStopAll) }

type AIPairingResult struct {
	Pairing  core.AIPairing   `json:"pairing"`
	Snippets []core.AISnippet `json:"snippets"`
	Exe      string           `json:"exe"`
	ExeFound bool             `json:"exeFound"`
}

// SetLanguage is called by the window: "en" or "zh-TW". It sets the language of native dialogs and
// of the code mails.
func (a *App) SetLanguage(lang string) {
	a.lang.Store(lang)
	a.svc.SetLanguage(lang)
}

// t picks the text for the window's language.
func (a *App) t(zh, en string) string {
	if l, _ := a.lang.Load().(string); l == "en" {
		return en
	}
	return zh
}

// AIDetectTools reports which AI tools Keyward can set up by itself on this computer.
func (a *App) AIDetectTools() []aisetup.Tool { return aisetup.Detect(aisetup.System()) }

type AIAutoResult struct {
	aisetup.Result
	Replaced int `json:"replaced"` // older connections of the same tool that were revoked
}

// AIAutoSetup pairs tool and writes keyward-mcp.exe with the new token into the tool's own
// configuration. The token is never shown.
func (a *App) AIAutoSetup(tool string) (AIAutoResult, error) {
	var res AIAutoResult
	exe := a.mcpExe()
	n, err := a.svc.AIAutoPair(tool, func(token string) error {
		r, err := aisetup.Apply(aisetup.System(), tool, exe, token)
		res.Result = r
		return err
	})
	res.Replaced = n
	return res, err
}

func (a *App) mcpExe() string {
	self, _ := os.Executable()
	return filepath.Join(filepath.Dir(self), "keyward-mcp.exe")
}

// AIAddClient pairs an AI tool and returns its configuration. The token is shown only this once.
func (a *App) AIAddClient(name string) (AIPairingResult, error) {
	p, err := a.svc.AIAddClient(name)
	if err != nil {
		return AIPairingResult{}, err
	}
	exe := a.mcpExe()
	_, statErr := os.Stat(exe)
	return AIPairingResult{Pairing: p, Snippets: core.AIConfigSnippets(exe, p.Token), Exe: exe, ExeFound: statErr == nil}, nil
}
