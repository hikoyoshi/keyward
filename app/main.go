package main

import (
	"embed"
	"flag"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	xwin "golang.org/x/sys/windows"

	"github.com/hikoyoshi/keyward/internal/vault"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// -data lets testing use a throwaway folder instead of the real vault.
	defaultDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "Keyward")
	dataDir := flag.String("data", defaultDir, "folder that holds vault.db")
	flag.Parse()

	if *dataDir == defaultDir {
		legacy := filepath.Join(os.Getenv("LOCALAPPDATA"), "PASS_PW")
		if _, err := os.Stat(filepath.Join(defaultDir, "vault.db")); err != nil && legacyAppRunning() {
			if _, err := os.Stat(filepath.Join(legacy, "vault.db")); err == nil {
				fatal(pick("請先關閉舊版 PASS_PW（passpw.exe），再開啟 Keyward。\n\nKeyward 第一次啟動時會把 PASS_PW 的密碼庫複製過來，舊版開著時可能漏掉尚未寫入的資料。",
					"Please close the old PASS_PW (passpw.exe) first, then open Keyward.\n\nOn its first start Keyward copies the PASS_PW vault; with the old app open it could miss changes not yet written."))
			}
		}
		if _, err := migrateLegacy(legacy, defaultDir); err != nil {
			fatal(pick("無法從舊版 PASS_PW 複製密碼庫：", "Could not copy the vault from the old PASS_PW: ") + err.Error() + pick("\n\n舊資料仍完整保留在 ", "\n\nThe old data is still intact in ") + legacy)
		}
	}

	vaultPath := filepath.Join(*dataDir, "vault.db")
	v, err := vault.Open(vaultPath)
	if err != nil {
		fatal(pick("無法開啟密碼庫：", "Cannot open the vault: ") + err.Error())
	}
	app, err := newApp(v, vaultPath)
	if err != nil {
		fatal(pick("無法啟動：", "Cannot start: ") + err.Error())
	}
	err = wails.Run(&options.App{
		Title:            "Keyward",
		Width:            1120,
		Height:           760,
		MinWidth:         900,
		MinHeight:        640,
		BackgroundColour: &options.RGBA{R: 246, G: 248, B: 252, A: 255},
		AssetServer:      &assetserver.Options{Assets: assets},
		OnStartup:        app.startup,
		OnBeforeClose:    app.beforeClose,
		Bind:             []interface{}{app},
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId:               "keyward-6f2c1e0a-desktop",
			OnSecondInstanceLaunch: app.secondInstance,
		},
		EnableDefaultContextMenu: false,
		Windows: &windows.Options{
			WebviewUserDataPath: filepath.Join(*dataDir, "WebView2"),
			DisablePinchZoom:    true,
			Theme:               windows.Light,
		},
	})
	if err != nil {
		fatal(pick("視窗發生錯誤：", "Window error: ") + err.Error())
	}
}

func fatal(msg string) {
	title, _ := xwin.UTF16PtrFromString("Keyward")
	text, _ := xwin.UTF16PtrFromString(msg)
	xwin.MessageBox(0, text, title, xwin.MB_OK|xwin.MB_ICONERROR)
	os.Exit(1)
}

// pick chooses a startup message by the Windows display language (the window has its own setting).
func pick(zh, en string) string {
	langs, err := xwin.GetUserPreferredUILanguages(xwin.MUI_LANGUAGE_NAME)
	if err == nil && len(langs) > 0 && strings.HasPrefix(strings.ToLower(langs[0]), "zh") {
		return zh
	}
	if err != nil {
		return zh + "\n\n" + en
	}
	return en
}
