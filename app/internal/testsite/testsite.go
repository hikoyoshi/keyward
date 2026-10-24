// Package testsite is a fake website for testing Keyward's browser login. Test use only.
package testsite

import (
	"fmt"
	"html"
	"net/http"
)

// Accounts on the fake site. MFAUser must enter OTP after the password.
const (
	User    = "demo@example.com"
	MFAUser = "mfa@example.com"
	OTP     = "123456"
)

const page = `<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><title>%s</title>
<style>body{font-family:sans-serif;margin:40px}input,button{display:block;margin:8px 0;padding:6px}</style></head><body>%s</body></html>`

// Handler serves the site; password is the correct password for both accounts.
func Handler(password string) http.Handler {
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, title, body string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, page, title, body)
	}
	session := func(r *http.Request) string {
		if c, err := r.Cookie("demo_session"); err == nil {
			return c.Value
		}
		return ""
	}
	login := func(w http.ResponseWriter, user string) {
		http.SetCookie(w, &http.Cookie{Name: "demo_session", Value: user, Path: "/", HttpOnly: true, Secure: true})
	}
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			user, pw := r.FormValue("username"), r.FormValue("password")
			switch {
			case pw != password:
				http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
			case user == User:
				login(w, user)
				http.Redirect(w, r, "/app", http.StatusSeeOther)
			case user == MFAUser:
				http.SetCookie(w, &http.Cookie{Name: "demo_pending", Value: user, Path: "/", HttpOnly: true, Secure: true})
				http.Redirect(w, r, "/mfa", http.StatusSeeOther)
			default:
				http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
			}
			return
		}
		msg := ""
		if r.URL.Query().Get("error") != "" {
			msg = `<p role="alert">帳號或密碼錯誤</p>`
		}
		write(w, "示範網站登入", msg+`<h1>示範網站登入</h1><form method="post" action="/login">
<label>Email <input type="email" name="username" autocomplete="username"></label>
<label>密碼 <input type="password" name="password" autocomplete="current-password"></label>
<button type="submit">登入</button></form>`)
	})
	mux.HandleFunc("/mfa", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("demo_pending")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost && r.FormValue("code") == OTP {
			login(w, c.Value)
			http.Redirect(w, r, "/app", http.StatusSeeOther)
			return
		}
		write(w, "兩步驟驗證", `<h1>輸入驗證碼</h1><form method="post" action="/mfa">
<input name="code" inputmode="numeric" autocomplete="one-time-code"><button type="submit">驗證</button></form>`)
	})
	// Two-step login: the account first, then the password on a second page.
	mux.HandleFunc("/two-step", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.FormValue("password") == "" {
			write(w, "輸入密碼", `<form method="post" action="/two-step"><input type="hidden" name="username" value="`+html.EscapeString(r.FormValue("username"))+`">
<label>密碼 <input type="password" name="password"></label><button type="submit">登入</button></form>`)
			return
		}
		if r.Method == http.MethodPost {
			if r.FormValue("username") == User && r.FormValue("password") == password {
				login(w, User)
				http.Redirect(w, r, "/app", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/two-step?error=1", http.StatusSeeOther)
			return
		}
		write(w, "登入（第一步）", `<form method="post" action="/two-step"><label>帳號 <input type="text" name="username"></label><button type="submit">下一步</button></form>`)
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		u := session(r)
		if u == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		write(w, "示範網站", `<h1>歡迎，`+html.EscapeString(u)+`</h1><p>這是登入後才看得到的頁面。</p>
<a href="/account">帳號設定</a><a href="/logout">登出</a>
<label>搜尋 <input name="q" id="q"></label><button type="button" onclick="document.getElementById('out').textContent='已搜尋：'+document.getElementById('q').value">搜尋</button><p id="out"></p>`)
	})
	// A careless page that shows the password, to check that snapshots hide it.
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		if session(r) == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		p := html.EscapeString(password)
		write(w, "帳號設定", `<h1>帳號設定</h1><p>你目前的密碼是 `+p+`</p>
<label>密碼 <input type="password" id="pw" value="`+p+`"></label>
<label>顯示的密碼 <input type="text" id="shown" value="`+p+`"></label>
<label>暱稱 <input type="text" id="nick" value="示範使用者"></label>`)
	})
	// A sign-in page that keeps its form two iframes deep, like many single sign-on servers.
	mux.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) {
		write(w, "單一登入", `<h1>單一登入</h1><iframe src="/sso/content" style="width:600px;height:400px"></iframe>`)
	})
	mux.HandleFunc("/sso/content", func(w http.ResponseWriter, r *http.Request) {
		write(w, "content", `<iframe src="/sso/credentials" style="width:560px;height:340px"></iframe>`)
	})
	mux.HandleFunc("/sso/credentials", func(w http.ResponseWriter, r *http.Request) {
		write(w, "credentials", `<form method="post" action="/login" target="_top">
<label>帳號 <input type="text" name="username"></label>
<label>密碼 <input type="password" name="password"></label>
<input type="submit" value="登入"></form>
<button type="button" id="hello" onclick="document.getElementById('said').textContent='框架內按鈕已按下'">框架內按鈕</button><p id="said"></p>`)
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "demo_session", Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	return mux
}
