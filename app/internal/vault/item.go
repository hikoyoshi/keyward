package vault

import (
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Item types.
const (
	TypeLogin    = "login"
	TypePassword = "password"
	TypeNote     = "note"
)

// Item is one stored entry. ID and Revision live in the table; everything else is encrypted.
type Item struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	URL      string `json:"url,omitempty"`
	Origin   string `json:"origin,omitempty"`
	// LoginURL is where the site sends you to sign in when that is another address (school or company
	// single sign-on). Keyward fills the password only at Origin or LoginOrigin.
	LoginURL    string `json:"loginUrl,omitempty"`
	LoginOrigin string `json:"loginOrigin,omitempty"`
	Alias       string `json:"alias,omitempty"`
	Account     string `json:"account,omitempty"`
	Password    string `json:"password,omitempty"`
	Note        string `json:"note,omitempty"`
	AI          bool   `json:"ai,omitempty"`
	GrantMin    int    `json:"grantMin,omitempty"`
	Created     int64  `json:"created"`
	Updated     int64  `json:"updated"`
}

// Secret is what "show" and "copy" reveal: the note body for secure notes, otherwise the password.
func (it Item) Secret() string {
	if it.Type == TypeNote {
		return it.Note
	}
	return it.Password
}

// ValidationError carries a message meant for the person using the app.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(msg string) error { return &ValidationError{Msg: msg} }

var allowedGrant = map[int]bool{30: true, 60: true, 120: true, 240: true, 480: true}

const maxField = 4096

// SiteURLAllowed reports whether a login may be saved for u: HTTPS, or plain HTTP on this computer
// only (localhost, 127.0.0.1, [::1]) for web tools under development. Never with credentials in the URL.
func SiteURLAllowed(u *url.URL) bool {
	if u == nil || u.Host == "" || u.User != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := strings.ToLower(u.Hostname())
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}

// normalize validates user input and fills derived fields. Secrets are never trimmed.
func normalize(it *Item) error {
	it.Name = strings.TrimSpace(it.Name)
	if it.Name == "" {
		return invalid("請輸入名稱。")
	}
	for _, f := range []string{it.Name, it.URL, it.LoginURL, it.Alias, it.Account, it.Password} {
		if len(f) > maxField || !utf8.ValidString(f) {
			return invalid("欄位內容過長或格式不正確。")
		}
	}
	if len(it.Note) > 64*1024 || !utf8.ValidString(it.Note) {
		return invalid("備註內容過長或格式不正確。")
	}
	switch it.Type {
	case TypeLogin:
		u, err := url.Parse(strings.TrimSpace(it.URL))
		if err != nil || u.Host == "" {
			return invalid("請輸入完整網址，例如 https://example.com/login。")
		}
		if !SiteURLAllowed(u) {
			return invalid("只接受 HTTPS 網址（本機開發可用 http://localhost、127.0.0.1），且網址不能包含帳號密碼。")
		}
		u.Host = strings.ToLower(u.Host)
		u.Fragment = ""
		it.URL = u.String()
		it.Origin = u.Scheme + "://" + u.Host
		it.LoginURL, it.LoginOrigin = strings.TrimSpace(it.LoginURL), ""
		if it.LoginURL != "" {
			l, err := url.Parse(it.LoginURL)
			if err != nil || l.Host == "" {
				return invalid("登入頁網址請輸入完整網址，例如 https://sso.example.com。")
			}
			if !SiteURLAllowed(l) {
				return invalid("登入頁網址只接受 HTTPS（本機開發可用 http://localhost、127.0.0.1），且不能包含帳號密碼。")
			}
			l.Host = strings.ToLower(l.Host)
			l.Fragment = ""
			it.LoginURL = l.String()
			it.LoginOrigin = l.Scheme + "://" + l.Host
			if it.LoginOrigin == it.Origin {
				it.LoginURL, it.LoginOrigin = "", ""
			}
		}
		it.Alias = strings.TrimSpace(it.Alias)
		it.Account = strings.TrimSpace(it.Account)
		if it.Alias == "" || it.Account == "" {
			return invalid("請輸入帳號別名與帳號。")
		}
		if it.GrantMin == 0 {
			it.GrantMin = 30
		}
		if !allowedGrant[it.GrantMin] {
			return invalid("AI 預設授權時間不正確。")
		}
	case TypePassword:
		it.URL, it.Origin, it.LoginURL, it.LoginOrigin, it.Alias, it.AI, it.GrantMin = "", "", "", "", "", false, 0
		it.Account = strings.TrimSpace(it.Account)
	case TypeNote:
		it.URL, it.Origin, it.LoginURL, it.LoginOrigin, it.Alias, it.Account, it.Password, it.AI, it.GrantMin = "", "", "", "", "", "", "", false, 0
	default:
		return errors.New("vault: unknown item type")
	}
	if it.Secret() == "" {
		if it.Type == TypeNote {
			return invalid("請輸入內容。")
		}
		return invalid("請輸入密碼。")
	}
	return nil
}
