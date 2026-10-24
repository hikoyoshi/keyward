package core

import (
	"bytes"
	"encoding/csv"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/hikoyoshi/keyward/internal/vault"
)

const (
	maxCSVBytes = 10 << 20
	maxCSVRows  = 10000
)

// Import actions shown in the preview.
const (
	ActionLogin     = "login"     // new website login
	ActionPassword  = "password"  // saved as 其它密碼 because the address is not HTTPS
	ActionDuplicate = "duplicate" // same site and account already exists
	ActionSkip      = "skip"      // no password, nothing to keep
)

type CSVRow struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	Account string `json:"account"`
	Action  string `json:"action"`
}

type CSVPreview struct {
	File       string   `json:"file"`
	Rows       []CSVRow `json:"rows"`
	New        int      `json:"new"`
	AsPassword int      `json:"asPassword"`
	Duplicate  int      `json:"duplicate"`
	Skipped    int      `json:"skipped"`
}

// Header names used by Chrome, Edge, Firefox and Bitwarden exports.
var csvColumns = map[string][]string{
	"name":     {"name", "title"},
	"url":      {"url", "login_uri", "website", "origin"},
	"username": {"username", "login_username", "user", "email"},
	"password": {"password", "login_password"},
	"note":     {"note", "notes", "extra"},
}

// parseCSV turns an exported file into items; passwords stay in memory only.
func parseCSV(path string, existing []vault.Item) (CSVPreview, []vault.Item, error) {
	f, err := os.Open(path)
	if err != nil {
		return CSVPreview{}, nil, uerr(CodeInvalid, "無法開啟這個檔案。")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxCSVBytes+1))
	if err != nil || len(raw) > maxCSVBytes {
		return CSVPreview{}, nil, uerr(CodeInvalid, "檔案太大或無法讀取（上限 10 MB）。")
	}
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	r := csv.NewReader(bytes.NewReader(raw))
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil || len(records) < 1 {
		return CSVPreview{}, nil, uerr(CodeInvalid, "不是可讀取的 CSV 檔。")
	}
	col := map[string]int{}
	for i, h := range records[0] {
		h = strings.ToLower(strings.TrimSpace(h))
		for key, names := range csvColumns {
			for _, n := range names {
				if h == n {
					if _, seen := col[key]; !seen {
						col[key] = i
					}
				}
			}
		}
	}
	if _, ok := col["password"]; !ok {
		return CSVPreview{}, nil, uerr(CodeInvalid, "找不到 password 欄位。請使用瀏覽器或密碼管理器匯出的 CSV。")
	}
	if len(records)-1 > maxCSVRows {
		return CSVPreview{}, nil, uerr(CodeInvalid, "資料列太多（上限 10000 列）。")
	}
	seen := map[string]bool{}
	for _, it := range existing {
		seen[dupKey(it)] = true
	}
	get := func(rec []string, key string) string {
		if i, ok := col[key]; ok && i < len(rec) {
			return rec[i]
		}
		return ""
	}
	prev := CSVPreview{Rows: []CSVRow{}}
	var items []vault.Item
	for _, rec := range records[1:] {
		pw := get(rec, "password")
		rawURL, user := strings.TrimSpace(get(rec, "url")), strings.TrimSpace(get(rec, "username"))
		name := strings.TrimSpace(get(rec, "name"))
		host := ""
		u, uerr := url.Parse(rawURL)
		if uerr == nil {
			host = strings.ToLower(u.Host)
		}
		if name == "" {
			name = host
		}
		if name == "" {
			name = "匯入項目"
		}
		row := CSVRow{Name: name, Host: host, Account: user}
		it := vault.Item{Name: name, Account: user, Password: pw, Note: strings.TrimSpace(get(rec, "note"))}
		switch {
		case pw == "":
			row.Action = ActionSkip
		case uerr == nil && vault.SiteURLAllowed(u) && user != "":
			it.Type, it.URL, it.Alias = vault.TypeLogin, rawURL, user
			it.Origin = u.Scheme + "://" + host
			row.Action = ActionLogin
		default:
			it.Type = vault.TypePassword
			if rawURL != "" {
				it.Note = strings.TrimSpace("匯入時的網址：" + rawURL + "\n" + it.Note)
			}
			row.Action = ActionPassword
		}
		if row.Action != ActionSkip {
			if k := dupKey(it); seen[k] {
				row.Action = ActionDuplicate
			} else {
				seen[k] = true
				items = append(items, it)
			}
		}
		switch row.Action {
		case ActionLogin:
			prev.New++
		case ActionPassword:
			prev.New++
			prev.AsPassword++
		case ActionDuplicate:
			prev.Duplicate++
		case ActionSkip:
			prev.Skipped++
		}
		prev.Rows = append(prev.Rows, row)
	}
	return prev, items, nil
}

// dupKey treats the same site and account (or the same name and account for other passwords) as one entry.
func dupKey(it vault.Item) string {
	if it.Type == vault.TypeLogin {
		return "login|" + it.Origin + "|" + strings.ToLower(it.Account)
	}
	return it.Type + "|" + strings.ToLower(it.Name) + "|" + strings.ToLower(it.Account)
}
