package core

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// SMTPMailer sends the fixed code message through the person's own mail account:
// TLS from the start on port 465, otherwise STARTTLS, which is required (never plain text).
type SMTPMailer struct {
	TLS      *tls.Config // nil uses the system roots; tests supply their own
	Timeout  time.Duration
	dialAddr string // tests only: connect here instead of Host:Port
}

var purposeText = map[string]string{
	PurposeUnlock:    "解鎖密碼庫",
	PurposeReset:     "忘記主密碼，重設主密碼",
	PurposeReveal:    "顯示或複製一筆密碼",
	PurposeSensitive: "變更安全設定或匯出備份",
	PurposeBind:      "確認這個信箱可以收到驗證碼",
}

var purposeTextEN = map[string]string{
	PurposeUnlock:    "unlock the vault",
	PurposeReset:     "reset a forgotten master password",
	PurposeReveal:    "show or copy a password",
	PurposeSensitive: "change security settings or export a backup",
	PurposeBind:      "confirm this mailbox receives codes",
}

// codeMessage builds the only message Keyward ever sends.
func codeMessage(from, to string, m CodeMail, now time.Time) []byte {
	expires := m.Expires.Local().Format("2006-01-02 15:04")
	subject := "Keyward 驗證碼：" + m.Code
	body := "你的 Keyward 驗證碼：" + m.Code + "\r\n\r\n" +
		"用途：" + purposeText[m.Purpose] + "\r\n" +
		"有效到：" + expires + "（10 分鐘內，只能使用一次）\r\n\r\n" +
		"如果這不是你本人的操作，請不要把驗證碼告訴任何人（包括 AI 工具），並考慮在 Keyward 變更主密碼。\r\n" +
		"這封信由你電腦上的 Keyward 自動寄出，不需要回覆。\r\n"
	if m.Lang == "en" {
		subject = "Keyward code: " + m.Code
		body = "Your Keyward code: " + m.Code + "\r\n\r\n" +
			"Purpose: " + purposeTextEN[m.Purpose] + "\r\n" +
			"Valid until: " + expires + " (10 minutes, single use)\r\n\r\n" +
			"If you did not request this, do not share the code with anyone (including AI tools), and consider changing your master password in Keyward.\r\n" +
			"This message was sent automatically by Keyward on your computer; no need to reply.\r\n"
	}
	id := make([]byte, 12)
	rand.Read(id)
	domain := from[strings.LastIndex(from, "@")+1:]
	var b bytes.Buffer
	for _, h := range [][2]string{
		{"From", from},
		{"To", to},
		{"Subject", mime.BEncoding.Encode("UTF-8", subject)},
		{"Date", now.Format(time.RFC1123Z)},
		{"Message-ID", "<" + hex.EncodeToString(id) + "@" + domain + ">"},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=UTF-8"},
		{"Content-Transfer-Encoding", "base64"},
	} {
		b.WriteString(h[0] + ": " + h[1] + "\r\n")
	}
	b.WriteString("\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(body))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return b.Bytes()
}

func (m SMTPMailer) Send(cfg SMTPConfig, to string, cm CodeMail) error {
	from := cfg.User
	if _, ok := checkAddr(from); !ok {
		from = to // some providers use a plain user name; send as the recipient's own address
	}
	timeout := m.Timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	if m.TLS != nil {
		tlsCfg = m.TLS.Clone()
		tlsCfg.ServerName, tlsCfg.MinVersion = cfg.Host, tls.VersionTLS12
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	if m.dialAddr != "" {
		addr = m.dialAddr
	}
	d := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if cfg.Port == 465 {
		conn, err = tls.DialWithDialer(d, "tcp", addr, tlsCfg)
	} else {
		conn, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(2 * timeout))
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if cfg.Port != 465 {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("郵件伺服器不支援 STARTTLS，為避免以明文傳送密碼而停止")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if ok, _ := c.Extension("AUTH"); ok {
		if err := c.Auth(smtp.PlainAuth("", cfg.User, cfg.Password, cfg.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(codeMessage(from, to, cm, time.Now())); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
