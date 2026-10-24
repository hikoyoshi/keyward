package core

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"mime"
	"net"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func TestCodeMessageIsFixed(t *testing.T) {
	exp := time.Date(2026, 10, 18, 9, 10, 0, 0, time.UTC)
	raw := codeMessage("sender@example.com", "demo@example.com", CodeMail{Code: "012345", Purpose: PurposeUnlock, Expires: exp}, exp.Add(-CodeLifetime))
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get("To") != "demo@example.com" || msg.Header.Get("From") != "sender@example.com" {
		t.Fatalf("headers: %v", msg.Header)
	}
	subj, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if subj != "Keyward 驗證碼：012345" {
		t.Fatalf("subject %q", subj)
	}
	b64, _ := bufio.NewReader(msg.Body).ReadString(0)
	body, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(b64, "\r\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "012345") || !strings.Contains(string(body), "解鎖密碼庫") {
		t.Fatalf("body %q", body)
	}
}

// fakeSMTP is a tiny server for one message: EHLO, optional STARTTLS, AUTH PLAIN, MAIL, RCPT, DATA.
type fakeSMTP struct {
	ln       net.Listener
	tlsCfg   *tls.Config
	startTLS bool // advertise STARTTLS (port 587 style)
	implicit bool // TLS from the first byte (port 465 style)
	got      chan string
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func (f *fakeSMTP) serve() {
	c, err := f.ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	if f.implicit {
		c = tls.Server(c, f.tlsCfg)
	}
	r, w := bufio.NewReader(c), c
	say := func(s string) { w.Write([]byte(s + "\r\n")) }
	say("220 fake ESMTP")
	secure := f.implicit
	var data strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			ext := []string{"250-fake"}
			if f.startTLS && !secure {
				ext = append(ext, "250-STARTTLS")
			}
			if secure {
				ext = append(ext, "250-AUTH PLAIN")
			}
			for _, e := range ext {
				say(e)
			}
			say("250 OK")
		case cmd == "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(c, f.tlsCfg)
			if tc.Handshake() != nil {
				return
			}
			c, r, w, secure = tc, bufio.NewReader(tc), tc, true
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			cred, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(line)[len("AUTH PLAIN "):])
			if string(cred) != "\x00sender@example.com\x00fake-app-password" {
				say("535 bad credentials")
				continue
			}
			say("235 ok")
		case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
			say("250 ok")
		case cmd == "DATA":
			say("354 go")
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				data.WriteString(l)
			}
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			f.got <- data.String()
			return
		default:
			say("502 ?")
		}
	}
}

func startFake(t *testing.T, startTLS, implicit bool) (*fakeSMTP, SMTPMailer, int) {
	t.Helper()
	cert, pool := selfSigned(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeSMTP{ln: ln, tlsCfg: &tls.Config{Certificates: []tls.Certificate{cert}}, startTLS: startTLS, implicit: implicit, got: make(chan string, 1)}
	go f.serve()
	return f, SMTPMailer{TLS: &tls.Config{RootCAs: pool}, Timeout: 5 * time.Second, dialAddr: ln.Addr().String()}, ln.Addr().(*net.TCPAddr).Port
}

func TestSMTPStartTLS(t *testing.T) {
	f, m, _ := startFake(t, true, false)
	cfg := SMTPConfig{Host: "localhost", Port: 587, User: "sender@example.com", Password: "fake-app-password"}
	if err := m.Send(cfg, "demo@example.com", CodeMail{Code: "654321", Purpose: PurposeReveal, Expires: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if got := <-f.got; !strings.Contains(got, "To: demo@example.com") || strings.Contains(got, "fake-app-password") {
		t.Fatalf("message: %q", got)
	}
}

func TestSMTPImplicitTLS(t *testing.T) {
	f, m, _ := startFake(t, false, true)
	cfg := SMTPConfig{Host: "localhost", Port: 465, User: "sender@example.com", Password: "fake-app-password"}
	if err := m.Send(cfg, "demo@example.com", CodeMail{Code: "000777", Purpose: PurposeUnlock, Expires: time.Now()}); err != nil {
		t.Fatal(err)
	}
	<-f.got
}

func TestSMTPRefusesPlainText(t *testing.T) {
	_, m, _ := startFake(t, false, false)
	cfg := SMTPConfig{Host: "localhost", Port: 587, User: "sender@example.com", Password: "fake-app-password"}
	err := m.Send(cfg, "demo@example.com", CodeMail{Code: "111111", Purpose: PurposeUnlock, Expires: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("plain-text server accepted: %v", err)
	}
}

func TestSMTPWrongPassword(t *testing.T) {
	_, m, _ := startFake(t, true, false)
	cfg := SMTPConfig{Host: "localhost", Port: 587, User: "sender@example.com", Password: "wrong"}
	if err := m.Send(cfg, "demo@example.com", CodeMail{Code: "111111", Purpose: PurposeUnlock, Expires: time.Now()}); err == nil || !strings.Contains(err.Error(), "535") {
		t.Fatalf("got %v", err)
	}
}

func TestSMTPUntrustedCertificate(t *testing.T) {
	_, m, _ := startFake(t, true, false)
	m.TLS = nil // system roots do not trust the test certificate
	cfg := SMTPConfig{Host: "localhost", Port: 587, User: "sender@example.com", Password: "fake-app-password"}
	if err := m.Send(cfg, "demo@example.com", CodeMail{Code: "111111", Purpose: PurposeUnlock, Expires: time.Now()}); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}
