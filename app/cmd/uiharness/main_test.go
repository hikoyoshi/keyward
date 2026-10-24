package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hikoyoshi/keyward/internal/vault"
)

func init() { vault.DefaultKDF = vault.KDFParams{Time: 1, MemoryKiB: 8 * 1024, Threads: 1} }

// call goes through the same /api/ handler the browser uses, without opening a port.
func call(t *testing.T, h *harness, name, query string, args ...any) (json.RawMessage, string) {
	t.Helper()
	body, _ := json.Marshal(args)
	req := httptest.NewRequest("POST", "/api/"+name+query, strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	h.api(rec, req)
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: %v %s", name, err, rec.Body.String())
	}
	return out.Result, out.Error
}

func ok(t *testing.T, h *harness, name string, args ...any) json.RawMessage {
	t.Helper()
	res, e := call(t, h, name, "", args...)
	if e != "" {
		t.Fatalf("%s: %s", name, e)
	}
	return res
}

// lastCode reads the newest code from the fake mailbox, as a browser walkthrough would.
func lastCode(t *testing.T, h *harness, purpose string) string {
	t.Helper()
	res, _ := call(t, h, "_mail", "")
	var mails []struct{ To, Purpose, Code string }
	json.Unmarshal(res, &mails)
	if len(mails) == 0 || mails[len(mails)-1].Purpose != purpose {
		t.Fatalf("mailbox: %s", res)
	}
	return mails[len(mails)-1].Code
}

func TestHarnessEmailWalkthrough(t *testing.T) {
	h, err := newHarness(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.svc.Shutdown()
	const pw, next = "Harness-pw!1", "Harness-pw!2"
	ok(t, h, "Setup", pw, pw)
	ok(t, h, "Save", map[string]any{"type": "password", "name": "Wi-Fi", "password": "fake-wifi-secret"})

	// Enable: re-verify, test code to the new address, confirm.
	ok(t, h, "Authorize", "email-setup", pw)
	ok(t, h, "StartEmailSetup", map[string]any{"host": "smtp.example.com", "port": 587, "user": "sender@example.com", "password": "fake-app-pw", "to": "demo@example.com"})
	ok(t, h, "FinishEmailSetup", lastCode(t, h, "bind"))
	var st struct {
		Locked bool
		Email  struct {
			Enabled bool
			Masked  string
		}
	}
	json.Unmarshal(ok(t, h, "Status"), &st)
	if !st.Email.Enabled || st.Email.Masked != "d***@example.com" {
		t.Fatalf("status: %+v", st)
	}

	// Unlock from the lock screen with a code (real DPAPI over the throwaway vault).
	ok(t, h, "Lock")
	call(t, h, "_advance", "?sec=61")
	ok(t, h, "SendCode", "unlock", "")
	ok(t, h, "UnlockWithCode", lastCode(t, h, "unlock"), false)
	json.Unmarshal(ok(t, h, "Status"), &st)
	if st.Locked {
		t.Fatal("still locked")
	}

	// Mail failure is reported and the master password still works.
	ok(t, h, "Lock")
	call(t, h, "_advance", "?sec=61")
	call(t, h, "_mailfail", "?on=1")
	if _, e := call(t, h, "SendCode", "", "unlock", ""); !strings.HasPrefix(e, "send_failed:") {
		t.Fatalf("failed send: %q", e)
	}
	call(t, h, "_mailfail", "?on=0")

	// Forgot master password: reset by email, old one stops working.
	ok(t, h, "SendCode", "reset", "")
	ok(t, h, "UnlockWithCode", lastCode(t, h, "reset"), true)
	ok(t, h, "ResetMaster", next, next)
	ok(t, h, "Lock")
	if _, e := call(t, h, "Unlock", "", pw); !strings.HasPrefix(e, "wrong_password:") {
		t.Fatalf("old master: %q", e)
	}
	call(t, h, "_advance", "?sec=2")
	ok(t, h, "Unlock", next)

	// Disable needs a fresh verification, then email unlock is gone.
	if _, e := call(t, h, "DisableEmail", ""); !strings.HasPrefix(e, "need_auth:") {
		t.Fatalf("disable without re-verify: %q", e)
	}
	ok(t, h, "Authorize", "email-disable", next)
	ok(t, h, "DisableEmail")
	ok(t, h, "Lock")
	call(t, h, "_advance", "?sec=61")
	if _, e := call(t, h, "SendCode", "", "unlock", ""); !strings.HasPrefix(e, "email_off:") {
		t.Fatalf("after disable: %q", e)
	}
}
