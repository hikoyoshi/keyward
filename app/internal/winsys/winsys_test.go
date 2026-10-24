//go:build windows

package winsys

import (
	"bytes"
	"testing"
)

// Does not write to the clipboard, so running tests never disturbs what the user copied.
func TestSessionStateAndClipboardWindow(t *testing.T) {
	locked, ok := SessionLocked()
	if !ok {
		t.Skip("session state unavailable on this system")
	}
	if locked {
		t.Fatal("session reported locked while tests are running")
	}
	if _, err := NewClipboard(); err != nil {
		t.Fatal(err)
	}
}

func TestDPAPIRoundTrip(t *testing.T) {
	var p DPAPI
	plain := []byte("fake data key 0123456789abcdef!!")
	blob, err := p.Protect(plain, []byte("ctx-a"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, plain) {
		t.Fatal("blob contains plaintext")
	}
	got, err := p.Unprotect(blob, []byte("ctx-a"))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip: %v %q", err, got)
	}
	if _, err := p.Unprotect(blob, []byte("ctx-b")); err == nil {
		t.Fatal("wrong entropy accepted")
	}
	blob[len(blob)-1] ^= 1
	if _, err := p.Unprotect(blob, []byte("ctx-a")); err == nil {
		t.Fatal("tampered blob accepted")
	}
}
