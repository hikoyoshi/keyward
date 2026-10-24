//go:build windows

package winsys

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// DPAPI protects data for the current Windows user (CryptProtectData without CRYPTPROTECT_LOCAL_MACHINE).
// Any program running as this user can unprotect it; the entropy only keeps blobs from being swapped between uses.
type DPAPI struct{}

func blobOf(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// takeBlob copies memory that Windows allocated and frees it, wiping the original first.
func takeBlob(b *windows.DataBlob) []byte {
	if b.Data == nil {
		return nil
	}
	src := unsafe.Slice(b.Data, b.Size)
	out := make([]byte, len(src))
	copy(out, src)
	for i := range src {
		src[i] = 0
	}
	windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	return out
}

func (DPAPI) Protect(plain, entropy []byte) ([]byte, error) {
	desc, _ := windows.UTF16PtrFromString("Keyward")
	var out windows.DataBlob
	if err := windows.CryptProtectData(blobOf(plain), desc, blobOf(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}

func (DPAPI) Unprotect(blob, entropy []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blobOf(blob), nil, blobOf(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}
