//go:build windows

// Package winsys wraps the few Win32 calls Keyward needs: a private clipboard and the session lock state.
package winsys

import (
	"errors"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procOpenClipboard            = user32.NewProc("OpenClipboard")
	procCloseClipboard           = user32.NewProc("CloseClipboard")
	procEmptyClipboard           = user32.NewProc("EmptyClipboard")
	procSetClipboardData         = user32.NewProc("SetClipboardData")
	procRegisterClipboardFormatW = user32.NewProc("RegisterClipboardFormatW")
	procGetClipboardSequence     = user32.NewProc("GetClipboardSequenceNumber")
	procCreateWindowExW          = user32.NewProc("CreateWindowExW")
	procGlobalAlloc              = kernel32.NewProc("GlobalAlloc")
	procGlobalFree               = kernel32.NewProc("GlobalFree")
	procGlobalLock               = kernel32.NewProc("GlobalLock")
	procGlobalUnlock             = kernel32.NewProc("GlobalUnlock")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
	hwndMessage   = ^uintptr(2) // (HWND)-3
)

// Clipboard writes secrets so Windows clipboard history, cloud sync and monitors skip them.
// All calls run on one locked OS thread that owns a hidden message-only window,
// because SetClipboardData fails when the clipboard is opened without an owner window.
type Clipboard struct {
	jobs chan func(hwnd uintptr)
}

func NewClipboard() (*Clipboard, error) {
	c := &Clipboard{jobs: make(chan func(uintptr))}
	ready := make(chan error)
	go func() {
		runtime.LockOSThread()
		cls, _ := windows.UTF16PtrFromString("STATIC")
		hwnd, _, err := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(cls)), 0, 0, 0, 0, 0, 0, hwndMessage, 0, 0, 0)
		if hwnd == 0 {
			ready <- err
			return
		}
		ready <- nil
		for job := range c.jobs {
			job(hwnd)
		}
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Clipboard) do(fn func(hwnd uintptr) error) error {
	done := make(chan error, 1)
	c.jobs <- func(hwnd uintptr) { done <- fn(hwnd) }
	return <-done
}

func openClipboard(hwnd uintptr) error {
	// Another app may hold the clipboard briefly; retry for about half a second.
	for i := 0; i < 10; i++ {
		if r, _, _ := procOpenClipboard.Call(hwnd); r != 0 {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("clipboard is busy")
}

func setGlobal(format uintptr, data []byte) error {
	h, _, err := procGlobalAlloc.Call(gmemMoveable, uintptr(len(data)))
	if h == 0 {
		return err
	}
	p, _, err := procGlobalLock.Call(h)
	if p == 0 {
		procGlobalFree.Call(h)
		return err
	}
	copy(unsafe.Slice((*byte)(foreignPtr(p)), len(data)), data)
	procGlobalUnlock.Call(h)
	if r, _, err := procSetClipboardData.Call(format, h); r == 0 {
		procGlobalFree.Call(h)
		return err
	}
	return nil // the clipboard owns h now
}

// foreignPtr converts an address returned by Win32 (memory not managed by Go) to a pointer.
func foreignPtr(addr uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&addr)) }

func registerFormat(name string) uintptr {
	p, _ := windows.UTF16PtrFromString(name)
	r, _, _ := procRegisterClipboardFormatW.Call(uintptr(unsafe.Pointer(p)))
	return r
}

// SetSecret places text on the clipboard and returns the clipboard sequence number afterwards.
func (c *Clipboard) SetSecret(text string) (uint32, error) {
	var seq uint32
	err := c.do(func(hwnd uintptr) error {
		utf16, err := windows.UTF16FromString(text)
		if err != nil {
			return err
		}
		buf := unsafe.Slice((*byte)(unsafe.Pointer(&utf16[0])), len(utf16)*2)
		defer func() {
			for i := range buf {
				buf[i] = 0
			}
		}()
		if err := openClipboard(hwnd); err != nil {
			return err
		}
		err = fill(buf)
		procCloseClipboard.Call()
		if err != nil {
			return err
		}
		r, _, _ := procGetClipboardSequence.Call()
		seq = uint32(r)
		return nil
	})
	return seq, err
}

// fill runs with the clipboard open.
func fill(text []byte) error {
	procEmptyClipboard.Call()
	zero := []byte{0, 0, 0, 0}
	// Documented opt-outs for clipboard history, cloud clipboard and clipboard monitors.
	for _, name := range []string{"ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"} {
		if f := registerFormat(name); f != 0 {
			if err := setGlobal(f, zero); err != nil {
				return err
			}
		}
	}
	return setGlobal(cfUnicodeText, text)
}

// ClearIf empties the clipboard only if nothing was copied since seq.
func (c *Clipboard) ClearIf(seq uint32) {
	c.do(func(hwnd uintptr) error {
		if r, _, _ := procGetClipboardSequence.Call(); uint32(r) != seq {
			return nil
		}
		if err := openClipboard(hwnd); err != nil {
			return err
		}
		procEmptyClipboard.Call()
		procCloseClipboard.Call()
		return nil
	})
}
