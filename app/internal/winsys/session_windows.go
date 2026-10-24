//go:build windows

package winsys

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wtsapi32                     = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformati = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory            = wtsapi32.NewProc("WTSFreeMemory")
)

const (
	wtsCurrentSession = ^uintptr(0) // WTS_CURRENT_SESSION (DWORD -1)
	wtsSessionInfoEx  = 25
	wtsSessionLock    = 0 // WTS_SESSIONSTATE_LOCK (Windows 8 and later)
)

// SessionLocked reports whether the current Windows session is locked.
// ok is false when Windows does not provide the information.
func SessionLocked() (locked, ok bool) {
	var buf unsafe.Pointer
	var n uint32
	r, _, _ := procWTSQuerySessionInformati.Call(0, wtsCurrentSession&0xFFFFFFFF, wtsSessionInfoEx, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || buf == nil {
		return false, false
	}
	defer procWTSFreeMemory.Call(uintptr(buf))
	if n < 20 {
		return false, false
	}
	// WTSINFOEXW: DWORD Level, then the 8-byte aligned WTSINFOEX_LEVEL1_W { ULONG SessionId; WTS_CONNECTSTATE_CLASS SessionState; LONG SessionFlags; ... }
	level := *(*uint32)(buf)
	if level != 1 {
		return false, false
	}
	flags := *(*int32)(unsafe.Add(buf, 16))
	return flags == wtsSessionLock, true
}
