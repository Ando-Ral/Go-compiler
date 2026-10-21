//go:build windows

// lockdown : gèle le clavier et la souris (BlockInput) et empêche
// l'extinction / le redémarrage (veto sur WM_QUERYENDSESSION).
//
// Échappatoire : Ctrl+Alt+Del (le noyau lève le blocage), ou appui long
// sur le bouton power (~4 s) qui force la coupure.
// Compilation : CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H=windowsgui" -o lockdown.exe ./lockdown

package main

import (
	"syscall"
	"unsafe"
)

// Passe à false si tu veux pouvoir éteindre normalement.
const vetoShutdown = true

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procBlockInput       = user32.NewProc("BlockInput")
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
)

const (
	WM_DESTROY         = 0x0002
	WM_QUERYENDSESSION = 0x0011
)

// WNDCLASSEXW — taille 80 octets en x64, alignement identique à l'API.
type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     syscall.Handle
	hIcon         syscall.Handle
	hCursor       syscall.Handle
	hbrBackground syscall.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       syscall.Handle
}

type point struct{ x, y int32 }

// MSG — taille 48 octets en x64.
type msgStruct struct {
	hwnd    syscall.Handle
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

// Callback de fenêtre. Tous les arguments en uintptr : imposé par NewCallback.
func wndProc(hwnd, m, w, l uintptr) uintptr {
	switch m {
	case WM_QUERYENDSESSION:
		if vetoShutdown {
			return 0 // FALSE => "non, ne termine pas la session"
		}
	case WM_DESTROY:
		procPostQuitMessage.Call(0)
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, m, w, l)
	return r
}

func main() {
	// 1) Gel du clavier ET de la souris, au niveau de la file d'entrée.
	procBlockInput.Call(1)

	// 2) Fenêtre invisible : sert uniquement à recevoir WM_QUERYENDSESSION.
	hInst, _, _ := procGetModuleHandleW.Call(0)
	className, _ := syscall.UTF16PtrFromString("LockdownWnd")
	title, _ := syscall.UTF16PtrFromString("lockdown")

	wc := wndClassEx{
		cbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		lpfnWndProc:   syscall.NewCallback(wndProc),
		hInstance:     syscall.Handle(hInst),
		lpszClassName: className,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(title)),
		0, // WS_OVERLAPPED, sans WS_VISIBLE => invisible
		0, 0, 0, 0,
		0, 0, hInst, 0,
	)
	if hwnd == 0 {
		select {} // pas de fenêtre : on reste bloqué quand même
	}

	// 3) Boucle de messages : c'est elle qui reçoit la demande d'extinction.
	var m msgStruct
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}
