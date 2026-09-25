const std = @import("std");

// Win32 types declared locally to avoid depending on std.os.windows.
const HINSTANCE = ?*anyopaque;
const HWND = ?*anyopaque;
const HHOOK = ?*anyopaque;
const WPARAM = usize;
const LPARAM = isize;
const LRESULT = isize;
const BOOL = i32;
const DWORD = u32;

const HOOKPROC = *const fn (nCode: i32, wParam: WPARAM, lParam: LPARAM) callconv(.winapi) LRESULT;

extern "user32" fn SetWindowsHookExW(idHook: i32, lpfn: HOOKPROC, hmod: HINSTANCE, dwThreadId: DWORD) callconv(.winapi) HHOOK;
extern "user32" fn UnhookWindowsHookEx(hhk: HHOOK) callconv(.winapi) BOOL;
extern "user32" fn CallNextHookEx(hhk: HHOOK, nCode: i32, wParam: WPARAM, lParam: LPARAM) callconv(.winapi) LRESULT;
extern "user32" fn GetMessageW(lpMsg: *MSG, hWnd: HWND, wMsgFilterMin: u32, wMsgFilterMax: u32) callconv(.winapi) BOOL;
extern "user32" fn PostMessageW(hWnd: HWND, Msg: u32, wParam: WPARAM, lParam: LPARAM) callconv(.winapi) BOOL;
extern "user32" fn GetForegroundWindow() callconv(.winapi) HWND;

const WH_KEYBOARD_LL: i32 = 13;
const WM_KEYDOWN: WPARAM = 0x0100;
const WM_INPUTLANGCHANGEREQUEST: u32 = 0x0050;
const VK_CAPITAL: u32 = 0x14;
const INPUTLANGCHANGE_FORWARD: WPARAM = 2;

const POINT = extern struct { x: i32, y: i32 };

const MSG = extern struct {
    hwnd: HWND,
    message: u32,
    wParam: WPARAM,
    lParam: LPARAM,
    time: DWORD,
    pt: POINT,
};

const KBDLLHOOKSTRUCT = extern struct {
    vkCode: DWORD,
    scanCode: DWORD,
    flags: DWORD,
    time: DWORD,
    dwExtraInfo: usize,
};

var h_hook: HHOOK = null;

fn keyboardHookProc(nCode: i32, wParam: WPARAM, lParam: LPARAM) callconv(.winapi) LRESULT {
    if (nCode >= 0 and wParam == WM_KEYDOWN) {
        const kbd: *const KBDLLHOOKSTRUCT = @ptrFromInt(@as(usize, @bitCast(lParam)));

        if (kbd.vkCode == VK_CAPITAL) {
            if (GetForegroundWindow()) |hwnd| {
                _ = PostMessageW(hwnd, WM_INPUTLANGCHANGEREQUEST, INPUTLANGCHANGE_FORWARD, 0);
            }
            return 1; // swallow the key so Caps Lock never toggles
        }
    }
    return CallNextHookEx(h_hook, nCode, wParam, lParam);
}

pub fn main(init: std.process.Init.Minimal) !void {
    _ = init;

    h_hook = SetWindowsHookExW(WH_KEYBOARD_LL, keyboardHookProc, null, 0);
    if (h_hook == null) return error.HookCreationFailed;
    defer _ = UnhookWindowsHookEx(h_hook);

    // Low-level hooks are dispatched through this thread's message loop.
    var msg: MSG = undefined;
    while (GetMessageW(&msg, null, 0, 0) > 0) {}
}
