const std = @import("std");
const builtin = @import("builtin");

// Win32 types declared locally to avoid depending on std.os.windows.
const HINSTANCE = ?*anyopaque;
const HANDLE = ?*anyopaque;
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
extern "user32" fn SetTimer(hWnd: HWND, nIDEvent: usize, uElapse: u32, lpTimerFunc: ?*anyopaque) callconv(.winapi) usize;
extern "user32" fn KillTimer(hWnd: HWND, uIDEvent: usize) callconv(.winapi) BOOL;
extern "user32" fn GetKeyboardLayout(idThread: DWORD) callconv(.winapi) ?*anyopaque;
extern "user32" fn GetForegroundWindow() callconv(.winapi) HWND;
extern "user32" fn GetWindowThreadProcessId(hWnd: HWND, lpdwProcessId: ?*DWORD) callconv(.winapi) DWORD;
extern "user32" fn GetGUIThreadInfo(idThread: DWORD, pgui: *GUITHREADINFO) callconv(.winapi) BOOL;
extern "user32" fn GetClassNameW(hWnd: HWND, lpClassName: [*]u16, nMaxCount: i32) callconv(.winapi) i32;

extern "kernel32" fn CreateFileW(lpFileName: [*:0]const u16, dwDesiredAccess: DWORD, dwShareMode: DWORD, lpSecurityAttributes: ?*anyopaque, dwCreationDisposition: DWORD, dwFlagsAndAttributes: DWORD, hTemplateFile: HANDLE) callconv(.winapi) HANDLE;
extern "kernel32" fn WriteFile(hFile: HANDLE, lpBuffer: [*]const u8, nNumberOfBytesToWrite: DWORD, lpNumberOfBytesWritten: ?*DWORD, lpOverlapped: ?*anyopaque) callconv(.winapi) BOOL;
extern "kernel32" fn GetTickCount() callconv(.winapi) DWORD;
extern "kernel32" fn GetLastError() callconv(.winapi) DWORD;

const WH_KEYBOARD_LL: i32 = 13;
const WM_KEYDOWN: WPARAM = 0x0100;
const WM_TIMER: u32 = 0x0113;
const WM_INPUTLANGCHANGEREQUEST: u32 = 0x0050;
const WM_APP_CAPS: u32 = 0x8000; // WM_APP
const VK_CAPITAL: u32 = 0x14;
const INPUTLANGCHANGE_FORWARD: WPARAM = 2;

// Windows silently removes a low-level hook whose callback ever exceeds the
// system timeout, so the hook is reinstalled periodically.
const rehook_interval_ms: u32 = 5000;

const POINT = extern struct { x: i32, y: i32 };
const RECT = extern struct { left: i32, top: i32, right: i32, bottom: i32 };

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

const GUITHREADINFO = extern struct {
    cbSize: DWORD,
    flags: DWORD,
    hwndActive: HWND,
    hwndFocus: HWND,
    hwndCapture: HWND,
    hwndMenuOwner: HWND,
    hwndMoveSize: HWND,
    hwndCaret: HWND,
    rcCaret: RECT,
};

const log_enabled = builtin.mode == .Debug;
var log_file: HANDLE = null;

fn logOpen() void {
    if (!log_enabled) return;
    const FILE_APPEND_DATA = 0x0004;
    const FILE_SHARE_READ_WRITE = 0x0003;
    const OPEN_ALWAYS = 4;
    const FILE_ATTRIBUTE_NORMAL = 0x80;
    const path = std.unicode.utf8ToUtf16LeStringLiteral("lang-switcher.log");
    const h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ_WRITE, null, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, null);
    if (@intFromPtr(h) != std.math.maxInt(usize)) log_file = h;
}

// Unbuffered so the file can be read while the program runs. Never call from the hook.
fn log(comptime fmt: []const u8, args: anytype) void {
    if (!log_enabled) return;
    const f = log_file orelse return;
    var buf: [512]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "[{d}] " ++ fmt ++ "\n", .{GetTickCount()} ++ args) catch return;
    _ = WriteFile(f, line.ptr, @intCast(line.len), null, null);
}

fn className(hwnd: HWND, out: []u8) []const u8 {
    var wide: [64]u16 = undefined;
    const len: usize = @intCast(@max(GetClassNameW(hwnd, &wide, wide.len), 0));
    const n = @min(len, out.len);
    for (wide[0..n], out[0..n]) |c, *o| o.* = if (c < 128) @intCast(c) else '?';
    return out[0..n];
}

var h_hook: HHOOK = null;

fn installHook() void {
    const new = SetWindowsHookExW(WH_KEYBOARD_LL, keyboardHookProc, null, 0);
    if (new == null) {
        log("hook install failed, error {d}", .{GetLastError()});
        return;
    }
    if (h_hook != null) _ = UnhookWindowsHookEx(h_hook);
    h_hook = new;
}

// The language request must reach the window that owns keyboard focus, which
// for UWP apps lives in a different process than the foreground frame.
fn inputTarget(fg: HWND) HWND {
    var info: GUITHREADINFO = std.mem.zeroes(GUITHREADINFO);
    info.cbSize = @sizeOf(GUITHREADINFO);
    if (GetGUIThreadInfo(GetWindowThreadProcessId(fg, null), &info) != 0) {
        if (info.hwndFocus) |w| return w;
    }
    return fg;
}

fn switchLayout(key_time: DWORD) void {
    const fg = GetForegroundWindow() orelse {
        log("caps: no foreground window", .{});
        return;
    };
    const target = inputTarget(fg);
    const ok = PostMessageW(target, WM_INPUTLANGCHANGEREQUEST, INPUTLANGCHANGE_FORWARD, 0) != 0;

    if (log_enabled) {
        var fg_buf: [64]u8 = undefined;
        var t_buf: [64]u8 = undefined;
        log("caps: fg={s} {x} target={s} {x} post={s} err={d} delay={d}ms", .{
            className(fg, &fg_buf),
            @intFromPtr(fg),
            className(target, &t_buf),
            @intFromPtr(target),
            if (ok) "ok" else "FAIL",
            if (ok) 0 else GetLastError(),
            GetTickCount() -% key_time,
        });
        logLayouts("before", fg, target);
        probe_fg = fg;
        probe_target = target;
        if (probe_timer != 0) _ = KillTimer(null, probe_timer);
        probe_timer = SetTimer(null, 0, 150, null);
    }
}

// Debug-only: the thread layouts shortly after the request, to see which one moved.
var probe_fg: HWND = null;
var probe_target: HWND = null;
var probe_timer: usize = 0;

fn layoutOf(hwnd: HWND, tid: *DWORD) usize {
    tid.* = GetWindowThreadProcessId(hwnd, null);
    return @intFromPtr(GetKeyboardLayout(tid.*)) & 0xFFFF;
}

fn logLayouts(comptime when: []const u8, fg: HWND, target: HWND) void {
    var fg_tid: DWORD = 0;
    var t_tid: DWORD = 0;
    const fg_hkl = layoutOf(fg, &fg_tid);
    const t_hkl = layoutOf(target, &t_tid);
    log("  " ++ when ++ ": fg tid={d} hkl={x}  target tid={d} hkl={x}", .{ fg_tid, fg_hkl, t_tid, t_hkl });
}

fn keyboardHookProc(nCode: i32, wParam: WPARAM, lParam: LPARAM) callconv(.winapi) LRESULT {
    if (nCode >= 0 and wParam == WM_KEYDOWN) {
        const kbd: *const KBDLLHOOKSTRUCT = @ptrFromInt(@as(usize, @bitCast(lParam)));

        if (kbd.vkCode == VK_CAPITAL) {
            // Keep the callback minimal; a null hwnd posts to this thread.
            _ = PostMessageW(null, WM_APP_CAPS, kbd.time, 0);
            return 1; // swallow the key so Caps Lock never toggles
        }
    }
    return CallNextHookEx(h_hook, nCode, wParam, lParam);
}

pub fn main(init: std.process.Init.Minimal) !void {
    _ = init;
    logOpen();

    installHook();
    if (h_hook == null) return error.HookCreationFailed;
    defer _ = UnhookWindowsHookEx(h_hook);
    log("started", .{});

    const rehook_timer = SetTimer(null, 0, rehook_interval_ms, null);

    // Low-level hooks are dispatched through this thread's message loop.
    var msg: MSG = undefined;
    while (GetMessageW(&msg, null, 0, 0) > 0) {
        switch (msg.message) {
            WM_APP_CAPS => switchLayout(@intCast(msg.wParam)),
            WM_TIMER => if (msg.wParam == rehook_timer) {
                installHook();
            } else if (log_enabled and msg.wParam == probe_timer) {
                _ = KillTimer(null, probe_timer);
                logLayouts("after ", probe_fg, probe_target);
            },
            else => {},
        }
    }
}
