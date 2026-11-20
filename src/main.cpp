// language: C++, file: main.cpp, target: Windows 11, MSVC
// *X.509 viewer. Parse lives in cert.cpp. Crypt32, no OpenSSL.*
#define WIN32_LEAN_AND_MEAN
#include "cert.hpp"

#include <windows.h>
#include <windowsx.h>
#include <commdlg.h>
#include <shellapi.h>

#include <string>
#include <vector>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")

static const COLORREF kBg = RGB(18, 20, 26);
static const COLORREF kPanel = RGB(27, 30, 39);
static const COLORREF kText = RGB(230, 232, 238);
static const COLORREF kMuted = RGB(139, 144, 160);
static const COLORREF kAccent = RGB(61, 139, 253);
static const COLORREF kOk = RGB(61, 220, 151);
static const COLORREF kErr = RGB(240, 113, 120);

struct Row {
    std::wstring k;
    std::wstring v;
};

struct App {
    HWND wnd = nullptr;
    HBRUSH bg = nullptr;
    HFONT title = nullptr;
    HFONT body = nullptr;
    HFONT mono = nullptr;
    RECT btn_open{40, 96, 250, 140};
    int hover = 0;
    std::vector<Row> rows;
    std::wstring status = L"drop a .pem / .cer / .crt / .der or Open";
    COLORREF status_c = kMuted;
    bool demo = false;
    int demo_step = 0;
    std::wstring demo_path;
};

static App g;

static void load_path(const std::wstring& path) {
    g.rows.clear();
    CertInfo info = parse_cert_file(path);
    if (!info.ok) {
        g.status = info.error.empty() ? L"parse failed" : info.error;
        g.status_c = kErr;
        if (g.wnd) InvalidateRect(g.wnd, nullptr, FALSE);
        return;
    }
    g.rows.reserve(info.rows.size());
    for (const auto& r : info.rows) g.rows.push_back({r.key, r.value});
    g.status = L"parsed · " + std::to_wstring(g.rows.size()) + L" fields";
    g.status_c = kOk;
    if (g.wnd) {
        InvalidateRect(g.wnd, nullptr, TRUE);
        UpdateWindow(g.wnd);
    }
}

static void do_open() {
    wchar_t file[MAX_PATH]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g.wnd;
    ofn.lpstrFilter = L"Certificates\0*.pem;*.cer;*.crt;*.der;*.cert\0All files\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Open certificate";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_EXPLORER;
    if (!GetOpenFileNameW(&ofn)) return;
    load_path(file);
}

static void paint_button(HDC hdc, const RECT& r, const wchar_t* label, bool hover) {
    HBRUSH br = CreateSolidBrush(hover ? kAccent : kPanel);
    HPEN pen = CreatePen(PS_SOLID, 1, kAccent);
    HGDIOBJ oldb = SelectObject(hdc, br);
    HGDIOBJ oldp = SelectObject(hdc, pen);
    RoundRect(hdc, r.left, r.top, r.right, r.bottom, 10, 10);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, hover ? RGB(255, 255, 255) : kText);
    SelectObject(hdc, g.body);
    DrawTextW(hdc, label, -1, const_cast<RECT*>(&r), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, oldb);
    SelectObject(hdc, oldp);
    DeleteObject(br);
    DeleteObject(pen);
}

static void on_paint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    RECT rc;
    GetClientRect(hwnd, &rc);
    FillRect(hdc, &rc, g.bg);

    SetBkMode(hdc, TRANSPARENT);
    SelectObject(hdc, g.title);
    SetTextColor(hdc, kText);
    RECT t{40, 24, rc.right - 40, 60};
    DrawTextW(hdc, L"cert-lens", -1, &t, DT_LEFT | DT_SINGLELINE);

    SelectObject(hdc, g.body);
    SetTextColor(hdc, kMuted);
    RECT s{40, 60, rc.right - 40, 88};
    DrawTextW(hdc, L"C++20  ·  X.509  ·  Crypt32  ·  PEM / DER", -1, &s, DT_LEFT | DT_SINGLELINE);

    paint_button(hdc, g.btn_open, L"Open certificate", g.hover == 1);

    SetTextColor(hdc, g.status_c);
    RECT st{270, 108, rc.right - 40, 132};
    DrawTextW(hdc, g.status.c_str(), -1, &st, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

    RECT panel{40, 156, rc.right - 40, rc.bottom - 24};
    HBRUSH pbr = CreateSolidBrush(kPanel);
    FillRect(hdc, &panel, pbr);
    DeleteObject(pbr);

    int y = 168;
    SelectObject(hdc, g.body);
    for (const auto& row : g.rows) {
        RECT rk{56, y, 210, y + 22};
        RECT rv{220, y, rc.right - 56, y + 22};
        SetTextColor(hdc, kMuted);
        DrawTextW(hdc, row.k.c_str(), -1, &rk, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        SetTextColor(hdc, kText);
        DrawTextW(hdc, row.v.c_str(), -1, &rv, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        y += 24;
        if (y > rc.bottom - 40) break;
    }
    EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        g.bg = CreateSolidBrush(kBg);
        g.title = CreateFontW(32, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                              OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                              DEFAULT_PITCH, L"Segoe UI");
        g.body = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             DEFAULT_PITCH, L"Segoe UI");
        g.mono = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             FIXED_PITCH | FF_MODERN, L"Consolas");
        DragAcceptFiles(hwnd, TRUE);
        if (g.demo) SetTimer(hwnd, 1, 700, nullptr);
        return 0;
    case WM_TIMER:
        if (g.demo_step == 0) {
            g.hover = 1;
            InvalidateRect(hwnd, &g.btn_open, FALSE);
            g.demo_step = 1;
            SetTimer(hwnd, 1, 400, nullptr);
            return 0;
        }
        KillTimer(hwnd, 1);
        g.hover = 0;
        if (!g.demo_path.empty()) load_path(g.demo_path);
        return 0;
    case WM_DROPFILES: {
        HDROP drop = reinterpret_cast<HDROP>(wParam);
        wchar_t path[MAX_PATH]{};
        if (DragQueryFileW(drop, 0, path, MAX_PATH)) load_path(path);
        DragFinish(drop);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        on_paint(hwnd);
        return 0;
    case WM_MOUSEMOVE: {
        POINT p{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        int h = PtInRect(&g.btn_open, p) ? 1 : 0;
        if (h != g.hover) {
            g.hover = h;
            InvalidateRect(hwnd, &g.btn_open, FALSE);
        }
        return 0;
    }
    case WM_LBUTTONDOWN: {
        POINT p{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        if (PtInRect(&g.btn_open, p)) do_open();
        return 0;
    }
    case WM_DESTROY:
        DeleteObject(g.bg);
        DeleteObject(g.title);
        DeleteObject(g.body);
        DeleteObject(g.mono);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hi, HINSTANCE, PWSTR cmd, int show) {
    std::wstring open_now;
    if (cmd && *cmd) {
        std::wstring p = cmd;
        while (!p.empty() && (p.front() == L' ' || p.front() == L'"')) p.erase(p.begin());
        while (!p.empty() && (p.back() == L' ' || p.back() == L'"')) p.pop_back();
        if (p.size() >= 6 && p.compare(0, 6, L"--demo") == 0) {
            g.demo = true;
            p = p.substr(6);
            while (!p.empty() && p.front() == L' ') p.erase(p.begin());
            while (!p.empty() && p.front() == L'"') p.erase(p.begin());
            while (!p.empty() && p.back() == L'"') p.pop_back();
            g.demo_path = p;
        } else {
            open_now = p;
        }
    }
    SetProcessDPIAware();
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hi;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(kBg);
    wc.lpszClassName = L"CertLensWnd";
    wc.hIcon = LoadIcon(nullptr, IDI_INFORMATION);
    RegisterClassExW(&wc);

    RECT r{0, 0, 920, 720};
    AdjustWindowRect(&r, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE);
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"cert-lens",
                                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                                80, 80, r.right - r.left, r.bottom - r.top,
                                nullptr, nullptr, hi, nullptr);
    g.wnd = hwnd;
    ShowWindow(hwnd, show);
    if (!open_now.empty()) load_path(open_now);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
