// ============================================================================
// DelTemp (Console, Win32-only, no <filesystem> needed)
// Program by: Bob Paydar
//
// Features of this app:
//   - Cleans the current user’s %TEMP% folder
//   - Optional: also cleans C:\Windows\Temp (--system), auto-elevates via UAC
//   - Optional: empties Recycle Bin (--recycle)
//   - Optional: quiet mode (--quiet) for minimal output
//   - Command-line help (--help) shows available options
//
// Implementation notes:
//   - Uses Win32 APIs (FindFirstFile, DeleteFile, RemoveDirectory).
//   - Skips locked/in-use files (safe operation).
//   - Automatically strips read-only/system/hidden attributes before deletion.
//   - Shows admin/elevation status on start.
//   - Logs actions and errors to the console.
// ============================================================================

#include <windows.h>
#include <shlobj.h>      // SHEmptyRecycleBinW
#include <shellapi.h>    // ShellExecuteExW
#include <string>
#include <vector>
#include <iostream>

#pragma comment(lib, "Shell32.lib")

struct Options {
    bool includeSystem = false;  // --system
    bool emptyRecycle = false;  // --recycle
    bool quiet = false;  // --quiet
};

static bool g_quiet = false;

static void log(const std::wstring& s, bool force = false) {
    if (!g_quiet || force) std::wcout << s << L'\n';
}

static bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;
    if (AllocateAndInitializeSid(&ntAuth, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return !!isAdmin;
}

static std::wstring GetExePath() {
    wchar_t buf[MAX_PATH]{};
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return n ? std::wstring(buf, buf + n) : L"";
}

// --------------------------------------------------------------------------
// Help / usage info
// --------------------------------------------------------------------------
static void PrintHelp() {
    std::wcout <<
        L"DelTemp.exe [--system] [--recycle] [--quiet] [--help]\n"
        L"\nOptions:\n"
        L"  --system   include C:\\Windows\\Temp (auto-elevates if needed)\n"
        L"  --recycle  empty Recycle Bin\n"
        L"  --quiet    minimal output\n"
        L"  --help     show this help\n"
        L"\nProgram written by Bob Paydar\n";
}

static Options ParseArgs(int argc, wchar_t* argv[]) {
    Options opt{};
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--system")        opt.includeSystem = true;
        else if (a == L"--recycle")  opt.emptyRecycle = true;
        else if (a == L"--quiet")    opt.quiet = true;
        else if (a == L"--help" || a == L"-h" || a == L"/?") {
            PrintHelp(); exit(0);
        }
        else {
            std::wcerr << L"[warn] Unknown option: " << a << L'\n';
        }
    }
    g_quiet = opt.quiet;
    return opt;
}

// --------------------------------------------------------------------------
// Utility helpers: join paths, clear file attributes
// --------------------------------------------------------------------------
static std::wstring JoinPath(const std::wstring& dir, const std::wstring& name) {
    if (!dir.empty() && (dir.back() == L'\\' || dir.back() == L'/'))
        return dir + name;
    return dir + L'\\' + name;
}

static void ClearAttrs(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        attrs &= ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
        SetFileAttributesW(path.c_str(), attrs);
    }
}

// Forward decl
static bool DeleteTree(const std::wstring& root, size_t& ok, size_t& fail);

// --------------------------------------------------------------------------
// File and directory deletion helpers
// --------------------------------------------------------------------------
static bool DeleteFileSafe(const std::wstring& file, size_t& ok, size_t& fail) {
    ClearAttrs(file);
    if (DeleteFileW(file.c_str())) { ++ok; return true; }
    ++fail;
    log(L"   - failed: " + file + L" (err=" + std::to_wstring(GetLastError()) + L")");
    return false;
}

static bool DeleteDirSafe(const std::wstring& dir, size_t& ok, size_t& fail) {
    if (!DeleteTree(dir, ok, fail)) return false;
    ClearAttrs(dir);
    if (RemoveDirectoryW(dir.c_str())) { ++ok; return true; }
    ++fail;
    log(L"   - failed: " + dir + L" (err=" + std::to_wstring(GetLastError()) + L")");
    return false;
}

// Enumerate and delete children of a directory (but not the directory itself)
static void CleanDirectoryContents(const std::wstring& dir) {
    DWORD attrs = GetFileAttributesW(dir.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) { log(L"[skip] Not found: " + dir); return; }
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) { log(L"[skip] Not a directory: " + dir); return; }

    log(L"[clean] " + dir);

    std::wstring pattern = JoinPath(dir, L"*");
    WIN32_FIND_DATAW ffd{};
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) { log(L"   -> nothing to delete"); return; }
        log(L"   - failed to enumerate (err=" + std::to_wstring(err) + L")");
        return;
    }

    size_t ok = 0, fail = 0;

    do {
        const std::wstring name = ffd.cFileName;
        if (name == L"." || name == L"..") continue;
        const std::wstring fullPath = JoinPath(dir, name);

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            DeleteDirSafe(fullPath, ok, fail);
        }
        else {
            DeleteFileSafe(fullPath, ok, fail);
        }
    } while (FindNextFileW(hFind, &ffd));

    FindClose(hFind);

    log(L"   -> removed " + std::to_wstring(ok) + L" item(s)" +
        (fail ? (L", failed " + std::to_wstring(fail) + L" item(s)") : L""));
}

// Helper that deletes everything inside a directory (used by DeleteDirSafe)
static bool DeleteTree(const std::wstring& root, size_t& ok, size_t& fail) {
    std::wstring pattern = JoinPath(root, L"*");
    WIN32_FIND_DATAW ffd{};
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) return true; // empty
        log(L"   - enumerate failed: " + root + L" (err=" + std::to_wstring(err) + L")");
        ++fail; return false;
    }

    bool allGood = true;
    do {
        const std::wstring name = ffd.cFileName;
        if (name == L"." || name == L"..") continue;
        const std::wstring fullPath = JoinPath(root, name);

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!DeleteDirSafe(fullPath, ok, fail)) allGood = false;
        }
        else {
            if (!DeleteFileSafe(fullPath, ok, fail)) allGood = false;
        }
    } while (FindNextFileW(hFind, &ffd));

    FindClose(hFind);
    return allGood;
}

// --------------------------------------------------------------------------
// Relaunch elevated if --system requested and not admin
// --------------------------------------------------------------------------
static int RelaunchElevatedIfNeeded(const Options& opt, int argc, wchar_t* argv[]) {
    if (!opt.includeSystem) return 0;
    if (IsRunningAsAdmin()) return 0;

    std::wstring params;
    for (int i = 1; i < argc; ++i) {
        params += L"\""; params += argv[i]; params += L"\"";
        if (i + 1 < argc) params += L" ";
    }

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    std::wstring exe = GetExePath();
    sei.lpFile = exe.c_str();
    sei.lpParameters = params.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        DWORD err = GetLastError();
        if (err == ERROR_CANCELLED) {
            log(L"[info] Elevation cancelled. Continuing without C:\\Windows\\Temp.");
            return 0;
        }
        std::wcerr << L"[error] Failed to elevate (code " << err << L")\n";
        return 1; // hard error
    }

    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        DWORD childExit = 0;
        if (GetExitCodeProcess(sei.hProcess, &childExit)) {
            CloseHandle(sei.hProcess);
            exit((int)childExit);
        }
        CloseHandle(sei.hProcess);
        exit(0);
    }

    exit(0);
}

// --------------------------------------------------------------------------
// Main entry point
// --------------------------------------------------------------------------
int wmain(int argc, wchar_t* argv[]) {
    Options opt = ParseArgs(argc, argv);

    if (int relaunch = RelaunchElevatedIfNeeded(opt, argc, argv)) {
        return relaunch; // non-zero only on hard error
    }

    bool isAdmin = IsRunningAsAdmin();
    log(L"Windows Temp Cleaner (Console, Win32) — Admin: " + std::wstring(isAdmin ? L"Yes" : L"No"));

    // Resolve %TEMP%
    wchar_t tempBuf[MAX_PATH]{};
    DWORD n = GetTempPathW(MAX_PATH, tempBuf);
    std::wstring userTemp = (n > 0 && n < MAX_PATH) ? std::wstring(tempBuf) : L"C:\\Windows\\Temp";
    if (!userTemp.empty() && (userTemp.back() == L'\\' || userTemp.back() == L'/')) userTemp.pop_back();

    // Resolve C:\Windows\Temp (if requested)
    std::wstring winTemp;
    if (opt.includeSystem) {
        wchar_t winBuf[MAX_PATH]{};
        DWORD m = GetWindowsDirectoryW(winBuf, MAX_PATH);
        if (m > 0 && m < MAX_PATH) winTemp = std::wstring(winBuf) + L"\\Temp";
    }

    // Clean user temp
    CleanDirectoryContents(userTemp);

    // Optional: clean Windows\Temp
    if (opt.includeSystem && !winTemp.empty()) {
        CleanDirectoryContents(winTemp);
    }

    // Optional: empty recycle bin
    if (opt.emptyRecycle) {
        log(L"Emptying Recycle Bin…");
        HRESULT hr = SHEmptyRecycleBinW(nullptr, nullptr,
            SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
        if (SUCCEEDED(hr)) log(L"Recycle Bin emptied.");
        else std::wcerr << L"[warn] Recycle Bin not emptied (hr=0x" << std::hex << hr << L")\n";
    }

    log(L"Done.");
    return 0;
}
