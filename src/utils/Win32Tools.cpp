#include "Win32Tools.h"
#include <cstdio>
#include <cstdarg>
#include <vector>
#include <tchar.h>

// ---------------- ConsoleIO 实现 ----------------
DWORD Console::WriteTextToConsole(HANDLE consoleHandle, LPCTSTR text) {
    if (!consoleHandle || consoleHandle == INVALID_HANDLE_VALUE || !text)
        return 0;

    DWORD len = static_cast<DWORD>(_tcslen(text));
    DWORD written = 0;
    if (!WriteConsole(consoleHandle, text, len, &written, nullptr))
        return 0;
    return written;
}

DWORD Console::WriteDwordToConsole(HANDLE consoleHandle, DWORD value) {
    TCHAR buffer[16];  // DWORD 最大 4294967295 (10位) + '\0'
#ifdef UNICODE
    _stprintf_s(buffer, _T("%lu"), value);
#else
    _stprintf_s(buffer, _T("%u"), value);
#endif
    return Console::WriteTextToConsole(consoleHandle, buffer);
}

DWORD Console::PrintfT(HANDLE consoleHandle, LPCTSTR format, ...) {
    if (!format)
        return static_cast<DWORD>(-1);

    va_list args;
    va_start(args, format);

    // 先试一个合理大小的缓冲区
    TCHAR buffer[512];
    int result = _vstprintf_s(buffer, _countof(buffer), format, args);
    va_end(args);

    if (result >= 0 && result < static_cast<int>(_countof(buffer))) {
        return Console::WriteTextToConsole(consoleHandle, buffer);
    }

    // 缓冲区不够，动态分配（注意：_vscprintf 不适用于 TCHAR）
    va_start(args, format);
#ifdef UNICODE
    int len = _vscwprintf(format, args);
#else
    int len = _vscprintf(format, args);
#endif
    va_end(args);

    if (len <= 0)
        return static_cast<DWORD>(-1);

    std::vector<TCHAR> dynamicBuf(len + 1);
    va_start(args, format);
    _vstprintf_s(dynamicBuf.data(), dynamicBuf.size(), format, args);
    va_end(args);

    return Console::WriteTextToConsole(consoleHandle, dynamicBuf.data());
}

DWORD Console::PrintLastError(HANDLE consoleHandle) {
    DWORD errorCode = GetLastError();
    if (errorCode == 0)
        return 0;

    LPTSTR errorMsg = nullptr;
    DWORD len = FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPTSTR>(&errorMsg),
        0,
        nullptr);

    if (len && errorMsg) {
        DWORD written = Console::WriteTextToConsole(consoleHandle, errorMsg);
        LocalFree(errorMsg);
        return written;
    }

    // 回退：打印错误码
    return Console::WriteDwordToConsole(consoleHandle, errorCode);
}

// ---------------- ProcessTools 实现 ----------------
DWORD Process::GetAllProcesses(PROCESSENTRY32** processList, DWORD* processCount) {
    if (!processList || !processCount)
        return ERROR_INVALID_PARAMETER;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return GetLastError();

    PROCESSENTRY32 entry = {sizeof(PROCESSENTRY32)};
    std::vector<PROCESSENTRY32> processes;

    if (Process32First(snapshot, &entry)) {
        do {
            processes.push_back(entry);
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);

    DWORD count = static_cast<DWORD>(processes.size());
    if (count == 0) {
        *processList = nullptr;
        *processCount = 0;
        return ERROR_SUCCESS;
    }

    // 分配内存（调用者需用 free() 释放）
    size_t totalSize = sizeof(PROCESSENTRY32) * count;
    PROCESSENTRY32* list = static_cast<PROCESSENTRY32*>(malloc(totalSize));
    if (!list) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    memcpy(list, processes.data(), totalSize);
    *processList = list;
    *processCount = count;
    return ERROR_SUCCESS;
}