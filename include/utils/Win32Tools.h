#ifndef LAIR_WIN32_TOOLS_H
#define LAIR_WIN32_TOOLS_H

#include <windows.h>
#include <TlHelp32.h>

namespace Process {
    /**
     * @brief 获取所有进程信息
     * @param processList 返回的进程信息数组指针（需用 free() 释放）
     * @param processCount 返回的进程数量指针
     * @return 成功返回 ERROR_SUCCESS，失败返回 GetLastError()
     */
    DWORD GetAllProcesses(PROCESSENTRY32** processList, DWORD* processCount);
}

namespace Console {
    /**
     * @brief 打印最后一个错误信息到控制台
     * @param consoleHandle 控制台句柄
     * @return 返回打印的字符数，失败返回 0
     */
    DWORD PrintLastError(HANDLE consoleHandle);

    /**
     * @brief 向控制台写入文本
     * @param consoleHandle 控制台句柄
     * @param text 要写入的文本（以 null 结尾）
     * @return 返回实际写入的字符数，失败返回 0
     */
    DWORD WriteTextToConsole(HANDLE consoleHandle, LPCTSTR text);

    /**
     * @brief 向控制台写入 DWORD 数值（十进制）
     * @param consoleHandle 控制台句柄
     * @param value 要写入的 DWORD 值
     * @return 返回实际写入的字符数，失败返回 0
     */
    DWORD WriteDwordToConsole(HANDLE consoleHandle, DWORD value);

    /**
     * @brief 格式化输出到控制台（类似 _stprintf_s + WriteConsole）
     * @param consoleHandle 控制台句柄
     * @param format 格式化字符串
     * @param ... 可变参数
     * @return 返回实际写入的字符数，失败返回 -1
     */
    DWORD PrintfT(HANDLE consoleHandle, LPCTSTR format, ...);
}

namespace Config {
    inline HANDLE getStdOutputHandle() {
        return GetStdHandle(STD_OUTPUT_HANDLE);
    }
}

#endif //LAIR_WIN32_TOOLS_H