#include "LairEngine.h"
#include <basetsd.h>
#include <minwindef.h>
#include <cstddef>
#include "Types.h"
#include "Win32Tools.h"

LairEngine::LairEngine() {
    DWORD dwRet = Process::GetAllProcesses(&this->pe32, &this->dwProcessCount);

    if (dwRet == ERROR_SUCCESS) {
        if (pe32 == NULL && dwProcessCount == 0) {
            Console::PrintfT(
                Config::getStdOutputHandle(),
                TEXT("fun( %S ) 列出所有进程失败，ErrorCode ：%lu\n"),
                __func__,
                dwProcessCount);
        }
    } else {
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("fun( %S ) 获取进程列表为空\n"), __func__);
    }
}

LairEngine::~LairEngine() {
    // 释放
    CloseHandle(this->currentProcHandle);
}

VOID LairEngine::setPID(DWORD ProcessID) {
    this->ProcessID = ProcessID;
    this->currentProcHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
    if (currentProcHandle == NULL) {
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("fun( %S ) 打开进程失败\n"), __func__);
    } else {
        BOOL IsWow64 = FALSE;
        if (IsWow64Process(currentProcHandle, &IsWow64)) {
            this->isCurrentProcWow64 = IsWow64;
        } else {
            Console::PrintfT(Config::getStdOutputHandle(), TEXT("fun( %S ) 判断进程架构失败\n"), __func__);
        }
    }
}

DWORD LairEngine::getPID() const {
    return this->ProcessID;
}

HANDLE LairEngine::getCurrentHandle() const {
    return this->currentProcHandle;
}

PROCESSENTRY32 *LairEngine::getProcEntry() const {
    return this->pe32;
}

DWORD LairEngine::getProcCount() const {
    return this->dwProcessCount;
}

template <AllowedType T>
T LairEngine::ReadMemory(Types::Data::Address lpAddr, DWORD *errorCode) {
    T buffer;
    if (!ReadProcessMemory(this->currentProcHandle, reinterpret_cast<LPCVOID>(lpAddr), &buffer, sizeof(T), NULL)) {
        if (errorCode) {
            *errorCode = GetLastError();
        }
        Console::PrintfT(
            Config::getStdOutputHandle(), TEXT("fun( %S )读取内存失败，ErrorCode ：%lu\n"), __func__, GetLastError());
        return T();
    }
    if (errorCode) {
        *errorCode = ERROR_SUCCESS;
    }
    return buffer;
}

template <AllowedType T>
DWORD LairEngine::WriteMemory(Types::Data::Address lpAddr, T targetValue) {
    if (!lpAddr) {
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("fun( %S ) Invalid Address\n"), __func__);
        return ERROR_INVALID_PARAMETER;
    }

    if (!this->currentProcHandle || this->currentProcHandle == INVALID_HANDLE_VALUE) {
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("fun( %S ) Invalid Process Handle\n"), __func__);
        return ERROR_INVALID_HANDLE;
    }

    SIZE_T written = 0;
    BOOL ok = WriteProcessMemory(
        this->getCurrentHandle(), reinterpret_cast<LPVOID>(lpAddr), &targetValue, sizeof(T), &written);
    if (!ok || written != sizeof(T)) {
        DWORD err = GetLastError();
        Console::PrintfT(
            Config::getStdOutputHandle(),
            TEXT("fun( %S ) 写入失败 ErrorCode=%lu Written=%zu Expect=%zu\n"),
            __func__,
            err,
            written,
            sizeof(T));
        return err;
    }
    return ERROR_SUCCESS;
}

template <AllowedType T>
DWORD LairEngine::ScanMemory(T targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount) {
    // 参数校验
    if (!pAddrs || !pAddrCount || *pAddrCount == 0) {
        if (pAddrCount)
            *pAddrCount = 0;
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("fun( %S ) Invalid Parameter\n"), __func__);
        return ERROR_INVALID_PARAMETER;
    }

    // 检查进程句柄
    if (!this->currentProcHandle || this->currentProcHandle == INVALID_HANDLE_VALUE) {
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("fun( %S ) Invalid Process Handle\n"), __func__);
        *pAddrCount = 0;
        return ERROR_INVALID_HANDLE;
    }

    const BYTE *pTargetValue = reinterpret_cast<const BYTE *>(&targetValue);
    SIZE_T typeSize = sizeof(T);
    DWORD maxCapacity = *pAddrCount; // 数组最大容量
    DWORD foundCount = 0;            // 已找到数量

    Types::Data::Address address = 0;
    MEMORY_BASIC_INFORMATION mbi = {0};

    // 设置最大扫描地址
    Types::Data::Address maxAddress = this->isCurrentProcWow64 ? 0x00000000FFFFFFFFULL : 0x00007FFFFFFFFFFFULL;

    while (address < maxAddress) {
        if (!VirtualQueryEx(this->currentProcHandle, (LPCVOID)address, &mbi, sizeof(mbi))) {
            // VirtualQueryEx 失败，遍历完成
            break;
        }

        // 跳过非提交内存区域
        if (mbi.State != MEM_COMMIT) {
            address = (Types::Data::Address)mbi.BaseAddress + mbi.RegionSize;
            continue;
        }

        // 跳过有特殊标志的页
        if ((mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOCACHE) || (mbi.Protect & PAGE_NOACCESS)) {
            address = (Types::Data::Address)mbi.BaseAddress + mbi.RegionSize;
            continue;
        }

        // 获取基础保护属性
        DWORD baseProtect = mbi.Protect & 0xFF;

        // 只扫描可读的内存区域（包括只读、可读写等）
        if (baseProtect != PAGE_READWRITE && 
            baseProtect != PAGE_WRITECOPY && 
            baseProtect != PAGE_EXECUTE_READWRITE &&
            baseProtect != PAGE_EXECUTE_WRITECOPY) {
            address = (Types::Data::Address)mbi.BaseAddress + mbi.RegionSize;
            continue;
        }

        // 跳过太小的内存区域
        if (mbi.RegionSize < typeSize) {
            address = (Types::Data::Address)mbi.BaseAddress + mbi.RegionSize;
            continue;
        }

        // 分块读取（1MB 缓冲区）
        constexpr SIZE_T BUFFER_SIZE = 0x100000;
        BYTE buffer[BUFFER_SIZE];

        // 扫描整个内存区域（不限制大小）
        SIZE_T offset = 0;
        while (offset < mbi.RegionSize) {
            SIZE_T readSize = ((mbi.RegionSize - offset) < BUFFER_SIZE) ? (mbi.RegionSize - offset) : BUFFER_SIZE;
            SIZE_T bytesRead = 0;

            LPVOID readAddr = (LPBYTE)mbi.BaseAddress + offset;
            if (!ReadProcessMemory(this->currentProcHandle, readAddr, buffer, readSize, &bytesRead) || bytesRead == 0) {
                // 读取失败，跳过该块
                offset += readSize;
                continue;
            }

            // 在 buffer 中搜索目标值
            for (SIZE_T i = 0; i + typeSize <= bytesRead; i+= typeSize) {
                if (*(T*)(buffer + i) == targetValue) {
                    Types::Data::Address foundAddr = (Types::Data::Address)readAddr + i;

                    // WOW64 进程安全检查
                    if (this->isCurrentProcWow64 && foundAddr > 0xFFFFFFFFULL) {
                        continue;
                    }

                    // 保存找到的地址
                    if (foundCount < maxCapacity) {
                        pAddrs[foundCount++] = foundAddr;
                    } else {
                        // 数组已满，提前返回
                        *pAddrCount = foundCount;
                        return ERROR_SUCCESS;
                    }
                }
            }

            offset += bytesRead; // 按实际读取量推进
        }

        // 移动到下一个内存区域
        address = (Types::Data::Address)mbi.BaseAddress + mbi.RegionSize;

        // 防止地址溢出
        if (address <= (Types::Data::Address)mbi.BaseAddress) {
            break;
        }
    }

    *pAddrCount = foundCount;
    return ERROR_SUCCESS;
}

template <AllowedType T>
DWORD LairEngine::RefineMemory(T targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount) {
    if (!pAddrs || !pAddrCount || *pAddrCount == 0) {
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("fun( %S ) Invalid Parameter\n"), __func__);
        return ERROR_INVALID_PARAMETER;
    }

    // 获取目标值的字节表示
    const BYTE *pTargetValue = reinterpret_cast<const BYTE *>(&targetValue);
    SIZE_T typeSize = sizeof(T);
    DWORD maxCapacity = *pAddrCount; // 原始地址数量
    DWORD refinedCount = 0;            // 精化后的地址数量
    DWORD readErrors = 0;              // 读取错误数量

    // 遍历所有输入的地址
    for (DWORD i = 0; i < maxCapacity; ++i) {
        Types::Data::Address currentAddr = pAddrs[i];

        // 从目标地址读取内存
        BYTE buffer[sizeof(T)] = {0};
        SIZE_T bytesRead = 0;

        if (!ReadProcessMemory(
                this->currentProcHandle, reinterpret_cast<LPCVOID>(currentAddr), buffer, typeSize, &bytesRead)) {
            // 读取失败，跳过该地址
            readErrors++;
            continue;
        }

        // 比较读取的值与目标值
        if (bytesRead == typeSize && memcmp(buffer, pTargetValue, typeSize) == 0) {
            // 匹配，保留该地址
            pAddrs[refinedCount++] = currentAddr;
        }
    }

    Console::PrintfT(Config::getStdOutputHandle(),TEXT("fun( %S ) Refined: %lu -> %lu addresses (Read Errors: %lu)\n"), __func__, maxCapacity, refinedCount, readErrors);
    // 更新返回的地址数量
    *pAddrCount = refinedCount;
    return ERROR_SUCCESS;
}

DWORD LairEngine::ResolvePointerChain(const Types::AddressInfo::PointerPath& PointerPath, Types::Data::Address *pTargetAddr) {
    if (!pTargetAddr) {
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("fun( %S ) Invalid Parameter\n"), __func__);
        return ERROR_INVALID_PARAMETER;
    }

    if (PointerPath.offsets.empty()) {
        *pTargetAddr = PointerPath.baseAddr;
        return ERROR_SUCCESS;
    }

    Types::Data::Address currentAddr = PointerPath.baseAddr;
    for (SIZE_T i = 0; i < PointerPath.offsets.size(); ++i) {
        Types::Data::Address pointer = 0;
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(this->currentProcHandle, reinterpret_cast<LPCVOID>(currentAddr), &pointer, sizeof(Types::Data::Address), &bytesRead) || bytesRead == 0) {
            Console::PrintfT(Config::getStdOutputHandle(), TEXT("fun( %S ) Read Memory Failed\n"), __func__);
            return ERROR_READ_FAULT;
        }
        currentAddr = pointer + PointerPath.offsets[i];
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("fun( %S ) Current Address: 0x%llX\n"), __func__, currentAddr);
    } 
    *pTargetAddr = currentAddr;
    return ERROR_SUCCESS;
}

template <AllowedType T>
T LairEngine::ReadValueFromPointerChain(const Types::AddressInfo::PointerPath &PointerPath, DWORD *errorCode) {
    Types::Data::Address pTargetAddr = 0;
    DWORD ret = ResolvePointerChain(PointerPath, &pTargetAddr);
    if (ret != ERROR_SUCCESS) {
        if (errorCode) {
            *errorCode = ret;
        }
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("fun( %S ) Resolve Pointer Chain Failed\n"), __func__);
        return T();
    }
    return ReadMemory<T>(pTargetAddr, errorCode);
}

Types::Data::Address LairEngine::GetModuleBaseAddress(LPCTSTR moduleName, DWORD *errorCode) {
    return Process::GetModuleBaseAddress(this->ProcessID, moduleName, errorCode);
}


//实例化模板
template Types::Data::Byte LairEngine::ReadMemory<Types::Data::Byte>(Types::Data::Address lpAddr, DWORD *errorCode);
template Types::Data::Word LairEngine::ReadMemory<Types::Data::Word>(Types::Data::Address lpAddr, DWORD *errorCode);
template Types::Data::Dword LairEngine::ReadMemory<Types::Data::Dword>(Types::Data::Address lpAddr, DWORD *errorCode);
template Types::Data::Float LairEngine::ReadMemory<Types::Data::Float>(Types::Data::Address lpAddr, DWORD *errorCode);
template Types::Data::Double LairEngine::ReadMemory<Types::Data::Double>(Types::Data::Address lpAddr, DWORD *errorCode);
template Types::Data::IntPtr LairEngine::ReadMemory<Types::Data::IntPtr>(Types::Data::Address lpAddr, DWORD *errorCode);
template Types::Data::UIntPtr LairEngine::ReadMemory<Types::Data::UIntPtr>(Types::Data::Address lpAddr, DWORD *errorCode);
template DWORD LairEngine::WriteMemory<Types::Data::Byte>(Types::Data::Address lpAddr, Types::Data::Byte targetValue);
template DWORD LairEngine::WriteMemory<Types::Data::Word>(Types::Data::Address lpAddr, Types::Data::Word targetValue);
template DWORD LairEngine::WriteMemory<Types::Data::Dword>(Types::Data::Address lpAddr, Types::Data::Dword targetValue);
template DWORD LairEngine::WriteMemory<Types::Data::Float>(Types::Data::Address lpAddr, Types::Data::Float targetValue);
template DWORD LairEngine::WriteMemory<Types::Data::Double>(Types::Data::Address lpAddr, Types::Data::Double targetValue);
template DWORD LairEngine::WriteMemory<Types::Data::IntPtr>(Types::Data::Address lpAddr, Types::Data::IntPtr targetValue);
template DWORD LairEngine::WriteMemory<Types::Data::UIntPtr>(Types::Data::Address lpAddr, Types::Data::UIntPtr targetValue);
template DWORD LairEngine::ScanMemory<Types::Data::Byte>(Types::Data::Byte targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount);
template DWORD LairEngine::ScanMemory<Types::Data::Word>(Types::Data::Word targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount);
template DWORD LairEngine::ScanMemory<Types::Data::Dword>(Types::Data::Dword targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount);
template DWORD LairEngine::ScanMemory<Types::Data::Float>(Types::Data::Float targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount);
template DWORD LairEngine::ScanMemory<Types::Data::Double>(Types::Data::Double targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount);
template DWORD LairEngine::ScanMemory<Types::Data::IntPtr>(Types::Data::IntPtr targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount);
template DWORD LairEngine::ScanMemory<Types::Data::UIntPtr>(Types::Data::UIntPtr targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount);
template DWORD LairEngine::RefineMemory<Types::Data::Byte>(Types::Data::Byte targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount);
template DWORD LairEngine::RefineMemory<Types::Data::Word>(Types::Data::Word targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount);
template DWORD LairEngine::RefineMemory<Types::Data::Dword>(Types::Data::Dword targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount);
template DWORD LairEngine::RefineMemory<Types::Data::Float>(Types::Data::Float targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount);
template DWORD LairEngine::RefineMemory<Types::Data::Double>(Types::Data::Double targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount);
template DWORD LairEngine::RefineMemory<Types::Data::IntPtr>(Types::Data::IntPtr targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount);
template DWORD LairEngine::RefineMemory<Types::Data::UIntPtr>(Types::Data::UIntPtr targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount);
template Types::Data::Byte LairEngine::ReadValueFromPointerChain<Types::Data::Byte>(const Types::AddressInfo::PointerPath& PointerPath, DWORD *errorCode);
template Types::Data::Word LairEngine::ReadValueFromPointerChain<Types::Data::Word>(const Types::AddressInfo::PointerPath& PointerPath, DWORD *errorCode);
template Types::Data::Dword LairEngine::ReadValueFromPointerChain<Types::Data::Dword>(const Types::AddressInfo::PointerPath& PointerPath, DWORD *errorCode);
template Types::Data::Float LairEngine::ReadValueFromPointerChain<Types::Data::Float>(const Types::AddressInfo::PointerPath& PointerPath, DWORD *errorCode);
template Types::Data::Double LairEngine::ReadValueFromPointerChain<Types::Data::Double>(const Types::AddressInfo::PointerPath &PointerPath, DWORD *errorCode);
template Types::Data::IntPtr LairEngine::ReadValueFromPointerChain<Types::Data::IntPtr>(const Types::AddressInfo::PointerPath &PointerPath, DWORD *errorCode);
template Types::Data::UIntPtr LairEngine::ReadValueFromPointerChain<Types::Data::UIntPtr>(const Types::AddressInfo::PointerPath &PointerPath, DWORD *errorCode);