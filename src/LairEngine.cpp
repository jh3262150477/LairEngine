//
// Created by 32621 on 2025/9/29.
//

#include "LairEngine.h"
#include "Win32Tools.h"

LairEngine::LairEngine() {
    DWORD dwRet = Process::GetAllProcesses(&this->pe32, &this->dwProcessCount);

    if (dwRet == ERROR_SUCCESS) {
        if (pe32 == NULL && dwProcessCount == 0) {
            Console::PrintfT(Config::getStdOutputHandle(), TEXT("fun( %S ) 列出所有进程失败，ErrorCode ：%lu\n"), __func__, dwProcessCount);
        }

    }
    else {
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("fun( %S ) 获取进程列表为空\n"), __func__);
    }
}

LairEngine::~LairEngine() {
    //释放
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

PROCESSENTRY32* LairEngine::getProcEntry() const {
    return this->pe32;
}

DWORD LairEngine::getProcCount() const {
    return this->dwProcessCount;
}

template<AllowedType T>
T LairEngine::ReadMemory(Types::Data::Address lpAddr, DWORD* errorCode) {
    T buffer;
    if (!ReadProcessMemory(getCurrentHandle(), reinterpret_cast<LPCVOID>(lpAddr), &buffer, sizeof(T), NULL)) {
        if (errorCode) {
            *errorCode = GetLastError();
        }
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("fun( %S )读取内存失败，ErrorCode ：%lu\n"), __func__, GetLastError());
        return T();
    }
    if (errorCode) {
        *errorCode = ERROR_SUCCESS;
    }
    return buffer;
}


template<AllowedType T>
DWORD LairEngine::WriteMemory(Types::Data::Address lpAddr, T targetValue) {
    SIZE_T written =0;
    BOOL ok = WriteProcessMemory(this->getCurrentHandle(), reinterpret_cast<LPVOID>(lpAddr), &targetValue, sizeof(T), &written);
    if (!ok || written != sizeof(T)) {
        DWORD err = GetLastError();
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("fun( %S ) 写入失败 ErrorCode=%lu Written=%zu Expect=%zu\n"),
                __func__, err, written, sizeof(T));
        return err;
    }
    return ERROR_SUCCESS;
}


template<AllowedType T>
DWORD LairEngine::ScanMemory(T targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount) {    
    if (pAddrs && pAddrCount) {
        const BYTE* pByte = reinterpret_cast<const BYTE*>(&targetValue);
        SIZE_T typeSize = sizeof(T);
        DWORD foundCount = 0;

        Types::Data::Address address = { 0 };
        MEMORY_BASIC_INFORMATION mbi = { 0 };

        Types::Data::Address maxAddress = this->isCurrentProcWow64 ? 0x00000000FFFFFFFF : 0x00007FFFFFFFFFFF;


        while (address < maxAddress) {
            if (!VirtualQueryEx(this->currentProcHandle, (LPCVOID)address, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
                break;
            }

			//跳过非提交内存区域
            if (mbi.State != MEM_COMMIT) {
				address = reinterpret_cast<Types::Data::Address>(mbi.BaseAddress) + mbi.RegionSize;
                continue;
            }

			//跳过不可读内存区域
			DWORD protect = mbi.Protect & 0xFF;
            if (protect ) {

            }
        }
    } else {
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("f( %s ) Invalid Parameter\n"));
        return ERROR_INVALID_PARAMETER;
    }
    return 0;
}


template Types::Data::Byte LairEngine::ReadMemory<Types::Data::Byte>(Types::Data::Address lpAddr, DWORD* errorCode);
template Types::Data::Word LairEngine::ReadMemory<Types::Data::Word>(Types::Data::Address lpAddr, DWORD* errorCode);
template Types::Data::Dword LairEngine::ReadMemory<Types::Data::Dword>(Types::Data::Address lpAddr, DWORD* errorCode);
template Types::Data::Float LairEngine::ReadMemory<Types::Data::Float>(Types::Data::Address lpAddr, DWORD* errorCode);
template Types::Data::Double LairEngine::ReadMemory<Types::Data::Double>(Types::Data::Address lpAddr, DWORD* errorCode);
template Types::Data::IntPtr LairEngine::ReadMemory<Types::Data::IntPtr>(Types::Data::Address lpAddr, DWORD* errorCode);
template Types::Data::UIntPtr LairEngine::ReadMemory<Types::Data::UIntPtr>(Types::Data::Address lpAddr, DWORD* errorCode);
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