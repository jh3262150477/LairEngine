#include "Win32Tools.h"
#include "LairEngine.h"
#include <iostream>

LairEngine lair_engine;

void showMenu();
void run();
void selectProcess();
void newSearch();
void writeMemory();

void showMenu() {
    system("cls");
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("========== LairEngine V0.1 ==========\n"));
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("           当前进程ID：%lu\n"), lair_engine.getPID());
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("1、选择进程\n"));
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("2、新的搜索\n"));
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("3、改善搜索\n"));
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("3、修改内存\n"));
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("0、退出\n"));
}

void run() {
    int choice = 0;
    do {
        showMenu();
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("请输入你要选择的选项："));
        std::cin >> choice;
        switch (choice) {
        case 0:
            exit(0);
        case 1:
            selectProcess();
            break;
        case 2:
            newSearch();
            break;
        case 3:
            writeMemory();
            break;
        default:
            Console::PrintfT(Config::getStdOutputHandle(), TEXT("无效选项，\n"));
            system("pause");
            break;
        }
    } while (true);
}

void selectProcess() {
    system("cls");
    PROCESSENTRY32* pe32 = lair_engine.getProcEntry();
    DWORD dwProcessCount = lair_engine.getProcCount();
    DWORD choicePid = 0;
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("%-8s\t%ls\n"), TEXT("PID"), TEXT("Process Name"));
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("----------------------------------------\n"));
    // 遍历并输出每个进程
    for (DWORD i = 0; i < dwProcessCount; ++i) {
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("%-8lu\t%ls\n"),
                pe32[i].th32ProcessID,
                pe32[i].szExeFile);
    }
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("----------------------------------------\n"));
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("请选择要修改的进程PID:"));
    std::cin >> choicePid;
    lair_engine.setPID(choicePid);
}

void newSearch() {
    DWORD pAddr = 0;
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("请输入要搜索的16进制地址值:"));
    std::cin >> std::hex >> pAddr;
    DWORD errorCode = 0;
    DWORD result = lair_engine.ReadMemory<DWORD>(pAddr, &errorCode);
    if (errorCode == ERROR_SUCCESS) {
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("地址 0x%08X 处的值为: %lu\n"), pAddr, result);
    }
    system("pause");
}

void writeMemory() {
    UINT_PTR pAddr = 0;
    DWORD newValue = 0;
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("请输入要修改的16进制地址值:"));
    std::cin >> std::hex >> pAddr;
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("请输入要修改的新值:"));
    std::cin >> std::dec >> newValue;
    DWORD errorCode = lair_engine.WriteMemory<DWORD>(pAddr, newValue);
    if (errorCode == ERROR_SUCCESS) {
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("地址 0x%08X 处的值已成功修改为: %lu\n"), pAddr, newValue);
    }
    system("pause");
}

int main() {
    run();
    system("pause");
    return 0;
}