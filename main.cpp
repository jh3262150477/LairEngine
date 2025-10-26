#include "LairEngine.h"
#include "Win32Tools.h"
#include <iostream>

LairEngine lair_engine;

void showMenu();
void run();
void selectProcess();
void newSearch();
void writeMemory();

// 辅助函数：清理输入错误
inline void clearInputError() {
    std::cin.clear();
    std::cin.ignore(10000, '\n');
}

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
    PROCESSENTRY32 *pe32 = lair_engine.getProcEntry();
    DWORD dwProcessCount = lair_engine.getProcCount();
    DWORD choicePid = 0;
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("%-8s\t%ls\n"), TEXT("PID"), TEXT("Process Name"));
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("----------------------------------------\n"));
    // 遍历并输出每个进程
    for (DWORD i = 0; i < dwProcessCount; ++i) {
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("%-8lu\t%ls\n"), pe32[i].th32ProcessID, pe32[i].szExeFile);
    }
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("----------------------------------------\n"));
    Console::PrintfT(Config::getStdOutputHandle(), TEXT("请选择要修改的进程PID:"));
    std::cin >> choicePid;
    lair_engine.setPID(choicePid);
}

void newSearch() {
    // 定义在循环外面，保持搜索状态
    Types::Data::Address *foundAddrs = nullptr;
    DWORD addrCount = 0;
    SHORT currentType = 0;
    
    while (true) {
        system("cls");
        
        // 判断是新搜索还是改善搜索
        bool isRefineSearch = (foundAddrs != nullptr && addrCount > 0);
        
        if (isRefineSearch) {
            Console::PrintfT(Config::getStdOutputHandle(), TEXT("========== 改善搜索 ==========\n"));
            Console::PrintfT(Config::getStdOutputHandle(), TEXT("当前类型：%d，剩余地址数：%lu\n"), currentType, addrCount);
        } else {
            Console::PrintfT(Config::getStdOutputHandle(), TEXT("========== 新的搜索 ==========\n"));
            Console::PrintfT(Config::getStdOutputHandle(), TEXT("1、Byte   2、Word   3、Dword\n"));
            Console::PrintfT(Config::getStdOutputHandle(), TEXT("4、Float  5、Double\n"));
            Console::PrintfT(Config::getStdOutputHandle(), TEXT("6、IntPtr 7、UIntPtr\n"));
            Console::PrintfT(Config::getStdOutputHandle(), TEXT("0、返回主菜单\n"));
            Console::PrintfT(Config::getStdOutputHandle(), TEXT("请选择类型: "));
            
            if (!(std::cin >> currentType)) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("输入无效！\n"));
                clearInputError();
                system("pause");
                continue;
            }
            
            if (currentType == 0) {
                if (foundAddrs) delete[] foundAddrs;
                return;
            }
            if (currentType < 1 || currentType > 7) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("无效选项！\n"));
                system("pause");
                continue;
            }
            
            // 准备地址数组
            const DWORD MAX_RESULTS = 100000;
            if (foundAddrs != nullptr) {
                delete[] foundAddrs;
            }
            foundAddrs = new Types::Data::Address[MAX_RESULTS];
            addrCount = MAX_RESULTS;
        }
        
        Console::PrintfT(Config::getStdOutputHandle(), TEXT("请输入值 (输入 0 返回): "));
        
        bool success = false;
        DWORD result = 0;
        bool shouldContinue = false;
        
        // 根据类型执行搜索或改善
        switch (currentType) {
        case 1: { // Byte
            UINT temp;
            if (!(std::cin >> temp) || temp > 255) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("输入无效或超出范围 (0-255)！\n"));
                clearInputError();
                system("pause");
                shouldContinue = true;
                break;
            }
            if (temp == 0 && isRefineSearch) {
                if (foundAddrs) delete[] foundAddrs;
                return;
            }
            Types::Data::Byte value = (Types::Data::Byte)temp;
            if (isRefineSearch) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("正在改善搜索 Byte ...\n"));
                result = lair_engine.RefineMemory<Types::Data::Byte>(value, foundAddrs, &addrCount);
            } else {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("正在搜索 Byte ...\n"));
                result = lair_engine.ScanMemory<Types::Data::Byte>(value, foundAddrs, &addrCount);
            }
            success = (result == ERROR_SUCCESS);
            break;
        }
        case 2: { // Word
            UINT temp;
            if (!(std::cin >> temp) || temp > 65535) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("输入无效或超出范围 (0-65535)！\n"));
                clearInputError();
                system("pause");
                shouldContinue = true;
                break;
            }
            if (temp == 0 && isRefineSearch) {
                if (foundAddrs) delete[] foundAddrs;
                return;
            }
            Types::Data::Word value = (Types::Data::Word)temp;
            if (isRefineSearch) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("正在改善搜索 Word ...\n"));
                result = lair_engine.RefineMemory<Types::Data::Word>(value, foundAddrs, &addrCount);
            } else {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("正在搜索 Word ...\n"));
                result = lair_engine.ScanMemory<Types::Data::Word>(value, foundAddrs, &addrCount);
            }
            success = (result == ERROR_SUCCESS);
            break;
        }
        case 3: { // Dword
            Types::Data::Dword value;
            if (!(std::cin >> value)) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("输入无效！\n"));
                clearInputError();
                system("pause");
                shouldContinue = true;
                break;
            }
            if (value == 0 && isRefineSearch) {
                if (foundAddrs) delete[] foundAddrs;
                return;
            }
            if (isRefineSearch) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("正在改善搜索 Dword ...\n"));
                result = lair_engine.RefineMemory<Types::Data::Dword>(value, foundAddrs, &addrCount);
            } else {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("正在搜索 Dword ...\n"));
                result = lair_engine.ScanMemory<Types::Data::Dword>(value, foundAddrs, &addrCount);
            }
            success = (result == ERROR_SUCCESS);
            break;
        }
        case 4: { // Float
            Types::Data::Float value;
            if (!(std::cin >> value)) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("输入无效！\n"));
                clearInputError();
                system("pause");
                shouldContinue = true;
                break;
            }
            if (value == 0.0f && isRefineSearch) {
                if (foundAddrs) delete[] foundAddrs;
                return;
            }
            if (isRefineSearch) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("正在改善搜索 Float ...\n"));
                result = lair_engine.RefineMemory<Types::Data::Float>(value, foundAddrs, &addrCount);
            } else {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("正在搜索 Float ...\n"));
                result = lair_engine.ScanMemory<Types::Data::Float>(value, foundAddrs, &addrCount);
            }
            success = (result == ERROR_SUCCESS);
            break;
        }
        case 5: { // Double
            Types::Data::Double value;
            if (!(std::cin >> value)) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("输入无效！\n"));
                clearInputError();
                system("pause");
                shouldContinue = true;
                break;
            }
            if (value == 0.0 && isRefineSearch) {
                if (foundAddrs) delete[] foundAddrs;
                return;
            }
            if (isRefineSearch) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("正在改善搜索 Double ...\n"));
                result = lair_engine.RefineMemory<Types::Data::Double>(value, foundAddrs, &addrCount);
            } else {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("正在搜索 Double ...\n"));
                result = lair_engine.ScanMemory<Types::Data::Double>(value, foundAddrs, &addrCount);
            }
            success = (result == ERROR_SUCCESS);
            break;
        }
        case 6: { // IntPtr
            Types::Data::IntPtr value;
            if (!(std::cin >> value)) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("输入无效！\n"));
                clearInputError();
                system("pause");
                shouldContinue = true;
                break;
            }
            if (value == 0 && isRefineSearch) {
                if (foundAddrs) delete[] foundAddrs;
                return;
            }
            if (isRefineSearch) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("正在改善搜索 IntPtr ...\n"));
                result = lair_engine.RefineMemory<Types::Data::IntPtr>(value, foundAddrs, &addrCount);
            } else {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("正在搜索 IntPtr ...\n"));
                result = lair_engine.ScanMemory<Types::Data::IntPtr>(value, foundAddrs, &addrCount);
            }
            success = (result == ERROR_SUCCESS);
            break;
        }
        case 7: { // UIntPtr
            Types::Data::UIntPtr value;
            if (!(std::cin >> value)) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("输入无效！\n"));
                clearInputError();
                system("pause");
                shouldContinue = true;
                break;
            }
            if (value == 0 && isRefineSearch) {
                if (foundAddrs) delete[] foundAddrs;
                return;
            }
            if (isRefineSearch) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("正在改善搜索 UIntPtr ...\n"));
                result = lair_engine.RefineMemory<Types::Data::UIntPtr>(value, foundAddrs, &addrCount);
            } else {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("正在搜索 UIntPtr ...\n"));
                result = lair_engine.ScanMemory<Types::Data::UIntPtr>(value, foundAddrs, &addrCount);
            }
            success = (result == ERROR_SUCCESS);
            break;
        }
        }
        
        if (shouldContinue) {
            continue;
        }
        
        // 显示搜索结果
        if (success) {
            Console::PrintfT(Config::getStdOutputHandle(), TEXT("\n搜索完成！找到 %lu 个地址\n"), addrCount);
            if (addrCount == 0) {
                Console::PrintfT(Config::getStdOutputHandle(), TEXT("没有找到匹配的地址，重置搜索状态。\n"));
                delete[] foundAddrs;
                foundAddrs = nullptr;
                currentType = 0;
            } else {
                DWORD displayCount = (addrCount > 50) ? 50 : addrCount;
                for (DWORD i = 0; i < displayCount; i++) {
                    Console::PrintfT(Config::getStdOutputHandle(), TEXT("[%lu] -> %llX\n"), i + 1, foundAddrs[i]);
                }
                if (addrCount > 50) {
                    Console::PrintfT(Config::getStdOutputHandle(), TEXT("... 还有 %lu 个地址\n"), addrCount - 50);
                }
            }
        } else {
            Console::PrintfT(Config::getStdOutputHandle(), TEXT("搜索失败！\n"));
        }
        
        system("pause");
    }
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