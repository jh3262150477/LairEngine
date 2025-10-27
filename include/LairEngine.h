//
// Created by 32621 on 2025/9/29.
//

#ifndef LAIRENGINE_LAIRENGINE_H
#define LAIRENGINE_LAIRENGINE_H
#include "Types.h"
#include <minwindef.h>
#include <tlhelp32.h>
#include <type_traits>
#include <windows.h>
#include <winnt.h>

template <typename T>
concept AllowedType = std::is_same_v<T, Types::Data::Byte> || std::is_same_v<T, Types::Data::Word> ||
    std::is_same_v<T, Types::Data::Dword> || std::is_same_v<T, Types::Data::Float> ||
    std::is_same_v<T, Types::Data::Double> || std::is_same_v<T, Types::Data::IntPtr> ||
    std::is_same_v<T, Types::Data::UIntPtr>;

class LairEngine {
private:
    DWORD ProcessID = 0;
    HANDLE currentProcHandle = NULL;
    BOOL isCurrentProcWow64 = FALSE;
    DWORD dwProcessCount = 0;
    PROCESSENTRY32 *pe32 = NULL;

public:
    LairEngine();
    ~LairEngine();
    VOID setPID(DWORD ProcessID);
    DWORD getPID() const;
    HANDLE getCurrentHandle() const;
    /**
     * @brief 获取进程条目数组的指针。
     * @return 返回进程条目数组的指针。如果没有进程条目，则返回NULL。
     */
    PROCESSENTRY32 *getProcEntry() const;

    /**
     * @brief 返回与当前对象相关联的进程数量。
     * @return 以 DWORD 类型返回的计数值，表示进程的数量。
     */
    DWORD getProcCount() const;

    /**
     * @brief 通过指定的基地址和长度读取内存中的数据。
     * @tparam T 模板类型，表示要读取的数据类型。
     * @param lpAddr 要读取的目标内存地址（UINT_PTR 表示的地址）。
     * @param errorCode 返回错误代码的指针，如果读取成功则为ERROR_SUCCESS。
     * @return 返回读取的数据。
     */
    template <AllowedType T>
    T ReadMemory(Types::Data::Address lpAddr, DWORD *errorCode);

    /**
     * @brief 将一个值写入指定的内存地址。
     * @tparam T 要写入值的类型。
     * @param lpAddr 要写入的目标内存地址（UINT_PTR 表示的地址）。
     * @param targetValue 要写入的值，类型由模板参数 T 确定。
     * @return 返回一个 DWORD，表示写入操作的错误代码。成功时返回 ERROR_SUCCESS。
     */
    template <AllowedType T>
    DWORD WriteMemory(Types::Data::Address lpAddr, T targetValue);

    /**
     * @brief 扫描内存中的目标值，并返回找到的地址。
     * @tparam T 要扫描的值的类型。
     * @param targetValue 要扫描的目标值，类型由模板参数 T 确定。
     * @param pAddrs 返回找到的地址的数组指针。
     * @param pAddrCount 传入时，数组最大容量。传出时，返回实际找到的地址的数量。
     * @return 返回一个 DWORD，表示扫描操作的错误代码。成功时返回 ERROR_SUCCESS。
     */
    template <AllowedType T>
    DWORD ScanMemory(T targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount);

    /**
     * @brief 细化扫描结果，只保留与目标值匹配的地址。
     * @tparam T 要细化的值的类型。
     * @param targetValue 要细化的目标值，类型由模板参数 T 确定。
     * @param pAddrs 要细化的地址数组。
     * @param pAddrCount 传入时，数组最大容量。传出时，返回实际细化的地址的数量。
     * @return 返回一个 DWORD，表示细化操作的错误代码。成功时返回 ERROR_SUCCESS。
     */
    template <AllowedType T>
    DWORD RefineMemory(T targetValue, Types::Data::PAddress pAddrs, DWORD *pAddrCount);

    /**
     * @brief 解析指针链，将基址和偏移量转换为最终地址。
     * @param lpBaseAddr 基址。
     * @param pPointerPath 指针路径。
     * @param pTargetAddr 返回最终地址的指针。
     * @return 返回一个 DWORD，表示解析操作的错误代码。成功时返回 ERROR_SUCCESS。
     */
    DWORD ResolvePointerChain(const Types::AddressInfo::PointerPath& PointerPath,
                              Types::Data::Address *pTargetAddr);


    /**
     * @brief 从指针链读取值。
     * @tparam T 要读取的数据类型。
     * @param PointerPath 指针路径结构。
     * @param errorCode 返回错误代码的指针。
     * @return 返回读取的值。
     */
    template <AllowedType T>
    T ReadValueFromPointerChain(const Types::AddressInfo::PointerPath& PointerPath, DWORD *errorCode);

    /**
     * @brief 获取指定模块的基址。
     * @param moduleName 模块名称（如 L"Game.exe" 或 L"kernel32.dll"）。
     * @return 返回模块基址，失败返回 0。
     */
    Types::Data::Address GetModuleBaseAddress(LPCTSTR moduleName, DWORD *errorCode);
};

#endif  // LAIRENGINE_LAIRENGINE_H
