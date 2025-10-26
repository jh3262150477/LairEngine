#ifndef LAIR_ENGINE_TYPES_H
#define LAIR_ENGINE_TYPES_H

#include <Windows.h>

namespace Types {
namespace Data {
    typedef BYTE Byte;
    typedef WORD Word;
    typedef DWORD Dword;
    typedef FLOAT Float;
    typedef DOUBLE Double;
    typedef INT_PTR IntPtr;
    typedef UINT_PTR UIntPtr;
    typedef UINT64 Address;
    typedef Address* PAddress;
    typedef struct _AddressEntry {
        UINT64 addr;
        LPVOID value;
    } AddressEntry;
    typedef Address* PAddressEntry;
}  // namespace Data
}  // namespace Types

#endif  // LAIR_ENGINE_TYPES_H
