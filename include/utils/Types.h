#ifndef LAIR_ENGINE_TYPES_H
#define LAIR_ENGINE_TYPES_H

#include <Windows.h>
#include <vector>

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
}  // namespace Data

namespace AddressInfo {
    typedef struct _AddressEntry {
        Types::Data::Address addr;
        LPVOID value;
        
        _AddressEntry() : addr(0), value(nullptr) {}
        _AddressEntry(Types::Data::Address a, LPVOID v) : addr(a), value(v) {}
    } AddressEntry;
    typedef AddressEntry* PAddressEntry;

    typedef struct _PointerPath {
        Types::Data::Address baseAddr;
        std::vector<DWORD> offsets;

        _PointerPath() : baseAddr(0), offsets() {}
        _PointerPath(Types::Data::Address b, std::vector<DWORD> o) : baseAddr(b), offsets(o) {}

        void addOffset(DWORD offset) { offsets.push_back(offset); }

        SIZE_T getDepth() const{
            return offsets.size();
        }
    } PointerPath;
}
}

#endif  // LAIR_ENGINE_TYPES_H
