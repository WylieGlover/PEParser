#ifndef HEADERS_WIN32_HPP
#define HEADERS_WIN32_HPP

#include <iostream>

typedef std::uint64_t QWORD;
typedef std::uint32_t DWORD;
typedef std::int32_t LONG;
typedef std::uint16_t WORD;
typedef std::uint8_t BYTE;

constexpr std::uint16_t DOS_MAGIC = 0x5A4D;
constexpr WORD NT_OPTIONAL_HDR32_MAGIC = 0x10b;
constexpr WORD NT_OPTIONAL_HDR64_MAGIC = 0x20b;

constexpr int NUMBER_OF_DIRECTORY_ENTRIES = 16;
constexpr std::uint32_t DIRECTORY_ENTRY_EXPORT = 0;
constexpr std::uint32_t DIRECTORY_ENTRY_IMPORT = 1;
constexpr std::uint32_t DIRECTORY_ENTRY_RESOURCE = 2;
constexpr std::uint32_t DIRECTORY_ENTRY_EXCEPTION = 3;
constexpr std::uint32_t DIRECTORY_ENTRY_SECURITY = 4;
constexpr std::uint32_t DIRECTORY_ENTRY_BASERELOC = 5;
constexpr std::uint32_t DIRECTORY_ENTRY_DEBUG = 6;
constexpr std::uint32_t DIRECTORY_ENTRY_ARCHITECTURE = 7;
constexpr std::uint32_t DIRECTORY_ENTRY_GLOBALPTR = 8;
constexpr std::uint32_t DIRECTORY_ENTRY_TLS = 9;
constexpr std::uint32_t DIRECTORY_ENTRY_LOAD_CONFIG = 10;
constexpr std::uint32_t DIRECTORY_ENTRY_BOUND_IMPORT = 11;
constexpr std::uint32_t DIRECTORY_ENTRY_IAT = 12;
constexpr std::uint32_t DIRECTORY_ENTRY_DELAY_IMPORT = 13;
constexpr std::uint32_t DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;

constexpr std::uint32_t SIZEOF_SHORT_NAME = 8;

struct DOS_HEADER {
    WORD    e_magic;
    WORD    e_cblp;
    WORD    e_cp;
    WORD    e_crlc;
    WORD    e_cparhdr;
    WORD    e_minalloc;
    WORD    e_maxalloc;
    WORD    e_ss;
    WORD    e_sp;
    WORD    e_csum;
    WORD    e_ip;
    WORD    e_cs;
    WORD    e_lfarlc;
    WORD    e_ovno;
    WORD    e_res[4];
    WORD    e_oemid;
    WORD    e_oeminfo;
    WORD    e_res2[10];
    LONG    e_lfanew;
};

struct DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
};

struct FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
};

struct OPTIONAL_HEADER_32 {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    DATA_DIRECTORY DataDirectory[NUMBER_OF_DIRECTORY_ENTRIES];
};

struct OPTIONAL_HEADER_64 {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;

    QWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    QWORD   SizeOfStackReserve;
    QWORD   SizeOfStackCommit;
    QWORD   SizeOfHeapReserve;
    QWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    DATA_DIRECTORY DataDirectory[NUMBER_OF_DIRECTORY_ENTRIES];
};

struct NTHeader_32 {
    DWORD signature;
    FILE_HEADER file_header;
    OPTIONAL_HEADER_32 optional_header32;
};

struct NTHeader_64 {
    DWORD signature;
    FILE_HEADER file_header;
    OPTIONAL_HEADER_64 optional_header64;
};

struct SECTION_HEADER {
    BYTE Name[SIZEOF_SHORT_NAME];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    }Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
};

struct IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;
        DWORD   OriginalFirstThunk;
    } misc;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   FirstThunk;
};

struct IMPORT_BY_NAME {
    WORD Hint;
    char Name[100];
};


struct ILT_ENTRY {
    union {
        DWORD Ordinal;
        DWORD HintNameTable;
    } misc;
    DWORD OrdinalNameFlag;
};

struct THUNK_DATA {
    union {
        DWORD * Function;
        DWORD  Ordinal;
        IMPORT_BY_NAME * AddressOfData;
        DWORD ForwarderString;
    } data;
};

struct BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
};

struct BASE_RELOCATION_ENTRY {
    WORD OFFSET : 12;
    WORD TYPE : 4;
};

struct EXCEPTIONS {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindInfoAddress;
};

struct TLS_CALLBACK64 {
    QWORD Callback;
};

struct TLS_DIRECTORY64 {
    QWORD   StartAddressOfRawData;
    QWORD   EndAddressOfRawData;
    QWORD   AddressOfIndex;
    QWORD   AddressOfCallBacks;
    DWORD   SizeOfZeroFill;
    DWORD   Characteristics;
};


#endif //HEADERS_WIN32_HPP
