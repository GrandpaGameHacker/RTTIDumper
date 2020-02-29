#include "pch.h"
#include "dllmain.h"
#include <DbgHelp.h>
#include <fstream>
#include <TlHelp32.h>
#pragma comment(lib,"dbghelp.lib")

/*CurrentNotes:

#FEATURE
Constructor Analysis (Possible members, Memory Size) (Include base class constructors, call traversal??)
Trying to wrap my head around a generic solution is just fuck.
!Use Zydis for Asm Parse! Fast and lightweight
64 bit Constructor AOB Scan - Could be useful for constructor stuff
LEA RAX, [VFTABLE-THISADDRESS];
MOV [RBX], RAX; 
48 8D 05 ?? ?? ?? ??  48 89 03
#ENDFEATURE
*/


#define MAX_DEMANGLE_BUFFER_SIZE 0x1000

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)RTTIDumper, NULL, NULL, NULL);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

std::string DemangleSymbol(char* symbol)
{
    //Attempts to process a symbol as a const virtual function table
    //tries to make allowences for edge cases
    //There are still a few cases that fail.
    std::string VFTableSymbolStart = "??_7";
    std::string VFTableSymbolEnd = "6B@";
    char buff[MAX_DEMANGLE_BUFFER_SIZE] = { 0 };
    memset(buff, 0, MAX_DEMANGLE_BUFFER_SIZE);
    char* pSymbol = symbol;
    if (*(char*)(symbol + 4) == '?') pSymbol = symbol + 1;
    else if (*(char*)symbol == '.') pSymbol = symbol + 4;
    else if (*(char*)symbol == '?') pSymbol = symbol + 2;
    
    else
    {
        puts("invalid msvc mangled name\n");
    }
    std::string ModifiedSymbol = std::string(pSymbol);
    ModifiedSymbol.insert(0, VFTableSymbolStart);
    ModifiedSymbol.insert(ModifiedSymbol.size(), VFTableSymbolEnd);
    if (!((UnDecorateSymbolName(ModifiedSymbol.c_str(), buff, MAX_DEMANGLE_BUFFER_SIZE, 0)) != 0))
    {
        printf("error %x\n", GetLastError());
        return std::string(symbol); //Failsafe
    }
    return std::string(buff);
}

void StrFilter(std::string& string, const std::string& substring)
{
    size_t pos = std::string::npos;
    while ((pos = string.find(substring)) != std::string::npos)
    {
        string.erase(pos, substring.length());
    }
}

void ApplySymbolFilters(std::string& Symbol)
{
    std::vector<std::string> filters = {"::`vftable'", "const ", "::`anonymous namespace'"};
    for (std::string filter : filters)
    {
        StrFilter(Symbol, filter);
    }
}

bool IsMemoryRangeReadable(void* ptr, size_t byteCount)
{
    void* tempBuffer = malloc(byteCount);
    if (tempBuffer)
    {
        bool readable = ReadProcessMemory(GetCurrentProcess(), ptr, tempBuffer, byteCount, nullptr);
        free(tempBuffer);
        return readable;
    }
    return false;
}

bool IsMemoryNotExecutable(void* ptr)
{
    MEMORY_BASIC_INFORMATION MemInfo{ 0 };
    VirtualQuery(ptr, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION));
    DWORD mask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY);
    bool b = (MemInfo.Protect & mask);
    return b;
};

bool IsMemoryReadable(void* ptr)
{
    MEMORY_BASIC_INFORMATION MemInfo{ 0 };
    VirtualQuery(ptr, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION));
    DWORD mask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
    bool b = (MemInfo.Protect & mask);
    return b;
};

void FixupImageNoAccess(uintptr_t moduleBase)
{
    /*When image sections are in memory as comitted
    but set to PAGE_NOACCESS this comes in handy.
    This stops the Dumper from skipping a module, just because it has an
    unreadable section in the PE file*/
    MEMORY_BASIC_INFORMATION MemInfo { 0 };
    size_t offset { 0 };
    do
    {
        void* addr = (void*)(moduleBase + offset);
        VirtualQuery(addr, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION));
        if (MemInfo.Type == MEM_IMAGE && MemInfo.State == MEM_COMMIT && MemInfo.Protect == PAGE_NOACCESS)
        {
            DWORD flOldProtect;
            VirtualProtect(MemInfo.BaseAddress, MemInfo.RegionSize, PAGE_READONLY, &flOldProtect);
        }
        offset += MemInfo.RegionSize;
    } while (MemInfo.Type == MEM_IMAGE);
}


void RTTIDumper()
{
    FILE* nullfile = nullptr;
    AllocConsole();
    freopen_s(&nullfile, "CONOUT$", "w", stdout);
    SetConsoleTitle("RTTI Class Dumper");
    DWORD CurrentProcessId = GetCurrentProcessId();
    std::cout << "Injected into processID: " << CurrentProcessId << std::endl;

    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, CurrentProcessId);
    if (hModuleSnap == INVALID_HANDLE_VALUE)
    {
        std::cout << "CreateToolhelp32Snapshot";
        return;
    }
    MODULEENTRY32 ModuleEntry;
    ModuleEntry.dwSize = sizeof(MODULEENTRY32);
    const char* sTypeInfo = ".?AVtype_info@@";
    const size_t length = strlen(sTypeInfo);

    std::ofstream VFTableLogStream;
    VFTableLogStream.open("vftable.txt");
    VFTableLogStream << "vftable_virtual : vftable_rva : symbol\n";

    std::ofstream InheritanceLogStream;
    InheritanceLogStream.open("inheritance.txt");
    InheritanceLogStream << "class A : class B : class N...\n";

    if (!Module32First(hModuleSnap, &ModuleEntry))
    {
        std::cout << "Module32First:" << GetLastError() << std::endl;
        CloseHandle(hModuleSnap);
        return;
    }
        bool NotFinished = true;
        do
        {
            uintptr_t baseAddress = (uintptr_t)ModuleEntry.modBaseAddr;
            uintptr_t sizeOfImage = (uintptr_t)ModuleEntry.modBaseSize;
            std::string moduleName = std::string(ModuleEntry.szModule);

            if (!IsMemoryRangeReadable((void*)(baseAddress), sizeOfImage))
            {
                std::cout << "WARNING: Fixing Image due to unreadable sections!" << std::endl;
                FixupImageNoAccess(baseAddress);
            }

            if (!IsMemoryRangeReadable((void*)(baseAddress), sizeOfImage))
            {
                NotFinished = Module32Next(hModuleSnap, &ModuleEntry);
                continue;
            }

            uintptr_t type_info_ptr = PatternScan::FindFirstString(baseAddress, sizeOfImage-length, sTypeInfo, length);
            TypeDescriptor* type_info = (TypeDescriptor*)(type_info_ptr - (sizeof(uintptr_t) * 2));

            if (!type_info_ptr)
            {
                NotFinished = Module32Next(hModuleSnap, &ModuleEntry);
                continue;
            }
            else
            {
                std::cout << moduleName << " contains RTTI" << std::endl;
                VFTableLogStream << "!<" << moduleName << ">!\n";
                InheritanceLogStream << "!<" << moduleName << ">!\n";
                std::cout << "Found RTTI0 at: " << std::hex << type_info << std::endl;
                std::cout << "Scanning for TypeDescriptor structs..." << std::endl;
                auto TypesFound = PatternScan::FindReferences(baseAddress, sizeOfImage, type_info->pVFTable);

                std::cout << "Finding VFTables via RTTI" << std::endl;
                size_t TotalDumped = 0;
                for (auto Type : TypesFound)
                {

                    uintptr_t
                        ObjectLocator = NULL,
                        MetaPointer = NULL,
                        VFTable = NULL,
                        VFTableRVA = NULL;
#ifdef _WIN64
                    DWORD TypeOffset = (DWORD)(Type - baseAddress);
                    auto references = PatternScan::FindReferencesDWORD(baseAddress, sizeOfImage, TypeOffset);

                    for (auto reference : references)
                    {
                        if (!IsMemoryNotExecutable((void*)reference)) continue;
                        if (*(DWORD*)reference != 0
                            && *(DWORD*)(reference + sizeof(DWORD)) != 0)
                        {
                            ObjectLocator = (reference - (sizeof(DWORD) * 3));
                        }
                        if (ObjectLocator)
                        {
                            MetaPointer = PatternScan::FindFirstReference(baseAddress, sizeOfImage, ObjectLocator);
                        }
                        if (MetaPointer)
                        {
                            TotalDumped++;

                            VFTable = MetaPointer + sizeof(uintptr_t);
                            VFTableRVA = VFTable - baseAddress;

                            TypeDescriptor* pTypeDescriptor = (TypeDescriptor*)Type;
                            char* pSymbol = &pTypeDescriptor->name;
                            std::string SymbolName = DemangleSymbol(pSymbol);
                            ApplySymbolFilters(SymbolName);

                            VFTableLogStream << std::hex << VFTable << " : ";
                            VFTableLogStream << std::hex << VFTableRVA << " : ";
                            VFTableLogStream << SymbolName << std::endl;

                            uintptr_t ClassHeirarchy = *(DWORD*)(ObjectLocator + 0x10) + baseAddress;
                            if (!IsMemoryReadable((void*)ClassHeirarchy))
                            {
                                break;
                            }
                            DWORD BaseClasses = *(DWORD*)(ClassHeirarchy + 0x8);
                            uintptr_t pClassArray = *(DWORD*)(ClassHeirarchy + 0xC) + baseAddress;
                            for (DWORD i = 0; i < BaseClasses; i++)
                            {
                                auto index = i * 4;
                                uintptr_t TDPtr = *(DWORD*)(pClassArray + index) + baseAddress;
                                TDPtr = *(DWORD*)TDPtr + baseAddress;
                                TypeDescriptor* TD = (TypeDescriptor*)TDPtr;
                                std::string CurrSymbolName = DemangleSymbol(&TD->name);
                                ApplySymbolFilters(CurrSymbolName);
                                if (i + 1 == BaseClasses)
                                {
                                    InheritanceLogStream << CurrSymbolName;
                                }
                                else
                                {
                                    InheritanceLogStream << CurrSymbolName << " -> ";
                                }
                            }
                            InheritanceLogStream << "\n";
                            break;
                        }
                    }
#else

                    auto references = PatternScan::FindReferences(baseAddress, sizeOfImage, Type);
                    for (auto reference : references)
                    {
                        if (!IsMemoryNotExecutable((void*)reference)) continue;
                        if (*(uintptr_t*)(reference) >= baseAddress
                            && *(uintptr_t*)(reference + sizeof(DWORD)) >= baseAddress)
                        {
                            ObjectLocator = (reference - (sizeof(DWORD) * 3));
                        }
                        if (ObjectLocator)
                        {
                            MetaPointer = PatternScan::FindFirstReference(baseAddress, sizeOfImage, ObjectLocator);
                        }
                        if (MetaPointer)
                        {
                            TotalDumped++;
                            VFTable = MetaPointer + 4;
                            uintptr_t VFTableRVA = VFTable - baseAddress;

                            TypeDescriptor* pTypeDescriptor = (TypeDescriptor*)Type;
                            char* pSymbol = &pTypeDescriptor->name;
                            std::string SymbolName = DemangleSymbol(pSymbol);
                            ApplySymbolFilters(SymbolName);

                            VFTableLogStream << std::hex << VFTable << " : ";
                            VFTableLogStream << std::hex << VFTableRVA << " : ";
                            VFTableLogStream << SymbolName << std::endl;

                            uintptr_t ClassHeirarchy = *(uintptr_t*)(ObjectLocator + 0x10);
                            if(!IsMemoryReadable((void*)ClassHeirarchy))
                            {
                                break;
                            }
                            size_t BaseClasses  = *(uintptr_t*)(ClassHeirarchy + 0x8);
                            uintptr_t pClassArray= *(uintptr_t*)(ClassHeirarchy + 0xC);
                            for(size_t i = 0; i < BaseClasses; i++)
                            {
                                auto index = i * 4;
                                TypeDescriptor * TD = (TypeDescriptor*)*(uintptr_t*)*(uintptr_t*)(pClassArray+index);
                                std::string CurrSymbolName = DemangleSymbol(&TD->name);
                                ApplySymbolFilters(CurrSymbolName);
                                if (i + 1 == BaseClasses)
                                {
                                    InheritanceLogStream << CurrSymbolName;
                                }
                                else
                                {
                                    InheritanceLogStream << CurrSymbolName << " -> ";
                                }
                            }
                            InheritanceLogStream << "\n";
                            break;
                        }
                    }
#endif
                }
                std::cout << "Done! Classes Dumped: " << std::dec << TotalDumped << std::endl;
                std::cout << std::endl;
            }


            VFTableLogStream <<"!<"<< moduleName << "!> END\n\n";
            InheritanceLogStream <<"!<"<< moduleName << "!> END\n\n";
            NotFinished = Module32Next(hModuleSnap, &ModuleEntry);
        } while (NotFinished);
        VFTableLogStream.close();
        InheritanceLogStream.close();
        std::cout << "VFTable Data written to \\vftable.txt" << std::endl;
        std::cout << "Inheritance Data written to \\inheritance.txt" << std::endl;

        Sleep(5000);

        fclose(stdout);
        FreeConsole();
        HMODULE self;
#ifdef _WIN64
        GetModuleHandleEx(NULL, "RTTIDumper64.dll", &self);
#else
        GetModuleHandleEx(NULL, "RTTIDumper.dll", &self);
#endif
        FreeLibraryAndExitThread(self, 0x00000000);
}

