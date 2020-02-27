#include "pch.h"
#include "dllmain.h"
#include <DbgHelp.h>
#include <fstream>
#include <TlHelp32.h>
#pragma comment(lib,"dbghelp.lib")

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

bool IsMemoryReadable(void* ptr, size_t byteCount)
{
    //Fucking hacky shit to avoid crashes ugh
    void* tempBuffer = malloc(byteCount);
    if (tempBuffer) {
        bool readable = ReadProcessMemory(GetCurrentProcess(), ptr, tempBuffer, byteCount, nullptr);
        free(tempBuffer);
        return readable;
    }
    return false;

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
    std::ofstream LogFileStream;
    LogFileStream.open("vftable.txt");
    LogFileStream << "vftable_virtual : vftable_rva : symbol\n";

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

            if (!IsMemoryReadable((void*)(baseAddress), sizeOfImage))
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
                LogFileStream << "!<" << moduleName << ">!\n";
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

                            LogFileStream << std::hex << VFTable << " : ";
                            LogFileStream << std::hex << VFTableRVA << " : ";
                            LogFileStream << SymbolName << std::endl;
                            break;
                        }
                    }
#else

                    auto references = PatternScan::FindReferences(baseAddress, sizeOfImage, Type);
                    for (auto reference : references)
                    {
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

                            LogFileStream << std::hex << VFTable << " : ";
                            LogFileStream << std::hex << VFTableRVA << " : ";
                            LogFileStream << SymbolName << std::endl;
                            break;
                        }
                    }
#endif
                }
                std::cout << "Done! Classes Dumped: " << std::dec << TotalDumped << std::endl;
                std::cout << std::endl;
            }


            LogFileStream <<"!<"<< moduleName << "!> END\n\n";
            NotFinished = Module32Next(hModuleSnap, &ModuleEntry);
        } while (NotFinished);
        LogFileStream.close();
        std::cout << "Data written to \\vftable.txt" << std::endl;

        Sleep(5000);

        fclose(stdout);
        FreeConsole();
        HMODULE self;
        GetModuleHandleEx(NULL, "RTTIDumper.dll", &self);
        FreeLibraryAndExitThread(self, 0x00000000);
}

