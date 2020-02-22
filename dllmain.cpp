#include "pch.h"
#include "dllmain.h"
#include <DbgHelp.h>
#include <fstream>
#pragma comment(lib,"dbghelp.lib")

//Name of process to be injected into
const char * ProgramName = "DarkSoulsII.exe";

//Name of loaded module inside process to
//Extract VFTables and RTTI data from
const char * ModuleName = "DarkSoulsII.exe";

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
    //Here we process a symbol as a virtual function table
    //and make some allowances for edge cases
    //There are still a few edge cases that fail.
    std::string vftable_start = "??_7";
    std::string vftable_end = "6B@";
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
    std::string symbol_processed = std::string(pSymbol);
    symbol_processed.insert(0, vftable_start);
    symbol_processed.insert(symbol_processed.size(), vftable_end);
    if (!((UnDecorateSymbolName(symbol_processed.c_str(), buff, MAX_DEMANGLE_BUFFER_SIZE, 0)) != 0))
    {
        printf("error %x\n", GetLastError());
        return std::string(symbol); //Failsafe
    }
    return std::string(buff);
}


void RTTIDumper()
{
    FILE* nullfile = nullptr;
    AllocConsole();
    freopen_s(&nullfile, "CONOUT$", "w", stdout);
    SetConsoleTitle("RTTI Class Dumper");

    MODULEINFO TargetModule;
    Memory::GetModuleInfo(ProgramName, ModuleName, &TargetModule);
    uintptr_t baseAddress = (uintptr_t)TargetModule.lpBaseOfDll, sizeOfImage = TargetModule.SizeOfImage;
    
    std::cout << "Injected into process: " << ProgramName << std::endl;
    std::cout << "Begin dumping: " << ModuleName << std::endl;
    
    //This string is contained in an important structure
    //We use information from this to scan for all
    //TypeDescriptor structures in the module
    const char* sTypeInfo = ".?AVtype_info@@";
    const size_t length = strlen(sTypeInfo);
    TypeDescriptor* type_info =
        (TypeDescriptor*)(PatternScan::FindFirstString(
         baseAddress,
         sizeOfImage,
         sTypeInfo,
         length) - (sizeof(uintptr_t) * 2));

    if (type_info == NULL) return; //Try to prevent crash

    std::cout << "Found RTTI0 at: " << std::hex << type_info << std::endl;
    std::cout << "Scanning for TypeDescriptor structs..." << std::endl;

    std::ofstream LogFileStream;
    LogFileStream.open("vftable.txt", std::ios::app);
    LogFileStream << "vftable_virtual : vftable_rva : symbol\n";

    std::cout << "Finding VFTables via RTTI" << std::endl;

    auto TypesFound = PatternScan::FindReferences(baseAddress, sizeOfImage, type_info->pVFTable);
    size_t TotalDumped = 0;
    
    for (auto Type : TypesFound)
    {
#ifdef _WIN64
        uintptr_t ObjectLocator = NULL,
            MetaPointer = NULL,
            VFTable = NULL,
            VFTableRVA = NULL;

        DWORD TypeOffset = (DWORD)(Type - baseAddress);
        auto references = PatternScan::FindReferencesDWORD(baseAddress, sizeOfImage, TypeOffset);
        
        for (auto reference : references) 
        {
            if (*(DWORD*)reference != 0
                && *(DWORD*)(reference + sizeof(DWORD)) != 0)
            {
                ObjectLocator = (reference - (sizeof(DWORD)*3));
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
        uintptr_t ObjectLocator = NULL,
            MetaPointer = NULL,
            VFTable = NULL,
            VFTableRVA = NULL;

        auto references = PatternScan::FindReferences(baseAddress, sizeOfImage, Type);
        for (auto reference : references)
        {
            if (*(uintptr_t*)(reference) >= baseAddress
                && *(uintptr_t*)(reference + sizeof(DWORD)) >= baseAddress)
            {
                ObjectLocator = (reference - (sizeof(DWORD)*3));
            }
            if (ObjectLocator)
            {
                MetaPointer = PatternScan::FindFirstReference(baseAddress, sizeOfImage, ObjectLocator);
            }
            if (MetaPointer)
            {
                TotalDumped++;

                VFTable = MetaPointer + 4;
                uintptr_t VFTableRVA= VFTable - baseAddress;
                
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
    LogFileStream.close();

    std::cout << "Done! Classes Dumped: " << std::dec << TotalDumped << std::endl;
    std::cout << "Data written to \\vftable.txt"<< std::endl;

    Sleep(5000);

    fclose(stdout);
    FreeConsole();
    HMODULE self;
    GetModuleHandleEx(NULL, "RTTIDumper.dll", &self);
    FreeLibraryAndExitThread(self, 0x00000000);
}
