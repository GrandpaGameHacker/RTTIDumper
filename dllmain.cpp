// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "dllmain.h"
#include <DbgHelp.h>
#include <fstream>
#pragma comment(lib,"dbghelp.lib")

const char * ProgramName = "Reckoning.exe";
#define MAXLEN 0x1000

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
    char buff[MAXLEN] = { 0 };
    memset(buff, 0, MAXLEN);
    char* pSymbol = symbol;
    if (*(char*)symbol == '.') pSymbol = symbol + 1;
    else if (*(char*)symbol == '?') pSymbol = symbol;
    else
    {
        puts("invalid msvc mangled name\n");
    }
    if (!((UnDecorateSymbolName(pSymbol, buff, MAXLEN, UNDNAME_NAME_ONLY)) != 0))
    {
        printf("error %x\n", GetLastError());
        return std::string();
    }
    return std::string(buff);
}


void RTTIDumper()
{
    //Create Debug Console Window
    FILE* nullfile = nullptr;
    AllocConsole();
    freopen_s(&nullfile, "CONOUT$", "w", stdout);
    SetConsoleTitle("RTTI Class Dumper");

    MODULEINFO GameProc;
    Memory::GetModuleInfo(ProgramName, &GameProc);
    uintptr_t baseAddress = (uintptr_t)GameProc.lpBaseOfDll, sizeOfImage = GameProc.SizeOfImage;
    std::cout << "Beginning dumping: " << ProgramName << std::endl;
    const char* type_info_pattern = ".?AVtype_info@@";
    const size_t typestrLen = strlen(type_info_pattern);
    TypeDescriptor* type_info =
        (TypeDescriptor*)
        (PatternScan::FindFirstString
        (baseAddress,
            sizeOfImage,
            type_info_pattern,
            typestrLen)
            - (sizeof(uintptr_t) * 2));

    if (type_info == NULL) return;

    std::cout << "Found RTTI0 at: " << std::hex << type_info << std::endl;
    std::cout << "Scanning for type information..." << std::endl;
    std::ofstream logstream;
    logstream.open("vftables.txt", std::ios::app);
    logstream << "vftable : symbol\n";
#if _WIN32
    auto class_types = PatternScan::FindReferences32(baseAddress, sizeOfImage, type_info->pVFTable);
    size_t classesfound = 0;
    std::cout << "Finding VFTables via RTTI" << std::endl;
    for (auto class_type : class_types)
    {
        auto references = PatternScan::FindReferences32(baseAddress, sizeOfImage, class_type);
        uintptr_t Meta = 0, pMeta = 0, vftable = 0;

        for (auto reference : references) {
            if (*(uintptr_t*)(reference) >= baseAddress
                && *(uintptr_t*)(reference + 4) >= baseAddress)
            {
                //RTTICompleteObjectLocator
                Meta = (reference - 0xC);
            }
            if (Meta)
            {
                pMeta = PatternScan::FindFirstReference32(baseAddress, sizeOfImage, Meta);
            }
            if (pMeta)
            {
                classesfound++;
                vftable = pMeta + 4;
                TypeDescriptor* class_typeinfo = (TypeDescriptor*)class_type;
                char* nameptr = &class_typeinfo->name;
                std::string name = DemangleSymbol(nameptr);
                logstream << std::hex << vftable << " : ";
                logstream << name << std::endl;
                break;
            }

        }
    }
#else

#endif
    std::cout << "Done! Found: " << std::dec << classesfound << " classes" << std::endl;
}