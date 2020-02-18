// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "Memory.h"
#include "PatternScanner.h"
#include "dllmain.h"
#include <DbgHelp.h>
#include <fstream>
#pragma comment(lib,"dbghelp.lib")

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
    if ((UnDecorateSymbolName(pSymbol, buff, MAXLEN, UNDNAME_NAME_ONLY)) != 0)
    {
        char* pBuff = buff + 2;

        printf("%s\n", pBuff);
    }
    else
    {
        printf("error %x\n", GetLastError());
    }
    return std::string(buff);
}


void RTTIDumper()
{
    //Create Debug Console Window
    FILE* nullfile = nullptr;
    AllocConsole();
    freopen_s(&nullfile, "CONOUT$", "w", stdout);
    SetConsoleTitle("RTTI Class DumperTest");

    MODULEINFO GameProc;
    Memory::GetModuleInfo("DarkSoulsII.exe",&GameProc);
    uintptr_t address = (uintptr_t)GameProc.lpBaseOfDll, length = GameProc.SizeOfImage;
    const char* str = ".?AV";
    auto symbols = PatternScan::StringScan(address, length, str, 3);
    std::ofstream logstream;
    logstream.open("vftables.txt", std::ios::app);
    logstream << "vftable : symbol\n";
    for (auto symbol : symbols)
    {
        
#if _WIN64
       

#else
        
        auto _TypeDescriptor = symbol - 0x8;
        auto _pTypeDescriptor = PatternScan::FindFirstRef32(address, length, _TypeDescriptor);
        if (*(uintptr_t*)(_pTypeDescriptor + 0xC) == 0xFFFFFFFF)
        {
            auto scanFrom = _pTypeDescriptor + 4;
            auto newLength = length - (scanFrom - address);
            _pTypeDescriptor = PatternScan::FindFirstRef32(scanFrom, newLength, _TypeDescriptor);
        }
        auto _RTTICompleteObjectLocator = _pTypeDescriptor - 0xC;
        auto _MetaPointer = PatternScan::FindFirstRef32(address, length, _RTTICompleteObjectLocator);
        auto _vftable = _MetaPointer + sizeof(uintptr_t);
        auto demangled_symbol = DemangleSymbol((char*)symbol);
        logstream << std::hex << _vftable;
        logstream << " : " << demangled_symbol << std::endl;
        logstream.flush();
#endif
    }
    logstream.close();
}

