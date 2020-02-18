// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "Memory.h"
#include "PatternScanner.h"
#include "dllmain.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)RTTIDumper, NULL, NULL, NULL);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
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
    for (auto symbol : symbols)
    {
#if _WIN64
        


#else
        
        auto _TypeDescriptor = symbol - 0x8;
        auto _pTypeDescriptor = PatternScan::FindFirstReference32(address, length, _TypeDescriptor);
        auto _RTTICompleteObjectLocator = _pTypeDescriptor - 0xC;
        auto _MetaPointer = PatternScan::FindFirstReference32(address, length, _RTTICompleteObjectLocator);
        auto _vftable = _MetaPointer + sizeof(uintptr_t);
        std::cout << std::hex << _vftable;
        std::cout << " : " << std::string((char*)symbol) << std::endl;
#endif
    }
}

