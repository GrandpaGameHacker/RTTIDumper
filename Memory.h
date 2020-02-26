#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
namespace Memory {
	void GetModuleInfo(const char* ProcessName, const char* ModuleName, MODULEINFO* ModuleInfo) {
		HMODULE Module {0};
		GetModuleHandleEx(NULL, ProcessName, &Module);
		GetModuleInformation(GetCurrentProcess(), Module, ModuleInfo, sizeof(MODULEINFO));
	}
}