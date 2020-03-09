#pragma once
#include <string>
#include <fstream>
#include <iostream>
#include <vector>

#include <Windows.h>
#include <DbgHelp.h>
#include <TlHelp32.h>

#include "PatternScanner.h"
#include "RTTI.h"

void __declspec(dllexport) RTTIDumper();

std::string DemangleSymbol(char* symbol);

bool isSystemModule(char* szPath);

void StrFilter(std::string& string, const std::string& substring);

void ApplySymbolFilters(std::string& Symbol);

bool IsMemoryRangeReadable(void* ptr, size_t byteCount);

bool IsMemoryReadable(void* ptr);

bool IsMemoryNotExecutable(void* ptr);

void FixupImageNoAccess(uintptr_t moduleBase);
