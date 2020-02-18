#pragma once
#include <vector>
#include <iostream>
namespace PatternScan
{
	std::vector<uintptr_t> StringScan(uintptr_t startAddress, size_t length, const char* pattern, size_t patternLen) {
		{
			std::vector<uintptr_t> resultsList;
			size_t pos = 0;
			for (uintptr_t i = startAddress; i < startAddress + length; i++)
			{
				bool match = true;
				for (uintptr_t j = 0; j < patternLen; j++) {
					if (*(char*)(i+j) != pattern[j])
					{
						match = false;
						break;
					}
				}
				if (match)
				{
					resultsList.push_back(i);
				}
			}
			return resultsList;
		}

	}
	
	uintptr_t _declspec(dllexport) FindFirstReference32(uintptr_t startAddress, size_t length, uintptr_t dword)
	{
		for(uintptr_t i = startAddress; i < startAddress + length; i+=sizeof(uintptr_t))
		{
			uintptr_t candidate = *(uintptr_t*) (i);
			if (candidate == dword)
			{
				return i;
			}
		}
		return NULL;
	}
}