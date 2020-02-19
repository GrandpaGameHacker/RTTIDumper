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
					if (*(char*)(i + j) != pattern[j])
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

	uintptr_t FindFirstString(uintptr_t startAddress, size_t length, const char* pattern, size_t patternLen)
	{
		size_t pos = 0;
		for (uintptr_t i = startAddress; i < startAddress + length; i++)
		{
			bool match = true;
			for (uintptr_t j = 0; j < patternLen; j++)
			{
				if (*(char*)(i + j) != pattern[j])
				{
					match = false;
					break;
				}
			}
			if (match) {
				return i;
			}
		}
		return NULL;
	}

	uintptr_t FindFirstReference32(uintptr_t startAddress, size_t length, uintptr_t dword)
	{
		for (uintptr_t i = startAddress; i < startAddress + length; i += sizeof(uintptr_t))
		{
			uintptr_t candidate = *(uintptr_t*)(i);
			if (candidate == dword)
			{
				return i;
			}
		}
		return NULL;
	}

	uintptr_t FindFirstReference64(uintptr_t startAddress, size_t length, DWORD dword)
	{
		for (uintptr_t i = startAddress; i < startAddress + length; i += sizeof(DWORD))
		{
			DWORD candidate = *(DWORD*)(i);
			if (candidate == dword)
			{
				return i;
			}
		}
		return NULL;
	}

	std::vector<uintptr_t> FindReferences32(uintptr_t startAddress, size_t length, uintptr_t dword)
	{
		std::vector<uintptr_t> resultsList;

		for (uintptr_t i = startAddress; i < startAddress + length; i += sizeof(uintptr_t))
		{
			uintptr_t candidate = *(uintptr_t*)(i);
			if (candidate == dword)
			{
				resultsList.push_back(i);
			}
		}
		return resultsList;
	}

	std::vector<uintptr_t> FindReferences64(uintptr_t startAddress, size_t length, DWORD dword)
	{
		std::vector<uintptr_t> resultsList;

		for (uintptr_t i = startAddress; i < startAddress + length; i += sizeof(DWORD))
		{
			uintptr_t candidate = *(uintptr_t*)(i);
			if (candidate == dword)
			{
				resultsList.push_back(i);
			}
		}
		return resultsList;
	}

}