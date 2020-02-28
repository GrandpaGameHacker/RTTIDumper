#pragma once
#include <vector>
#include <iostream>

/*
Implements memory scanning
These functions operate on Memory regions
Without checking for potential access violation
*/

namespace PatternScan
{
	std::vector<uintptr_t> StringScan(uintptr_t startAddress, size_t length, const char* pattern, size_t patternLen) {
		{
			std::vector<uintptr_t> resultsList;
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

	std::vector<uintptr_t> FindReferences(uintptr_t startAddress, size_t length, uintptr_t scanValue)
	{
		std::vector<uintptr_t> resultsList;

		for (uintptr_t i = startAddress; i < startAddress + length; i += sizeof(uintptr_t))
		{
			uintptr_t candidate = *(uintptr_t*)(i);
			if (candidate == scanValue)
			{
				resultsList.push_back(i);
			}
		}
		return resultsList;
	}

	std::vector<uintptr_t> FindReferencesDWORD(uintptr_t startAddress, size_t length, DWORD scanValue)
	{
		std::vector<uintptr_t> resultsList;

		for (uintptr_t i = startAddress; i < startAddress + length; i += sizeof(DWORD))
		{
			DWORD candidate = *(DWORD*)(i);
			if (candidate == scanValue)
			{
				resultsList.push_back(i);
			}
		}
		return resultsList;
	}


	uintptr_t FindFirstReference(uintptr_t startAddress, size_t length, uintptr_t scanValue)
	{
		for (uintptr_t i = startAddress; i < startAddress + length; i += sizeof(uintptr_t))
		{
			uintptr_t candidate = *(uintptr_t*)(i);
			if (candidate == scanValue)
			{
				return i;
			}
		}
		return NULL;
	}

	uintptr_t FindFirstReferenceDWORD(uintptr_t startAddress, size_t length, DWORD scanValue)
	{
		for (uintptr_t i = startAddress; i < startAddress + length; i += sizeof(DWORD))
		{
			DWORD candidate = *(DWORD*)(i);
			if (candidate == scanValue)
			{
				return i;
			}
		}
		return NULL;
	}
}