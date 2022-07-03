/**
* Copyright (C) 2022 Elisha Riedlinger
*
* This software is  provided 'as-is', without any express  or implied  warranty. In no event will the
* authors be held liable for any damages arising from the use of this software.
* Permission  is granted  to anyone  to use  this software  for  any  purpose,  including  commercial
* applications, and to alter it and redistribute it freely, subject to the following restrictions:
*
*   1. The origin of this software must not be misrepresented; you must not claim that you  wrote the
*      original  software. If you use this  software  in a product, an  acknowledgment in the product
*      documentation would be appreciated but is not required.
*   2. Altered source versions must  be plainly  marked as such, and  must not be  misrepresented  as
*      being the original software.
*   3. This notice may not be removed or altered from any source distribution.
*
* Created from source code found in DxWnd v2.03.99
* https://sourceforge.net/projects/dxwnd/
*
* Code in GetProcAddress function taken from source code found on rohitab.com
* http://www.rohitab.com/discuss/topic/40594-parsing-pe-export-table/
*/

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <stdio.h>
#include <psapi.h>
#include "Hook.h"

// Hook API using host patch or IAT patch
void *Hook::HookAPI(HMODULE module, const char *dll, void *apiproc, const char *apiname, void *hookproc)
{
#ifdef _DEBUG
	spd::log()->info(__FUNCTION__ ": module = {0} dll = {1} apiproc = {2} apiname = {3} hookproc = {4}", static_cast<void*>(module), dll, apiproc, hookproc);
#endif

	// Check if API name is blank
	if (!apiname)
	{
		spd::log()->info(__FUNCTION__ " Error: NULL api name");
		return nullptr;
	}

	// Check API address
	if (!apiproc)
	{
		spd::log()->info(__FUNCTION__ " Error: Failed to find '{}' api", apiname);
		return nullptr;
	}

	// Check hook address
	if (!hookproc)
	{
		spd::log()->info(__FUNCTION__ " Error: Invalid hook address for '{}'", apiname);
		return nullptr;
	}

	// Try HotPatch first
	void *orig;
	orig = HotPatch(apiproc, apiname, hookproc);
	if ((DWORD)orig > 1)
	{
		return orig;
	}

	// Check if dll name is blank
	if (!dll)
	{
		spd::log()->info(__FUNCTION__ " Error: NULL dll name");
		return nullptr;
	}

	// Check module addresses
	if (!module)
	{
		spd::log()->info(__FUNCTION__ " Error: NULL api module address for '{}'", dll);
		return nullptr;
	}

	// Try IATPatch next
	orig = IATPatch(module, 0, dll, apiproc, apiname, hookproc);
	if ((DWORD)orig > 1)
	{
		return orig;
	}

	// Return default address
	return nullptr;
}

// Unhook API
void Hook::UnhookAPI(HMODULE module, const char *dll, void *apiproc, const char *apiname, void *hookproc)
{
#ifdef _DEBUG
	spd::log()->info(__FUNCTION__ ": module = {0} dll = {1} apiproc = {2} apiname = {3} hookproc = {4}", static_cast<void*>(module), dll, apiproc, hookproc);
#endif

	// Check if API name is blank
	if (!apiname)
	{
		spd::log()->info(__FUNCTION__ " Error: NULL api name");
		return;
	}

	// Check API address
	if (!apiproc)
	{
		spd::log()->info(__FUNCTION__ " Error: Failed to find '{}' api", apiname);
		return;
	}

	// Check hook address
	if (!hookproc)
	{
		spd::log()->info(__FUNCTION__ " Error: Invalid hook address for '{}'", apiname);
		return;
	}

	// Unhooking HotPatch
	UnhookHotPatch(apiproc, apiname, hookproc);

	// Check if dll name is blank
	if (!dll)
	{
		spd::log()->info(__FUNCTION__ " Error: NULL dll name");
		return;
	}

	// Check module addresses
	if (!module)
	{
		spd::log()->info(__FUNCTION__ " Error: NULL api module address for '{}'", dll);
		return;
	}

	// Unhook IATPatch
	UnhookIATPatch(module, 0, dll, apiproc, apiname, hookproc);
}

// Get pointer for function name from binary file
FARPROC Hook::GetProcAddress(HMODULE hModule, LPCSTR FunctionName)
{
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_EXPORT_DIRECTORY pIED;
	PDWORD Address, Name;
	PWORD Ordinal;

	if (!FunctionName || !hModule)
	{
		spd::log()->info(__FUNCTION__ ": NULL module or function name.");
		return nullptr;
	}

#ifdef _DEBUG
	spd::log()->info(__FUNCTION__ ": Searching for {}.", FunctionName);
#endif

	FARPROC functAddr = ::GetProcAddress(hModule, FunctionName);

	__try {
		pIDH = (PIMAGE_DOS_HEADER)hModule;

		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
		{
			spd::log()->info(__FUNCTION__ " Error: {} is not IMAGE_DOS_SIGNATURE.", FunctionName);
			return functAddr;
		}

		pINH = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pIDH->e_lfanew);

		if (pINH->Signature != IMAGE_NT_SIGNATURE)
		{
			spd::log()->info(__FUNCTION__ " Error: {} is not IMAGE_NT_SIGNATURE.", FunctionName);
			return functAddr;
		}

		if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
		{
			spd::log()->info(__FUNCTION__ " Error: Could not get VirtualAddress in {}.", FunctionName);
			return functAddr;
		}

		pIED = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		Address = (PDWORD)((LPBYTE)hModule + pIED->AddressOfFunctions);
		Name = (PDWORD)((LPBYTE)hModule + pIED->AddressOfNames);
		Ordinal = (PWORD)((LPBYTE)hModule + pIED->AddressOfNameOrdinals);

		for (DWORD i = 0; i < pIED->AddressOfFunctions; i++)
		{
			if (!strcmp(FunctionName, (char*)hModule + Name[i]))
			{
				return (FARPROC)((DWORD)Address[Ordinal[i]] + (DWORD)hModule);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DWORD ErrorCode = GetExceptionCode();
		spd::log()->info(__FUNCTION__ " Error: EXCEPTION module={0} Failed to get address. Code={1}", FunctionName, ErrorCode);
	}

	// Exit function
	spd::log()->info(__FUNCTION__ " Error: Could not find {}.", FunctionName);
	return functAddr;
}

// Unhook all APIs
bool Hook::UnhookAll()
{
	return (UnHotPatchAll() && UnIATPatchAll());
}

// Get pointer for function name from binary file
HMODULE Hook::GetModuleHandle(char* ProcName)
{
	DWORD processID = GetCurrentProcessId();
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;

	if (!ProcName)
	{
		spd::log()->info(__FUNCTION__ " Error: NULL process name.");
		return nullptr;
	}

#ifdef _DEBUG
	spd::log()->info(__FUNCTION__ ": Searching for \"{}\".", ProcName);
#endif

	// Get a handle to the process.
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
	if (!hProcess)
	{
		spd::log()->info(__FUNCTION__ " Error: Could not open process.");
		return nullptr;
	}

	// Get a list of all the modules in this process.
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (UINT i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			char szModName[MAX_PATH];

			// Get the full path to the module's file.
			if (GetModuleFileNameExA(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(char)))
			{
				// Check the module name.
				if (!_stricmp(ProcName, szModName))
				{
					// Release the handle to the process.
					CloseHandle(hProcess);

					// Return module handle
					return hMods[i];
				}
			}
		}
	}

	// Release the handle to the process.
	CloseHandle(hProcess);

	// Exit function
	spd::log()->info(__FUNCTION__ " Error: Could not file module {}.", ProcName);
	return nullptr;
}
