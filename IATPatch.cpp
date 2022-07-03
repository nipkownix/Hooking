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
*/

// return:
// 0 = patch failed
// 1 = already patched
// addr = address of the original function

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <vector>
#include "Hook.h"

namespace Hook
{
	struct IATPATCH
	{
		HMODULE module = nullptr;
		DWORD ordinal = 0;
		std::string dll;
		void *apiproc = nullptr;
		std::string apiname;
		void *hookproc = nullptr;
	};

	std::vector<IATPATCH> IATPatchProcs;

	void StoreIATRecord(HMODULE module, DWORD ordinal, const char *dll, void *apiproc, const char *apiname, void *hookproc)
	{
		IATPATCH tmpMemory;
		tmpMemory.module = module;
		tmpMemory.ordinal = ordinal;
		tmpMemory.dll = std::string(dll);
		tmpMemory.apiproc = apiproc;
		tmpMemory.hookproc = hookproc;
		tmpMemory.apiname = std::string(apiname);
		IATPatchProcs.push_back(tmpMemory);
	}
}

// Hook API using IAT patch
void *Hook::IATPatch(HMODULE module, DWORD ordinal, const char *dll, void *apiproc, const char *apiname, void *hookproc)
{
	PIMAGE_NT_HEADERS pnth;
	PIMAGE_IMPORT_DESCRIPTOR pidesc;
	DWORD base, rva;
	PSTR impmodule;
	PIMAGE_THUNK_DATA ptaddr;
	PIMAGE_THUNK_DATA ptname;
	PIMAGE_IMPORT_BY_NAME piname;
	DWORD oldprotect;
	void *org;

	// Check if dll name is blank
	if (!dll)
	{
		spd::log()->info(__FUNCTION__ " Error: NULL dll name");
		return nullptr;
	}

	// Check if API name is blank
	if (!apiname)
	{
		spd::log()->info(__FUNCTION__ " Error: NULL api name");
		return nullptr;
	}

	// Check module addresses
	if (!module)
	{
		spd::log()->info(__FUNCTION__ " Error: NULL api module address for '{}'", apiname);
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

#ifdef _DEBUG
	spd::log()->info(__FUNCTION__ ": module={0} ordinal={1} name={2} dll={3}", static_cast<void*>(module), ordinal, *apiname, *dll);
#endif

	base = (DWORD)module;
	org = 0; // by default, ret = 0 => API not found

	__try
	{
		pnth = PIMAGE_NT_HEADERS(PBYTE(base) + PIMAGE_DOS_HEADER(base)->e_lfanew);
		if (!pnth)
		{
			spd::log()->info(__FUNCTION__ ": ERROR no PNTH at {}", __LINE__);
			return nullptr;
		}
		rva = pnth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		if (!rva)
		{
			spd::log()->info(__FUNCTION__ ": ERROR no RVA at {}", __LINE__);
			return nullptr;
		}
		pidesc = (PIMAGE_IMPORT_DESCRIPTOR)(base + rva);

		while (pidesc->FirstThunk)
		{
			impmodule = (PSTR)(base + pidesc->Name);
#ifdef _DEBUG
			//spd::log()->info(__FUNCTION__ ": analyze impmodule={}", impmodule);
#endif
			char *fname = impmodule;
			for (; *fname; fname++); for (; !*fname; fname++);

			if (!lstrcmpiA(dll, impmodule))
			{
#ifdef _DEBUG
				spd::log()->info(__FUNCTION__ ": dll={0} found at {1}", dll, impmodule);				
#endif

				ptaddr = (PIMAGE_THUNK_DATA)(base + (DWORD)pidesc->FirstThunk);
				ptname = (pidesc->OriginalFirstThunk) ? (PIMAGE_THUNK_DATA)(base + (DWORD)pidesc->OriginalFirstThunk) : nullptr;

				while (ptaddr->u1.Function)
				{
#ifdef _DEBUG
					//spd::log()->info(__FUNCTION__ ": address={0} ptname={1}", ptaddr->u1.AddressOfData, ptname);
#endif

					if (ptname)
					{
						// examining by function name
						if (!IMAGE_SNAP_BY_ORDINAL(ptname->u1.Ordinal))
						{
							piname = (PIMAGE_IMPORT_BY_NAME)(base + (DWORD)ptname->u1.AddressOfData);
#ifdef _DEBUG
							spd::log()->info(__FUNCTION__ ": BYNAME ordinal={0} address={1} name={2} hint={3}", ptaddr->u1.Ordinal, ptaddr->u1.AddressOfData, (char *)piname->Name, piname->Hint);							
#endif
							if (!lstrcmpiA(apiname, (char *)piname->Name))
							{
								break;
							}
						}
						else
						{
#ifdef _DEBUG
							//spd::log()->info(__FUNCTION__ ": BYORD target={0} ord={1}", ordinal, IMAGE_ORDINAL32(ptname->u1.Ordinal));
#endif
							// skip unknow ordinal 0
							if (ordinal && (IMAGE_ORDINAL32(ptname->u1.Ordinal) == ordinal))
							{
#ifdef _DEBUG
								spd::log()->info(__FUNCTION__ ": BYORD ordinal={0} addr={1}", ptname->u1.Ordinal, ptaddr->u1.Function);
								//spd::log()->info(__FUNCTION__ ": BYORD GetProcAddress={0}", GetProcAddress(GetModuleHandle(dll), MAKEINTRESOURCE(IMAGE_ORDINAL32(ptname->u1.Ordinal))));									
#endif
								break;
							}
						}

					}
					else
					{
#ifdef _DEBUG
						//spd::log()->info(__FUNCTION__ ": fname={}", fname);
						//LogText(buffer);
#endif
						if (!lstrcmpiA(apiname, fname))
						{
#ifdef _DEBUG
							spd::log()->info(__FUNCTION__ ": BYSCAN ordinal={0} address={1} name={2}", ptaddr->u1.Ordinal, ptaddr->u1.AddressOfData, fname);							
#endif
							break;
						}
						for (; *fname; fname++); for (; !*fname; fname++);
					}

					if (apiproc)
					{
						// examining by function addr
						if (ptaddr->u1.Function == (DWORD)apiproc)
						{
							break;
						}
					}
					ptaddr++;
					if (ptname) ptname++;
				}

				if (ptaddr->u1.Function)
				{
					org = (void *)ptaddr->u1.Function;
					if (org == hookproc) return (void *)1; // already hooked

					if (!VirtualProtect(&ptaddr->u1.Function, 4, PAGE_EXECUTE_READWRITE, &oldprotect))
					{
#ifdef _DEBUG
						spd::log()->info(__FUNCTION__ ": VirtualProtect error {0} at {1}", GetLastError(), __LINE__);						
#endif
						return nullptr;
					}
					ptaddr->u1.Function = (DWORD)hookproc;
					if (!VirtualProtect(&ptaddr->u1.Function, 4, oldprotect, &oldprotect))
					{
#ifdef _DEBUG
						spd::log()->info(__FUNCTION__ ": VirtualProtect error {} at {}", GetLastError(), __LINE__);						
#endif
						return nullptr;
					}
					if (!FlushInstructionCache(GetCurrentProcess(), &ptaddr->u1.Function, 4))
					{
#ifdef _DEBUG
						spd::log()->info(__FUNCTION__ ": FlushInstructionCache error {} at {}", GetLastError(), __LINE__);						
#endif
						return nullptr;
					}
#ifdef _DEBUG
					spd::log()->info(__FUNCTION__ " hook={} address={}->{}", apiname, org, hookproc);					
#endif
					// Record hook
					StoreIATRecord(module, ordinal, dll, apiproc, apiname, hookproc);

					// Return old address
					return org;
				}
			}
			pidesc++;
		}
		if (!pidesc->FirstThunk)
		{
#ifdef _DEBUG
			spd::log()->info(__FUNCTION__ ": PE unreferenced function {}:{}", dll, apiname);			
#endif
			return nullptr;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		spd::log()->info(__FUNCTION__ "Ex: EXCEPTION hook={}:{} Hook Failed.", dll, apiname);
	}
	return org;
}

// Restore all addresses hooked
bool Hook::UnIATPatchAll()
{
	bool flag = true;
	while (IATPatchProcs.size() != 0)
	{
		if (!UnhookIATPatch(IATPatchProcs.back().module, IATPatchProcs.back().ordinal, IATPatchProcs.back().dll.c_str(), IATPatchProcs.back().apiproc, IATPatchProcs.back().apiname.c_str(), IATPatchProcs.back().hookproc))
		{
			// Failed to restore address
			flag = false;
			spd::log()->info(__FUNCTION__ ": failed to restore address. procaddr: {}", IATPatchProcs.back().apiproc);
		}
		IATPatchProcs.pop_back();
	}
	IATPatchProcs.clear();
	return flag;
}

// Unhook IAT patched API
bool Hook::UnhookIATPatch(HMODULE module, DWORD ordinal, const char *dll, void *apiproc, const char *apiname, void *hookproc)
{
	PIMAGE_NT_HEADERS pnth;
	PIMAGE_IMPORT_DESCRIPTOR pidesc;
	DWORD base, rva;
	PSTR impmodule;
	PIMAGE_THUNK_DATA ptaddr;
	PIMAGE_THUNK_DATA ptname;
	PIMAGE_IMPORT_BY_NAME piname;
	DWORD oldprotect;
	void *org;

#ifdef _DEBUG
	spd::log()->info(__FUNCTION__ ": module={} ordinal={} name={} dll={}", static_cast<void*>(module), ordinal, apiname, dll);
#endif

	base = (DWORD)module;
	org = 0;

	__try
	{
		pnth = PIMAGE_NT_HEADERS(PBYTE(base) + PIMAGE_DOS_HEADER(base)->e_lfanew);
		if (!pnth)
		{
			spd::log()->info(__FUNCTION__ ": ERROR no PNTH at {}", __LINE__);
			return false;
		}
		rva = pnth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		if (!rva)
		{
			spd::log()->info(__FUNCTION__ ": ERROR no RVA at {}", __LINE__);
			return false;
		}
		pidesc = (PIMAGE_IMPORT_DESCRIPTOR)(base + rva);

		while (pidesc->FirstThunk)
		{
			impmodule = (PSTR)(base + pidesc->Name);
#ifdef _DEBUG
			//spd::log()->info(__FUNCTION__ ": analyze impmodule={}", impmodule);
#endif
			char *fname = impmodule;
			for (; *fname; fname++); for (; !*fname; fname++);

			if (!lstrcmpiA(dll, impmodule))
			{
#ifdef _DEBUG
				spd::log()->info(__FUNCTION__ ": dll={} found at {}", dll, impmodule);				
#endif

				ptaddr = (PIMAGE_THUNK_DATA)(base + (DWORD)pidesc->FirstThunk);
				ptname = (pidesc->OriginalFirstThunk) ? (PIMAGE_THUNK_DATA)(base + (DWORD)pidesc->OriginalFirstThunk) : nullptr;

				while (ptaddr->u1.Function)
				{
#ifdef _DEBUG
					//spd::log()->info(__FUNCTION__ ": address={} ptname={}", ptaddr->u1.AddressOfData, ptname);
#endif

					if (ptname)
					{
						// examining by function name
						if (!IMAGE_SNAP_BY_ORDINAL(ptname->u1.Ordinal))
						{
							piname = (PIMAGE_IMPORT_BY_NAME)(base + (DWORD)ptname->u1.AddressOfData);
#ifdef _DEBUG
							spd::log()->info(__FUNCTION__ ": BYNAME ordinal={} address={} name={} hint={}", ptaddr->u1.Ordinal, ptaddr->u1.AddressOfData, (char *)piname->Name, piname->Hint);							
#endif
							if (!lstrcmpiA(apiname, (char *)piname->Name))
							{
								break;
							}
						}
						else
						{
#ifdef _DEBUG
							//spd::log()->info(__FUNCTION__ ": BYORD target={} ord={}", ordinal, IMAGE_ORDINAL32(ptname->u1.Ordinal));
#endif
							// skip unknown ordinal 0
							if (ordinal && (IMAGE_ORDINAL32(ptname->u1.Ordinal) == ordinal))
							{
#ifdef _DEBUG
								spd::log()->info(__FUNCTION__ ": BYORD ordinal={} addr={}", ptname->u1.Ordinal, ptaddr->u1.Function);
								//spd::log()->info(__FUNCTION__ ": BYORD GetProcAddress={}", GetProcAddress(GetModuleHandle(dll), MAKEINTRESOURCE(IMAGE_ORDINAL32(ptname->u1.Ordinal))));									
#endif
								break;
							}
						}

					}
					else
					{
#ifdef _DEBUG
						//spd::log()->info(__FUNCTION__ ": fname={}", fname);
#endif
						if (!lstrcmpiA(apiname, fname))
						{
#ifdef _DEBUG
							spd::log()->info(__FUNCTION__ ": BYSCAN ordinal={} address={} name={}", ptaddr->u1.Ordinal, ptaddr->u1.AddressOfData, fname);							
#endif
							break;
						}
						for (; *fname; fname++); for (; !*fname; fname++);
					}

					if (apiproc)
					{
						// examining by function addr
						if (ptaddr->u1.Function == (DWORD)apiproc)
						{
							break;
						}
					}
					ptaddr++;
					if (ptname) ptname++;
				}

				if (ptaddr->u1.Function)
				{
					org = (void *)ptaddr->u1.Function;

					// Check if API is patched
					if (org == hookproc)
					{

						if (!VirtualProtect(&ptaddr->u1.Function, 4, PAGE_EXECUTE_READWRITE, &oldprotect))
						{
#ifdef _DEBUG
							spd::log()->info(__FUNCTION__ ": VirtualProtect error {} at {}", GetLastError(), __LINE__);							
#endif
							return false;
						}
						ptaddr->u1.Function = (DWORD)apiproc;
						if (!VirtualProtect(&ptaddr->u1.Function, 4, oldprotect, &oldprotect))
						{
#ifdef _DEBUG
							spd::log()->info(__FUNCTION__ ": VirtualProtect error {} at {}", GetLastError(), __LINE__);							
#endif
							return false;
						}
						if (!FlushInstructionCache(GetCurrentProcess(), &ptaddr->u1.Function, 4))
						{
#ifdef _DEBUG
							spd::log()->info(__FUNCTION__ ": FlushInstructionCache error {} at {}", GetLastError(), __LINE__);							
#endif
							return false;
						}
#ifdef _DEBUG
						spd::log()->info(__FUNCTION__ " hook={} address={}->{}", apiname, org, hookproc);						
#endif

						return true;
					}
					return false;
				}
			}
			pidesc++;
		}
		if (!pidesc->FirstThunk)
		{
#ifdef _DEBUG
			spd::log()->info(__FUNCTION__ ": PE unreferenced function {}:{}", dll, apiname);			
#endif
			return false;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		spd::log()->info(__FUNCTION__ "Ex: EXCEPTION hook={}:{} Hook Failed.", dll, apiname);
	}
	return false;
}
