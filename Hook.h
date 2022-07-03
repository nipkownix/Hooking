#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <log.h>
#include "..\dllmain\Utils.h"

namespace Hook
{
	FARPROC GetProcAddress(HMODULE, LPCSTR);
	HMODULE GetModuleHandle(char*);

	// Managed hooks
	void *HookAPI(HMODULE, const char *, void *, const char *, void *);
	void UnhookAPI(HMODULE, const char *, void *, const char *, void *);
	bool UnhookAll();

	// HotPatch hooks
	void *HotPatch(void*, const char*, void*, bool = false);
	bool UnhookHotPatch(void *, const char *, void *);
	bool UnHotPatchAll();

	// IATPatch hooks
	void *IATPatch(HMODULE, DWORD, const char*, void*, const char*, void*);
	bool UnhookIATPatch(HMODULE, DWORD, const char *, void *, const char *, void *);
	bool UnIATPatchAll();
}
