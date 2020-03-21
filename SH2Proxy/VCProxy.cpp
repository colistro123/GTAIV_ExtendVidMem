// proxydll.cpp
#include "stdafx.h"
#include "VCProxy.h"
#include "VCPatcher.h"
#include "HookFunction.h"
#include "Hooking.h"

// global variables
HINSTANCE           gl_hOriginalDll;
HINSTANCE           gl_hThisInstance;
VCPatcher			gl_patcher;
#pragma data_seg ()

BOOL APIENTRY DllMain(HANDLE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	// to avoid compiler lvl4 warnings 
	LPVOID lpDummy = lpReserved;
	lpDummy = NULL;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH: InitInstance(hModule); break;
	case DLL_PROCESS_DETACH: {
		//Why are we exiting
		ExitInstance(); 
		break;
	}

	case DLL_THREAD_ATTACH:  break;
	case DLL_THREAD_DETACH:  break;
	}
	return TRUE;
}

bool bDelay;
DWORD WINAPI Init(LPVOID)
{
	//location = hook::pattern("8b ? ? ? ? ? 83 ? 14 33 ? 85 ? 74 ? ff").count(1).get(0).get<char>(0);
	gl_patcher.PreHooks();

#if 1
	auto pattern = hook::pattern("8b ? ? ? ? ? 83 ? 14 33 ? 85 ? 74 ? ff");
	if (!(pattern.size() > 0) && !bDelay)
	{
		bDelay = true;
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&Init, NULL, 0, NULL);
		return 0;
	}

	if (bDelay)
	{
		while (!(pattern.size() > 0))
			pattern = hook::pattern("8b ? ? ? ? ? 83 ? 14 33 ? 85 ? 74 ? ff");
	}

	if (bDelay)
	{
#endif
		//Ready to go
		HookFunction::RunAll();
		gl_patcher.Init();
#if 1
	}
#endif
	return 0;
}

void InitInstance(HANDLE hModule)
{
	OutputDebugString("PROXYDLL: InitInstance called.\r\n");

	// Initialisation
	gl_hOriginalDll = NULL;
	gl_hThisInstance = NULL;

	// Storing Instance handle into global var
	gl_hThisInstance = (HINSTANCE)hModule;
	Init(NULL);
}

void ExitInstance()
{
	OutputDebugString("PROXYDLL: ExitInstance called.\r\n");
}

