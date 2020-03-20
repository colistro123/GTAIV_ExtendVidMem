#include "stdafx.h"
#include <windows.h>
#include <mmsystem.h>
#include <dinput.h>
#include "Hooking.h"

extern "C" {
	HRESULT WINAPI DirectInput8Create_wrapper(HINSTANCE inst_handle, DWORD version, const IID & r_iid, LPVOID *ppvOut, LPUNKNOWN p_unk) {
		char realLib[MAX_PATH] = { 0 };
		GetSystemDirectoryA(realLib, sizeof(realLib));
		strcat_s(realLib, MAX_PATH, "\\dinput8.dll");
		HMODULE hLibrary = LoadLibraryA(realLib);

		if (hLibrary)
		{
			FARPROC originalProc = GetProcAddress(hLibrary, "DirectInput8Create");

			if (originalProc)
			{
				return ((HRESULT(WINAPI*)(HINSTANCE, DWORD, REFIID, LPVOID *, LPUNKNOWN))originalProc)(inst_handle, version, r_iid, ppvOut, p_unk);
			}
		}
	}
}