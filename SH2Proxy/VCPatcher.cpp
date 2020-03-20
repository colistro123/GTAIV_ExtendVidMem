#include "stdafx.h"
#include <iostream>
#include <fstream>
#include "VCPatcher.h"
#include "Hooking.Patterns.h"
#include "Utils.h"
#include <stdio.h>
#include <MinHook.h>

#define CONSOLE_ENABLED

#include "timer.h"
#include <iostream>

void logFuncCustom(const char* logEntry, ...) {
	FILE* logFile = _wfopen(L"GameMessages.log", L"a");
	if (logFile)
	{
		char bufferOut[1024];
#ifdef CONSOLE_ENABLED
		char bufferOutConsole[1024];
#endif
		va_list argptr;
		char end_char = logEntry[strlen(logEntry) - 1];
		_snprintf(bufferOut, sizeof(bufferOut), (end_char == '\n') ? "%s" : "%s\n", logEntry);
		va_start(argptr, logEntry);
		vfprintf(logFile, bufferOut, argptr);
#ifdef CONSOLE_ENABLED
		vsprintf(bufferOutConsole, bufferOut, argptr);
#endif
		va_end(argptr);
		fclose(logFile);
#ifdef CONSOLE_ENABLED
		printf(bufferOutConsole);
#endif
	}
	return;
}

bool ReturnTrue() {
	return true;
}

extern VCPatcher gl_patcher;

static void __cdecl ourExit(int ucode) {
	exit(ucode);
}

void __declspec(naked) ourTerminateProcess() {
	MessageBox(0, "Application Exited", "Application Exited", MB_ICONWARNING);
	exit(0);
}

static int(*g_origourCustomSetAvailableVidMem)();
static int ourCustomSetAvailableVidMem() {
	printf("Setting max video memory to 3072 MB...\n");
	g_origourCustomSetAvailableVidMem();

	return 0x20000000 * 6; //512 * 6 = 3072
}

bool VCPatcher::Init()
{
	char* location;
#if _DEBUG
	MessageBox(0, "Waiting for debug attach", "Waiting for debug attach", MB_ICONWARNING);

	DWORD address = (DWORD)GetProcAddress(GetModuleHandle("kernel32.dll"), "TerminateProcess");
	hook::vp::jump(address, ourTerminateProcess);

	location = hook::pattern("55 8B EC FF 75 08 FF 15 ? ? ? ? 50 FF 15 ? ? ? ? 5D C3").count(1).get(0).get<char>(0);
	hook::vp::jump(location, ourExit);
#endif

	location = hook::pattern("8b ? ? ? ? ? 83 ? 14 33 ? 85 ? 74 ? ff").count(1).get(0).get<char>(0);
	MH_CreateHook(location, ourCustomSetAvailableVidMem, (void**)&g_origourCustomSetAvailableVidMem);

#if _DEBUG
	AllocConsole();
	AttachConsole(GetCurrentProcessId());
	freopen("CON", "w", stdout);
#endif

	MH_EnableHook(MH_ALL_HOOKS);
	return true;
}

static struct MhInit
{
	MhInit()
	{
		MH_Initialize();
	}
} mhInit;