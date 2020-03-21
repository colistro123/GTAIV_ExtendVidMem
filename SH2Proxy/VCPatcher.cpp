#include "stdafx.h"
#include <iostream>
#include <fstream>
#include "VCPatcher.h"
#include "Hooking.Patterns.h"
#include "Utils.h"
#include <stdio.h>
#include <MinHook.h>
#include <d3d9.h>
#include <dxgi.h>
#include <fstream>
#include <iostream>

#define CONSOLE_ENABLED

IDirect3D9* d3dDevice;
int availableVidMem = 0x20000000 * 2; //512 * 2 = 1024
int overrideMemAmountFromFile = 0;

void logFuncCustom(const char* logEntry, ...) {
	FILE* logFile = _wfopen(L"ExtendVidMem.log", L"a");
	if (logFile)
	{
		char bufferOut[1024];
#ifdef CONSOLE_ENABLED
		char bufferOutConsole[1024];
#endif
		va_list argptr;
		char end_char = logEntry[strlen(logEntry) - 1];
		_snprintf(bufferOut, sizeof(bufferOut), (end_char == '\n') ? "[EXTEND_VID_MEM]: %s" : "[EXTEND_VID_MEM]: %s\n", logEntry);
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

int bytesToMB(size_t value) 
{
	return value / (1024 * 1024);
}

static int(*g_origGetMaxAvailableVideoMemory)();
static int GetMaxAvailableVideoMemory_Hook() {
	int mem = g_origGetMaxAvailableVideoMemory();
	return availableVidMem;
}

typedef HRESULT(WINAPI* LPCREATEDXGIFACTORY)(REFIID, void**);
static LPCREATEDXGIFACTORY sFnPtr_CreateDXGIFactory = NULL;
IDXGIAdapter1* g_pAdapter = NULL;  // Adapter to use

static IDirect3D9* (__stdcall *g_origDirect3DCreate9)(UINT SDKVersion);
static IDirect3D9* __stdcall Direct3DCreate9_Hook(UINT SDKVersion) 
{
	d3dDevice = g_origDirect3DCreate9(SDKVersion);

	HMODULE s_hModDXGI = LoadLibrary("dxgi.dll");
	HRESULT hr = S_OK;
	D3DADAPTER_IDENTIFIER9 pIdentifier;

	if (s_hModDXGI)
	{
		sFnPtr_CreateDXGIFactory = (LPCREATEDXGIFACTORY)GetProcAddress(s_hModDXGI, "CreateDXGIFactory");
	}

	IDXGIFactory* pFactory;
	hr = sFnPtr_CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)(&pFactory));

	if (!SUCCEEDED(hr))
	{
		logFuncCustom("> No DXGI Factory created.\n");
		return false;
	}

	UINT adapter = 0;

	for (; !g_pAdapter; ++adapter)
	{
		// Get a candidate DXGI adapter
		IDXGIAdapter* pAdapter = NULL;

		hr = pFactory->EnumAdapters(adapter, &pAdapter);
		
		if (FAILED(hr))
		{
			break;    // no compatible adapters found
		}

		//Get the current adapter from d3dDevice
		hr = d3dDevice->GetAdapterIdentifier(adapter, 0, &pIdentifier);
		int currentDeviceId = 0;

		if (S_OK == hr) 
			currentDeviceId = pIdentifier.DeviceId;

		DXGI_ADAPTER_DESC adapterDesc;
		if SUCCEEDED(pAdapter->GetDesc(&adapterDesc)) 
		{			
			if (adapterDesc.DeviceId == currentDeviceId) 
			{
				//Increment memory accordingly
				if (availableVidMem < adapterDesc.DedicatedVideoMemory)
				{
					logFuncCustom("Matched current selected device...\n");
					logFuncCustom("Dedicated video memory for %ls should now be %d MB.\n", adapterDesc.Description, bytesToMB(adapterDesc.DedicatedVideoMemory));
					int dedVideoMem = static_cast<int>(adapterDesc.DedicatedVideoMemory);

					availableVidMem = overrideMemAmountFromFile <= 0 ? dedVideoMem : overrideMemAmountFromFile;
					logFuncCustom("availableVidMem %d MB.\n", bytesToMB(availableVidMem));
				}
			}
		}

		pAdapter->Release();
	}

	pFactory->Release();

	return d3dDevice;
}

void readConfig()
{
	std::ifstream Config("extendvidmem.txt");
	std::string line;

	if (!Config.is_open())
		return;

	while (std::getline(Config, line))
		overrideMemAmountFromFile = std::stoi(line) * (1024*1024);

	Config.close();
}

bool VCPatcher::Init()
{
	readConfig();

	char* location;
#if _DEBUG
	DWORD address = (DWORD)GetProcAddress(GetModuleHandle("kernel32.dll"), "TerminateProcess");
	hook::vp::jump(address, ourTerminateProcess);

	location = hook::pattern("55 8B EC FF 75 08 FF 15 ? ? ? ? 50 FF 15 ? ? ? ? 5D C3").count(1).get(0).get<char>(0);
	hook::vp::jump(location, ourExit);
#endif

	location = hook::pattern("8b ? ? ? ? ? 83 ? 14 33 ? 85 ? 74 ? ff").count(1).get(0).get<char>(0);
	MH_CreateHook(location, GetMaxAvailableVideoMemory_Hook, (void**)&g_origGetMaxAvailableVideoMemory);

#if _DEBUG
	AllocConsole();
	AttachConsole(GetCurrentProcessId());
	freopen("CON", "w", stdout);
#endif

	MH_EnableHook(MH_ALL_HOOKS);

	return true;
}

void VCPatcher::PreHooks() 
{
	char* location = (char*)GetProcAddress(GetModuleHandle("d3d9.dll"), "Direct3DCreate9");
	MH_CreateHook(location, Direct3DCreate9_Hook, (void**)&g_origDirect3DCreate9);

	MH_EnableHook(MH_ALL_HOOKS);
}

static struct MhInit
{
	MhInit()
	{
		MH_Initialize();
	}
} mhInit;