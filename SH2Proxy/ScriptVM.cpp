#include "stdafx.h"
#include "ScriptVM.h"
#include "Hooking.h"
#include <winternl.h>
#include "MinHook.h"
#include <ntstatus.h>
#include <windows.h>
#include <tlhelp32.h>
#pragma comment(lib, "C:\\Users\\Ignacio\\Desktop\\Projects\\Resources (Projects that are not mine)\\Terminator3_Hook\\Debug\\MinHook.lib")

intptr_t(__thiscall *ScriptSystem__RegisterFunction)(void *thisPtr, char *Str, int a3);
intptr_t(__thiscall *ScriptExecutable__LookupVar)(intptr_t *thisPtr, char *Str);
intptr_t(__thiscall *ScriptVM__CallFunction)(void **thisPtr, char *Str, int a3); //a3 is 0 most of the time
intptr_t(__thiscall *ScriptVM__PushCActor)(intptr_t *thisPtr, int a2);
intptr_t(__thiscall *ScriptVM__PushCHandle)(intptr_t *thisPtr, int a2);
intptr_t(__thiscall *ScriptVM__PushVector3)(intptr_t *thisPtr, intptr_t* a2);
intptr_t(__thiscall *ScriptVM__PushChar)(intptr_t *thisPtr, char* a2);
intptr_t(__thiscall *ScriptVM__PushFloat)(intptr_t **thisPtr, float a2);
intptr_t(__thiscall *ScriptVM__PushIntPtr)(intptr_t *thisPtr);
intptr_t(__thiscall *ScriptVM__PushScriptVarType)(intptr_t* thisPtr, intptr_t a2, intptr_t a3);
intptr_t(__thiscall *ScriptVM__SetMessageHandlerRules)(intptr_t* thisPtr, char *Str2, int a3);
float*(__thiscall *ScriptVM__SetVarFloat)(intptr_t **thisPtr, char *Str, float a3);
intptr_t(__thiscall *ScriptVM__SetVarInt)(intptr_t* thisPtr, char *Str2, int a3);
intptr_t(__thiscall *ScriptVM__GetVarInt)(intptr_t* thisPtr, char *Str2);
char*(__thiscall *ScriptVM__PopString)(intptr_t* thisPtr);
intptr_t*(__thiscall *ScriptExecutable__LookupLabel)(intptr_t* thisPtr, char *str);
intptr_t(__thiscall *PersistentData__SetGlobal)(intptr_t* thisPtr, char *Str2, int a3);

intptr_t* luaPtr = (intptr_t*)0x12962B4;
intptr_t* persPtr = (intptr_t*)0x01293BCC;

intptr_t jmpAddr = 0xC1B5C9;

enum ss_mode {
	DISABLED = 0,
	ENABLED = 1,
};

HRESULT(__cdecl *Effects__SplitScreen__SetupSplitScreen)(ss_mode mode);

static bool returnFalse() {
	return false;
}


void ScriptVM__CallFunctionIntercept(intptr_t** thisPtr, char* str) {
	Effects__SplitScreen__SetupSplitScreen((ss_mode)2);
	char* coopactive = "CoOpActive";
	if (GetKeyState(VK_CAPITAL) & 0x8000)
	{
		char** coop = &coopactive;
		PersistentData__SetGlobal(persPtr, (char*)coop, 1);
	}
	
	printf("ScriptVM__CallFunctionIntercept: %s\n", str);
}

void _declspec(naked) ScriptVM__CallFunctionInterceptOurs()
{
	_asm
	{
		//restore lost overwritten args by the jmp
		push    ebp
		mov     ebp, esp
		sub     esp, 0x14
		mov		dword ptr[ebp - 0x14], ecx

		//Store regs
		push eax

		mov eax, dword ptr[ebp+8]
		push eax
		push ecx
		call ScriptVM__CallFunctionIntercept
		add esp, 8

		//pop 'em
		pop eax

		//jump back
		jmp jmpAddr
	}
}

bool IsDebuggerPresentOurs() {
	return false;
}


typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      UINT             ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);

int ProcessDebugPort2 = 7;

pfnNtQueryInformationProcess g_origNtQueryInformationProcess = NULL;


static ULONG ValueProcessBreakOnTermination = FALSE;
static bool IsProcessHandleTracingEnabled = false;

DWORD dwExplorerPid = 0;
WCHAR ExplorerProcessName[] = L"explorer.exe";

DWORD GetProcessIdByName(const WCHAR * processName)
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return 0;
	}

	DWORD pid = 0;

	do
	{
		if (!lstrcmpiW((LPCWSTR)pe32.szExeFile, processName))
		{
			pid = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return pid;
}

DWORD GetExplorerProcessId()
{
	if (!dwExplorerPid)
	{
		dwExplorerPid = GetProcessIdByName(ExplorerProcessName);
	}
	return dwExplorerPid;
}


NTSTATUS NTAPI HookedNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
	NTSTATUS ntStat = g_origNtQueryInformationProcess(
		ProcessHandle,
		ProcessInformationClass,
		ProcessInformation,
		ProcessInformationLength,
		ReturnLength);

	//if (GetCurrentProcessId() == GetProcessId(ProcessHandle))
	{
		if (NT_SUCCESS(ntStat) && ProcessInformation != 0 && ProcessInformationLength != 0)
		{
			if (ProcessInformationClass == 31) //ProcessDebugFlags
			{
				*((ULONG *)ProcessInformation) = 1;
			}
			else if (ProcessInformationClass == 30) //ProcessDebugObjectHandle
			{
				*((HANDLE *)ProcessInformation) = 0;
				return STATUS_PORT_NOT_SET;
			}
			else if (ProcessInformationClass == ProcessDebugPort)
			{
				*((HANDLE *)ProcessInformation) = 0;
			}
			else if (ProcessInformationClass == ProcessBasicInformation) //Fake parent
			{
				((PPROCESS_BASIC_INFORMATION)ProcessInformation)->UniqueProcessId = GetExplorerProcessId();
			}
			else if (ProcessInformationClass == ProcessBreakOnTermination)
			{
				*((ULONG *)ProcessInformation) = ValueProcessBreakOnTermination;
			}
			else if (ProcessInformationClass == 32)//ProcessHandleTracing)
			{
				if (IsProcessHandleTracingEnabled)
				{
					return STATUS_SUCCESS;
				}
				else
				{
					return STATUS_INVALID_PARAMETER;
				}
			}
		}

		return ntStat;
	}
	return ntStat;
}

void SetupHook()
{
	HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
	if (NULL != hNtDll)
	{
		g_origNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
		if (NULL != g_origNtQueryInformationProcess)
		{
			char* loc = (char*)g_origNtQueryInformationProcess;
			MH_CreateHook(loc, HookedNtQueryInformationProcess, (void**)&g_origNtQueryInformationProcess);
		}
	}
	MH_EnableHook(MH_ALL_HOOKS);
	return;
}

void EnableDebugPriv()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

	CloseHandle(hToken);
}

void SetupSetPEB() {
	// Thread Environment Block (TEB)
#if defined(_M_X64) // x64
	PTEB tebPtr = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#else // x86
	PTEB tebPtr = reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#endif

	// Process Environment Block (PEB)
	PPEB pebPtr = tebPtr->ProcessEnvironmentBlock;
	//pebPtr->BeingDebugged = false;
	bool falsey = false;

	//hook::putVP(&pebPtr->BeingDebugged, false);
	//FF 15 F4 B0 02 01 //isdebuggerpresent -> p
	//
	auto matches = hook::pattern("FF 15 F4 B0 02 01");

	for (int i = 0; i < matches.size(); i++)
	{
		hook::vp::call(matches.get(i).get<void>(0), IsDebuggerPresentOurs);
	}
}
static HookFunction hookFunction([]()
{
	//SetupSetPEB();
	//SetupHook();
	//hook::vp::jump(0xC1B5C0, ScriptVM__CallFunctionInterceptOurs); //scriptvm callfunction, intercept calls
});

static struct MhInit
{
	MhInit()
	{
		MH_Initialize();
	}
} mhInit;