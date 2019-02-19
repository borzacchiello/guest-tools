// dllmain.cpp : Definisce il punto di ingresso per l'applicazione DLL.
#include "stdafx.h"

#define LEN_OPCODES_HOOK_FUNCTION 7

#define GET_FILE_PATH_ADDRESS 0x409BAB
#define TIME_ADDR 0x40F5A8

typedef void(*funcpointer)(void *);

bool executed = false;

void HookFunction(funcpointer address_to_patch, funcpointer function_to_load, unsigned char* old_data)
{
	DWORD bytes_written;

	unsigned char opcodes[] = {										// MOV EAX, $ADDRESS_TO_PATCH
		0xB8,														// JMP EAX
		(unsigned char)(((unsigned long)function_to_load)),
		(unsigned char)(((unsigned long)function_to_load) >> 8),
		(unsigned char)(((unsigned long)function_to_load) >> 16),
		(unsigned char)(((unsigned long)function_to_load) >> 24),
		0xFF,
		0xE0
	};
	SIZE_T len_opcodes = sizeof(opcodes);

	DWORD dwProtect;
	if (!VirtualProtect(address_to_patch, len_opcodes, PAGE_EXECUTE_READWRITE, &dwProtect)) {
		exit(1);
	}

	// Save old opcodes
	if (!WriteProcessMemory(
		GetCurrentProcess(),
		(LPVOID)old_data,
		(LPVOID)address_to_patch,
		len_opcodes,
		&bytes_written
	)) {
		exit(1);
	}
	else if (bytes_written != len_opcodes) {
		exit(1);
	}

	// Write new opcodes
	if (!WriteProcessMemory(
		GetCurrentProcess(),
		(LPVOID)address_to_patch,
		(LPVOID)opcodes,
		len_opcodes,
		&bytes_written
	)) {
		exit(1);
	}
	else if (bytes_written != len_opcodes) {
		exit(1);
	}

	if (!FlushInstructionCache(
		GetCurrentProcess(),
		address_to_patch,
		len_opcodes
	)) {
		exit(1);
	}
}

unsigned char oldGetFilePath[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
int get_file_path_stub() {
	return 0;
}

unsigned char oldMyTime[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
long long myTime() {
	return 1549763150;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	if (!executed) {
		executed = false;

		HookFunction((funcpointer)TIME_ADDR, (funcpointer)&myTime, oldMyTime);
		HookFunction((funcpointer)GET_FILE_PATH_ADDRESS, (funcpointer)get_file_path_stub, oldGetFilePath);
	}
    return TRUE;
}

