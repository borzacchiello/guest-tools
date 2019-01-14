// dllmain.cpp : Definisce il punto di ingresso per l'applicazione DLL.
#include "stdafx.h"
#include "Util.h"
#include "LibraryStubs.h"
#define USER_APP
extern "C" {
#include <s2e/s2e.h>
}

#define GET_FILE_PATH_ADDRESS 0x0405073
#define ADDR_AFTER_INIT 0x0402027
#define ADDR_CMD_SWITCH 0x0401068
#define ADDR_CHECK 0x0402071

BOOL executed = FALSE;
int s2eVersion = 0;

unsigned char oldExit_stub[LEN_OPCODES_HOOK_INSTRUCTION] = { 0 };
void exit_stub(unsigned long eax, unsigned long ebx, unsigned long ecx,
	unsigned long edx, unsigned long edi, unsigned long esi)
{
	Message("REACHED.\n");
	exit(1);
}

unsigned char oldGetFilePath[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
int get_file_path_stub() {
	return 0;
}

// rendez-vouz *******
void check_ris(unsigned long eax, unsigned long ebx, unsigned long ecx,
	unsigned long edx, unsigned long edi, unsigned long esi);
unsigned char oldCheck_ris[LEN_OPCODES_HOOK_INSTRUCTION] = { 0 };

unsigned char oldHook_after_init[LEN_OPCODES_HOOK_INSTRUCTION] = { 0 };
void hook_after_init(unsigned long eax, unsigned long ebx, unsigned long ecx,
	unsigned long edx, unsigned long edi, unsigned long esi)
{
	HookInstruction((funcpointer)ADDR_CHECK, (funcpointer)check_ris, (funcpointer)ADDR_CHECK, oldCheck_ris);
	RestoreData((funcpointer)ADDR_AFTER_INIT, oldHook_after_init, LEN_OPCODES_HOOK_INSTRUCTION);
}

void check_ris(unsigned long eax, unsigned long ebx, unsigned long ecx,
	unsigned long edx, unsigned long edi, unsigned long esi)
{
	if (eax == 0) exit(1);
	HookInstruction((funcpointer)ADDR_AFTER_INIT, (funcpointer)hook_after_init, (funcpointer)ADDR_AFTER_INIT, oldHook_after_init);
	RestoreData((funcpointer)ADDR_CHECK, oldCheck_ris, LEN_OPCODES_HOOK_INSTRUCTION);
}
// *******************
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	if (!executed) {
		executed = true;
#if S2E
		s2eVersion = S2EGetVersion();
#else
		s2eVersion = 0;
#endif
		if (!s2eVersion) InitDebugFile();
		Message("Initialization phase.\n");

		HookFunction((funcpointer)GET_FILE_PATH_ADDRESS, (funcpointer)get_file_path_stub, oldGetFilePath);
		HookInstruction((funcpointer)ADDR_CMD_SWITCH, (funcpointer)&exit_stub, (funcpointer)ADDR_CMD_SWITCH, oldExit_stub);
#if S2E
		HookInstruction((funcpointer)ADDR_AFTER_INIT, (funcpointer)hook_after_init, (funcpointer)ADDR_AFTER_INIT, oldHook_after_init);	
#endif
		HookDynamicFunction("ws2_32", "WSAStartup", (funcpointer)WSAStartupHook, oldWSAStartupHook);
		HookDynamicFunction("ws2_32", "getaddrinfo", (funcpointer)getaddrinfoHook, oldGetaddrinfoHook);
		HookDynamicFunction("ws2_32", "socket", (funcpointer)socketHook, oldSocketHook);
		HookDynamicFunction("ws2_32", "connect", (funcpointer)connectHook, oldConnectHook);
		HookDynamicFunction("ws2_32", "closesocket", (funcpointer)closesocketHook, oldClosesocketHook);
		HookDynamicFunction("ws2_32", "freeaddrinfo", (funcpointer)freeaddrinfoHook, oldFreeaddrinfoHook);
		HookDynamicFunction("ws2_32", "WSACleanup", (funcpointer)WSACleanupHook, oldWSACleanupHook);
		HookDynamicFunction("ws2_32", "send", (funcpointer)sendHook, oldSendHook);
		HookDynamicFunction("ws2_32", "shutdown", (funcpointer)shutdownHook, oldShutdownHook);
		HookDynamicFunction("ws2_32", "WSAGetLastError", (funcpointer)WSAGetLastErrorHook, oldWSAGetLastErrorHook);
		HookDynamicFunction("ws2_32", "recv", (funcpointer)recvHook, oldRecvHook);
		HookDynamicFunction("ws2_32", "select", (funcpointer)selectHook, oldSelectHook);
		HookDynamicFunction("ws2_32", "gethostbyname", (funcpointer)gethostbynameHook, oldGethostbynameHook);
		HookDynamicFunction("ws2_32", "htons", (funcpointer)htonsHook, OldHtonsHook);
		Message("Hooks done.\n");
	}
    return TRUE;
}

