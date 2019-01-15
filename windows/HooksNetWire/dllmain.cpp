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
#define ADDR_AFTER_SWITCH 0x0405214
#define ADDR_AVOID_2 0x04020DE

#define ADDR_AVOID_3 0x040D3B6 
#define ADDR_TARGET 0x040D3AD
#define ADDR_FIRST_CMD 0x04010EB

#define ADDR_CMD_4 0x04010EB

BOOL executed = FALSE;
static volatile BOOL command_ex = FALSE;
int s2eVersion = 0;

unsigned char oldCmd_4[LEN_OPCODES_HOOK_INSTRUCTION] = { 0 };
void cmd_4()
{
	Message("In cmd 4.\n");
	RestoreData((funcpointer)ADDR_CMD_4, oldCmd_4, LEN_OPCODES_HOOK_INSTRUCTION);
}

unsigned char oldAvoidTMP[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
void avoidTMP() 
{
	Message("AVOID TMP.\n");
#if S2E
	S2EKillState(0, "avoid tmp");
#else
	exit(1);
#endif
}

unsigned char oldTargetTMP[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
void targetTMP()
{
	Message("TARGET TMP.\n");
#if S2E
	S2EKillState(0, "target tmp");
#else
	exit(1);
#endif
}

unsigned char oldExit_stub[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
void exit_stub()
{
	Message("AVOID.\n");
#if S2E
	S2EKillState(0, "exit stub");
#else
	exit(1);
#endif
}

unsigned char oldAfterSwitch[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
void after_switch()
{
	if (! command_ex) {
#if S2E
		S2EKillState(0, "avoid 1");
#else
		exit(1);
#endif
	}
	else {
		command_ex = FALSE;
		Message("After switch.\n");
	}
}

unsigned char oldGetFilePath[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
int get_file_path_stub() {
	return 0;
}

int counter = 0;
unsigned char oldCmd_switch[LEN_OPCODES_HOOK_INSTRUCTION] = { 0 };
void cmd_switch(unsigned long eax, unsigned long ebx, unsigned long ecx,
	unsigned long edx, unsigned long edi, unsigned long esi)
{
	Message("In command switch.\n");
	if (counter > 0) {
#if S2E
		S2EKillState(0, "2nd switch");
#else
		exit(1);
#endif
	}
	else {
		command_ex = TRUE;
		RestoreData((funcpointer)ADDR_CMD_SWITCH, oldCmd_switch, LEN_OPCODES_HOOK_INSTRUCTION);
		counter++;
	}
}

// rendez-vouz *******
void check_ris(unsigned long eax, unsigned long ebx, unsigned long ecx,
	unsigned long edx, unsigned long edi, unsigned long esi);
unsigned char oldCheck_ris[LEN_OPCODES_HOOK_INSTRUCTION] = { 0 };

unsigned char oldHook_after_init[LEN_OPCODES_HOOK_INSTRUCTION] = { 0 };
void hook_after_init(unsigned long eax, unsigned long ebx, unsigned long ecx,
	unsigned long edx, unsigned long edi, unsigned long esi)
{
	HookInstruction((funcpointer)ADDR_CMD_SWITCH, (funcpointer)&cmd_switch, (funcpointer)ADDR_CMD_SWITCH, oldCmd_switch);
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
#if S2E
		HookInstruction((funcpointer)ADDR_CMD_4, (funcpointer)cmd_4, (funcpointer)ADDR_CMD_4, oldCmd_4);

		// HookFunction((funcpointer)ADDR_AVOID_3, (funcpointer)avoidTMP,oldAvoidTMP);
		// HookFunction((funcpointer)ADDR_TARGET, (funcpointer)targetTMP, oldTargetTMP);

		HookFunction((funcpointer)ADDR_AFTER_SWITCH, (funcpointer)after_switch, oldAfterSwitch);
		HookFunction((funcpointer)ADDR_AVOID_2, (funcpointer)exit_stub, oldExit_stub);
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

