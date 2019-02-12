// dllmain.cpp : Definisce il punto di ingresso per l'applicazione DLL.
#include "stdafx.h"
#include "Util.h"
#include "LibraryStubs.h"
#include "KillAfterNGuest.h"
#define USER_APP
extern "C" {
#include <s2e/s2e.h>
}
#include <intrin.h>

#define GET_FILE_PATH_ADDRESS 0x409BAB //0x0405073
#define ADDR_AFTER_INIT 0x0402027
#define ADDR_CMD_SWITCH 0x04010C7// 0x0401068
#define ADDR_CHECK 0x0402071
#define ADDR_AFTER_SWITCH 0x0405214
#define ADDR_AVOID_2 0x04020DE

#define ADDR_AVOID_3 0x040D3B6

#define ADDR_TARGET 0x040D3AD
#define ADDR_FIRST_CMD 0x04010EB

#define ADDR_CMD_4 0x04010EB

#define MALLOC_ADDR 0x040F520
#define FREE_ADDR 0x040F530
#define TIME_ADDR 0x40F5A8

#define ADDR_END_SWITCH 0x0401F9A

#define ADDR_CREATE_DIRECTORY 0x040F400

BOOL executed = FALSE;
static BOOL command_ex = FALSE;
int s2eVersion = 0;

long long vals[] = { -6293595036912659288, -1663823975275766040 };
int timeCallCounter = 0;
unsigned char oldMyTime[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
long long myTime() {
	Message("time called by 0x%x\n", _ReturnAddress());
	// if (timeCallCounter == 0 || timeCallCounter == 1) return vals[timeCallCounter++];
#if S2E
	// long long ris;
	// S2EMakeConcolic(&ris, sizeof(long long), "time");
	// return ris;
	// return 0;
	return 1549763150;
#else
	return 1549763150;
#endif
}

unsigned char oldMyMalloc[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
void* myMalloc(int size) {
	void* ris = calloc(size, 1);
	return ris;
}

unsigned char oldMyFree[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
void myFree(void* addr) {
	free(addr);
}

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
	return;
//	if (! command_ex) {// (true) {
//#if S2E
//		S2EKillState(0, "avoid 1");
//#else
//		exit(1);
//#endif
//	}
//	else {
//		// command_ex = FALSE;
//		Message("After switch.\n");
//	}
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
	Message("RIS OK.\n");
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
		//HookFunction((funcpointer)MALLOC_ADDR, (funcpointer)&myMalloc, oldMyMalloc);
		//HookFunction((funcpointer)FREE_ADDR, (funcpointer)&myFree, oldMyFree);
		HookFunction((funcpointer)TIME_ADDR, (funcpointer)&myTime, oldMyTime);
		HookFunction((funcpointer)GET_FILE_PATH_ADDRESS, (funcpointer)get_file_path_stub, oldGetFilePath);
#if S2E
		// HookInstruction((funcpointer)ADDR_CMD_4, (funcpointer)cmd_4, (funcpointer)ADDR_CMD_4, oldCmd_4);

		// CHECK KEY
		HookFunction((funcpointer)ADDR_AVOID_3, (funcpointer)avoidTMP,oldAvoidTMP);
		// HookFunction((funcpointer)ADDR_TARGET, (funcpointer)targetTMP, oldTargetTMP);
		// *********

		HookFunction((funcpointer)ADDR_AFTER_SWITCH, (funcpointer)after_switch, oldAfterSwitch);
		// HookFunction((funcpointer)ADDR_AVOID_2, (funcpointer)exit_stub, oldExit_stub);
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

		// HookFunction((funcpointer)ADDR_CREATE_DIRECTORY, (funcpointer)&targetTMP, oldTargetTMP);

		HookDynamicFunction("advapi32", "CryptCreateHash", (funcpointer)&HookCryptCreateHash, OldHookCryptCreateHash);
		HookDynamicFunction("advapi32", "GetUserNameA", (funcpointer)&HookGetUserNameA, OldHookGetUserNameA);
		HookDynamicFunction("advapi32", "RegOpenKeyExA", (funcpointer)&HookRegOpenKeyExA, OldHookRegOpenKeyExA);
		HookDynamicFunction("advapi32", "RegSetValueExA", (funcpointer)&HookRegSetValueExA, OldHookRegSetValueExA);
		HookDynamicFunction("advapi32", "RegCloseKey", (funcpointer)&HookRegCloseKey, OldHookRegCloseKey);

		HookDynamicFunction("msvcrt", "fopen", (funcpointer)Hookfopen, OldHookfopen);
		HookDynamicFunction("msvcrt", "fclose", (funcpointer)Hookfclose, OldHookfclose);
		HookDynamicFunction("msvcrt", "fwrite", (funcpointer)Hookfwrite, OldHookfwrite);

		HookDynamicFunction("winmm", "waveInOpen", (funcpointer)HookwaveInOpen, OldHookwaveInOpen);

		HookDynamicFunction("shell32", "ShellExecuteA", (funcpointer)HookShellExecuteA, OldHookShellExecuteA);

		HookDynamicFunction("kernel32", "Sleep", (funcpointer)HookSleep, OldHookSleep);
		HookDynamicFunction("kernel32", "SleepEx", (funcpointer)HookSleepEx, OldHookSleepEx);
		// HookDynamicFunction("kernel32", "GetLocalTime", (funcpointer)HookGetLocalTime, OldHookGetLocalTime);
		HookDynamicFunction("kernel32", "CreatePipe", (funcpointer)HookCreatePipe, OldHookCreatePipe);
		HookDynamicFunction("kernel32", "GetCommandLineA", (funcpointer)HookGetCommandLineA, OldHookGetCommandLineA);
		HookDynamicFunction("kernel32", "CreateProcessA", (funcpointer)&HookCreateProcessA, OldHookCreateProcessA);
		HookDynamicFunction("kernel32", "CreateMutexA", (funcpointer)&HookCreateMutexA, OldHookCreateMutexA);
		HookDynamicFunction("kernel32", "FindFirstFileA", (funcpointer)&HookFindFirstFileA, OldHookFindFirstFileA);
		HookDynamicFunction("kernel32", "FindNextFileA", (funcpointer)&HookFindNextFileA, OldHookFindNextFileA);
		HookDynamicFunction("kernel32", "FindClose", (funcpointer)&HookFindClose, OldHookFindClose);
		HookDynamicFunction("kernel32", "CreateDirectoryA", (funcpointer)&HookCreateDirectoryA, OldHookCreateDirectoryA);
		HookDynamicFunction("kernel32", "RemoveDirectoryA", (funcpointer)&HookRemoveDirectoryA, OldHookRemoveDirectoryA);
		HookDynamicFunction("kernel32", "MoveFileA", (funcpointer)&HookMoveFileA, OldHookMoveFileA);
		HookDynamicFunction("kernel32", "DeleteFileA", (funcpointer)&HookDeleteFileA, OldHookDeleteFileA);
		HookDynamicFunction("kernel32", "CreateFileA", (funcpointer)&HookCreateFileA, OldHookCreateFileA);
		// HookDynamicFunction("kernel32", "CloseHandle", (funcpointer)&HookCloseHandle, OldHookCloseHandle);
		HookDynamicFunction("kernel32", "GetDriveTypeA", (funcpointer)&HookGetDriveTypeA, OldHookGetDriveTypeA);
		HookDynamicFunction("kernel32", "GetLogicalDrives", (funcpointer)&HookGetLogicalDrives, OldHookGetLogicalDrives);
		HookDynamicFunction("kernel32", "WinExec", (funcpointer)&HookWinExec, OldHookWinExec);
		HookDynamicFunction("kernel32", "CreateToolhelp32Snapshot", (funcpointer)&HookCreateToolhelp32Snapshot, OldHookCreateToolhelp32Snapshot);
		HookDynamicFunction("kernel32", "OpenProcess", (funcpointer)&HookOpenProcess, OldHookOpenProcess);

		HookDynamicFunction("user32", "EnumWindows", (funcpointer)&HookEnumWindows, OldHookEnumWindows);
		HookDynamicFunction("user32", "CreateWindowExA", (funcpointer)&HookCreateWindowExA, OldHookCreateWindowExA);
		HookDynamicFunction("msvcrt", "_beginthreadex", (funcpointer)&_beginthreadexHook, Old_beginthreadexHook);

		HookDynamicFunction("secur32", "LsaGetLogonSessionData", (funcpointer)HookLsaGetLogonSessionData, OldHookLsaGetLogonSessionData);
		HookDynamicFunction("secur32", "LsaFreeReturnBuffer", (funcpointer)HookLsaFreeReturnBuffer, OldHookLsaFreeReturnBuffer);
		HookDynamicFunction("secur32", "LsaEnumerateLogonSessions", (funcpointer)HookLsaEnumerateLogonSessions, OldHookLsaEnumerateLogonSessions);

		Message("Hooks done.\n");
	}
    return TRUE;
}

