#include "stdafx.h"
#include <iostream>
#include "Util.h"
#include "LibraryStubs.h"

#define USER_APP
extern "C" {
#include <s2e/s2e.h>
}

unsigned char oldWSAStartupHook[LEN_OPCODES_HOOK_FUNCTION];
int WINAPI WSAStartupHook(
	WORD      wVersionRequired,
	LPWSADATA lpWSAData
) {
	Message("WSAStartup called.\n");
	return 0;
}

unsigned char oldGetaddrinfoHook[LEN_OPCODES_HOOK_FUNCTION];
INT WSAAPI getaddrinfoHook(
	PCSTR           pNodeName,
	PCSTR           pServiceName,
	const ADDRINFOA *pHints,
	PADDRINFOA      *ppResult
) {
	Message("getaddrinfo called. pNodeName=%s\n", pNodeName);
	ADDRINFOA* ris = new ADDRINFOA(*pHints);
	*ppResult = ris;
	return 0;
}

int i = 0;
int rets[] = { 0xdeadbeef, 0xcafecafe };
unsigned char oldSocketHook[LEN_OPCODES_HOOK_FUNCTION];
SOCKET WSAAPI socketHook(
	int af,
	int type,
	int protocol
) {
	Message("socket called.\n");
	return rets[0];
}

unsigned char oldConnectHook[LEN_OPCODES_HOOK_FUNCTION];
int WSAAPI connectHook(
	SOCKET         s,
	const sockaddr *name,
	int            namelen
) {
	Message("connect called.\n");
	return 0;
}

unsigned char oldClosesocketHook[LEN_OPCODES_HOOK_FUNCTION];
int WSAAPI closesocketHook(
	SOCKET s
) {
	Message("closesocket called.\n");
	return 0;
}

unsigned char oldFreeaddrinfoHook[LEN_OPCODES_HOOK_FUNCTION];
VOID WSAAPI freeaddrinfoHook(
	PADDRINFOA pAddrInfo
) {
	Message("freeaddrinfo called.\n");
	return;
}

unsigned char oldWSACleanupHook[LEN_OPCODES_HOOK_FUNCTION];
int WINAPI WSACleanupHook() {
	Message("WSACleanupHook called.\n");
	return 0;
}

unsigned char oldSendHook[LEN_OPCODES_HOOK_FUNCTION];
int WSAAPI sendHook(
	SOCKET     s,
	const char *buf,
	int        len,
	int        flags
) {
	Message("send called.\n");
	// exit(1);
	// unsigned int snd_len;
	// memcpy(&snd_len, buf, 4);
	// char* dst = (char*)malloc(sizeof(char)*snd_len*3 + 1);
	for (i=0; i<len; ++i)
		Message("%x\n", buf[i] & 0xff);
		// sprintf(dst + 3*i, "%x ", buf[4 + i]);
	// memcpy(dst, buf + 4, snd_len);
	// dst[len] = NULL;
	// free(dst);
	return len;
}

unsigned char oldShutdownHook[LEN_OPCODES_HOOK_FUNCTION];
int WSAAPI shutdownHook(
	SOCKET s,
	int    how
) {
	Message("shutdown called.\n");
	return 0;
}

unsigned char oldWSAGetLastErrorHook[LEN_OPCODES_HOOK_FUNCTION];
int WINAPI WSAGetLastErrorHook() {
	Message("WSAGetLastError called.\n");
	return 42;
}

int callCounter = 0;
unsigned char oldRecvHook[LEN_OPCODES_HOOK_FUNCTION];
int WSAAPI recvHook(
	SOCKET s,
	char   *buf,
	int    len,
	int    flags
) {
	Message("recv called.\n");
#if S2E
	if (S2EIsSymbolic((PVOID)&len, 4)) {
		S2EPrintExpression(len, "symb_len");
		if (len > 0x45) S2EKillState(0, "limit len");
		else      		S2EConcretize(&len, 4);
		// S2EAssume(len = 0x41);
		Message("Concretizing len to %d\n", len);
	}
#endif
	memset(buf, 0, len);
	if (callCounter == 0) {
		callCounter++;
		buf[0] = 0x41;
		return len;
	}
	if (callCounter == 1) {
		callCounter++;
		Message("KEY\n");
		// extracted using SE (TARGET: 0x040D3AD; AVOID: 0x040D3B6). First recv {0x41, 0x0, 0x0, 0x0}
		unsigned char tmp[] = { 0x5, 0x0, 0x0, 0x1, 0x4, 0x1, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x4, 0x1, 0x4, 0x0, 0x1, 0x4, 0x5, 0x10, 0x10, 0x7, 0x1d, 0x4, 0x2, 0x8f, 0xd2, 0xb, 0xcb, 0x42, 0x16, 0x36, 0x25, 0x65, 0x35, 0xfd, 0x4e, 0xa6, 0x98, 0xa, 0x41, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
		memcpy(buf, tmp, 0x41);
		// S2EMakeConcolic(buf, len, "recv_buf");
		// buf[0] = 0x5;
		return len;
	}
#if S2E
	char name[50];
	sprintf(name, "recv_%d", callCounter++);
	S2EMakeConcolic(buf, len, name);   // passing a stack variable should be safe
	return len;
#else
	if (len == 4)
		buf[0] = 0x6;
	else
		buf[0] = 0x4b;
	callCounter++;
	return len;
#endif
}

unsigned char oldSelectHook[LEN_OPCODES_HOOK_FUNCTION];
int WSAAPI selectHook(
	int           nfds,
	fd_set        *readfds,
	fd_set        *writefds,
	fd_set        *exceptfds,
	const timeval *timeout
) {
	Message("select called.\n");
	return 1;
}

unsigned char oldGethostbynameHook[LEN_OPCODES_HOOK_FUNCTION];
hostent *WSAAPI gethostbynameHook(
	const char *name
) {
	Message("gethostbyname called. name=%s\n", name);
	char* h_name = (char*)malloc(strlen(name));
	strcpy(h_name, name);
	char* addr1 = (char*)calloc(sizeof(char), 1);
	char** h_addr_list = (char**)malloc(sizeof(char*) * 2);
	h_addr_list[0] = addr1; h_addr_list[1] = NULL;

	hostent* ris = (hostent*)malloc(sizeof(hostent));

	ris->h_name = h_name;
	ris->h_length = (short)strlen(name);
	ris->h_addr_list = h_addr_list;
	ris->h_aliases = h_addr_list;
	return ris;

}

unsigned char OldHtonsHook[LEN_OPCODES_HOOK_FUNCTION];
u_short WINAPI htonsHook(
	u_short hostshort
)
{
	Message("Intercepted htons\n");
	return 0;
}


// *****************************************************************************************

unsigned char OldHookRegOpenKeyExA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
LSTATUS WINAPI HookRegOpenKeyExA(
	HKEY   hKey,
	LPCSTR lpSubKey,
	DWORD  ulOptions,
	REGSAM samDesired,
	PHKEY  phkResult
)
{
	*phkResult = (HKEY)0xDEADBEEF; // dummy handle
	Message("Intercepted RegOpenKeyExA\n");
	return ERROR_SUCCESS;
}

unsigned char OldHookRegSetValueExA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
LSTATUS WINAPI HookRegSetValueExA(
	HKEY       hKey,
	LPCSTR     lpValueName,
	DWORD      Reserved,
	DWORD      dwType,
	const BYTE *lpData,
	DWORD      cbData
)
{
	if (S2EIsSymbolic((LPVOID)lpValueName, 1)) {
		Message("Intercepted RegSetValueExA\n");
		S2EPrintExpression(*lpValueName, "RegSetValueExA lpValueName");
		Message("END SYMBOL");
	}
	else
		Message("Intercepted RegSetValueExA(%s)\n", lpValueName);
	return ERROR_SUCCESS;
}

unsigned char OldHookRegCloseKey[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
LSTATUS WINAPI HookRegCloseKey(
	HKEY hKey
)
{
	Message("Intercepted RegCloseKey(%08x)\n",
		hKey);
	return ERROR_SUCCESS;
}

// ************************************************************************************************************
// KERNEL32 ***************************************************************************************************

unsigned char OldHookFindFirstFileA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
HANDLE WINAPI HookFindFirstFileA(
	LPCSTR             lpFileName,
	LPWIN32_FIND_DATAA lpFindFileData
)
{
	if (S2EIsSymbolic((LPVOID)lpFileName, 1)) {
		Message("Intercepted FindFirstFileA\n");
		S2EPrintExpression(*lpFileName, "FindFirstFileA FileName");
		Message("END SYMBOL");
	}
	else
		Message("Intercepted FindFirstFileA(%s)\n", lpFileName);
	return INVALID_HANDLE_VALUE; // fail
}

unsigned char OldHookFindNextFileA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
HANDLE WINAPI HookFindNextFileA(
	HANDLE             hFindFile,
	LPWIN32_FIND_DATAA lpFindFileData
)
{
	Message("Intercepted FindNextFileA\n");
	return 0x0; // fail
}

unsigned char OldHookFindClose[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookFindClose(
	HANDLE hFindFile
)
{
	Message("Intercepted FindClose\n");
	return TRUE;
}

unsigned char OldHookCreateDirectoryA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookCreateDirectoryA(
	LPCSTR                lpPathName,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
)
{
	if (S2EIsSymbolic((LPVOID)lpPathName, 1)) {
		Message("Intercepted CreateDirectoryA\n");
		S2EPrintExpression(*lpPathName, "CreateDirectoryA PathName");
		Message("END SYMBOL");
	}
	else
		Message("Intercepted CreateDirectoryA(%s)\n", lpPathName);
	return FALSE;
}

unsigned char OldHookRemoveDirectoryA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookRemoveDirectoryA(
	LPCSTR lpPathName
)
{
	if (S2EIsSymbolic((LPVOID)lpPathName, 1)) {
		Message("Intercepted RemoveDirectoryA\n");
		S2EPrintExpression(*lpPathName, "RemoveDirectoryA PathName");
		Message("END SYMBOL");
	}
	else
		Message("Intercepted RemoveDirectoryA(%s)\n", lpPathName);
	return FALSE;
}

unsigned char OldHookCreateFileA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
HANDLE WINAPI HookCreateFileA(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	if (S2EIsSymbolic((LPVOID)lpFileName, 1)) {
		Message("Intercepted CreateFileA\n");
		S2EPrintExpression(*lpFileName, "CreateFileA FileName");
		Message("END SYMBOL");
	}
	else
		Message("Intercepted CreateFileA(%s)\n", lpFileName);
	return INVALID_HANDLE_VALUE;// (HANDLE)0xDEADCAFE;
}

unsigned char OldHookCloseHandle[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookCloseHandle(
	_In_ HANDLE hObject
)
{
	Message("Intercepted CloseHandle(%08x)\n",
		hObject);
	return TRUE;
}

unsigned char OldHookMoveFileA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookMoveFileA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName
)
{
	if (S2EIsSymbolic((LPVOID)lpExistingFileName, 1) || S2EIsSymbolic((LPVOID)lpNewFileName, 1)) {
		Message("Intercepted MoveFileA\n");
		S2EPrintExpression(*lpExistingFileName, "MoveFileA ExistingFileName");
		S2EPrintExpression(*lpNewFileName, "MoveFileA NewFileName");
		Message("END SYMBOL");
	}
	else
		Message("Intercepted MoveFileA(%s, %s)\n", lpExistingFileName, lpNewFileName);
	return FALSE;
}

unsigned char OldHookDeleteFileA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookDeleteFileA(
	LPCSTR lpFileName
)
{
	if (S2EIsSymbolic((LPVOID)lpFileName, 1)) {
		Message("Intercepted DeleteFileA\n");
		S2EPrintExpression(*lpFileName, "DeleteFileA FileName");
		Message("END SYMBOL");
	}
	else
		Message("Intercepted DeleteFileA(%s)\n", lpFileName);
	return FALSE;
}

unsigned char OldHookGetDriveTypeA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
UINT WINAPI HookGetDriveTypeA(
	LPCSTR lpRootPathName
)
{
	if (S2EIsSymbolic((LPVOID)lpRootPathName, 1)) {
		Message("Intercepted GetDriveTypeA\n");
		S2EPrintExpression(*lpRootPathName, "GetDriveTypeA PathName");
		Message("END SYMBOL");
	}
	else
		Message("Intercepted GetDriveTypeA(%s)\n", lpRootPathName);
	return DRIVE_UNKNOWN;
}

unsigned char OldHookGetLogicalDrives[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
DWORD WINAPI HookGetLogicalDrives()
{
	Message("Intercepted GetLogicalDrives()\n");
	return 0; // no drive
}

unsigned char OldHookWinExec[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
UINT WINAPI HookWinExec(
	LPCSTR lpCmdLine,
	UINT   uCmdShow
)
{
	if (S2EIsSymbolic((LPVOID)lpCmdLine, 1)) {
		Message("Intercepted WinExec\n");
		S2EPrintExpression(*lpCmdLine, "WinExec command");
		Message("END SYMBOL");
	}
	else
		Message("Intercepted WinExec(%s)\n", lpCmdLine);
	return 32;
}

// ************************************************************************************************************

