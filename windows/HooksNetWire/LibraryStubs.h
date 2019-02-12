#pragma once

#include <windows.h>
#include <WinInet.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <wincrypt.h>
#include <Mmsystem.h>
#include <ntsecapi.h>
#include <stdio.h>
#include "Util.h"

extern unsigned char oldWSAStartupHook[LEN_OPCODES_HOOK_FUNCTION];
int WINAPI WSAStartupHook(
	WORD      wVersionRequired,
	LPWSADATA lpWSAData
);

extern unsigned char oldGetaddrinfoHook[LEN_OPCODES_HOOK_FUNCTION];
INT WSAAPI getaddrinfoHook(
	PCSTR           pNodeName,
	PCSTR           pServiceName,
	const ADDRINFOA *pHints,
	PADDRINFOA      *ppResult
);

extern unsigned char oldSocketHook[LEN_OPCODES_HOOK_FUNCTION];
SOCKET WSAAPI socketHook(
	int af,
	int type,
	int protocol
);

extern unsigned char oldConnectHook[LEN_OPCODES_HOOK_FUNCTION];
int WSAAPI connectHook(
	SOCKET         s,
	const sockaddr *name,
	int            namelen
);

extern unsigned char oldClosesocketHook[LEN_OPCODES_HOOK_FUNCTION];
int WSAAPI closesocketHook(
	SOCKET s
);

extern unsigned char oldFreeaddrinfoHook[LEN_OPCODES_HOOK_FUNCTION];
VOID WSAAPI freeaddrinfoHook(
	PADDRINFOA pAddrInfo
);

extern unsigned char oldWSACleanupHook[LEN_OPCODES_HOOK_FUNCTION];
int WINAPI WSACleanupHook();

extern unsigned char oldSendHook[LEN_OPCODES_HOOK_FUNCTION];
int WSAAPI sendHook(
	SOCKET     s,
	const char *buf,
	int        len,
	int        flags
);

extern unsigned char oldShutdownHook[LEN_OPCODES_HOOK_FUNCTION];
int WSAAPI shutdownHook(
	SOCKET s,
	int    how
);

extern unsigned char oldWSAGetLastErrorHook[LEN_OPCODES_HOOK_FUNCTION];
int WINAPI WSAGetLastErrorHook();

extern unsigned char oldRecvHook[LEN_OPCODES_HOOK_FUNCTION];
int WSAAPI recvHook(
	SOCKET s,
	char   *buf,
	int    len,
	int    flags
);

extern unsigned char oldSelectHook[LEN_OPCODES_HOOK_FUNCTION];
int WSAAPI selectHook(
	int           nfds,
	fd_set        *readfds,
	fd_set        *writefds,
	fd_set        *exceptfds,
	const timeval *timeout
);

extern unsigned char oldGethostbynameHook[LEN_OPCODES_HOOK_FUNCTION];
hostent *WSAAPI gethostbynameHook(
	const char *name
);

extern unsigned char OldHtonsHook[LEN_OPCODES_HOOK_FUNCTION];
u_short WINAPI htonsHook(
	u_short hostshort
);

// ************************************************************************************************************
// ADVAPI32 ***************************************************************************************************
extern unsigned char OldHookCryptCreateHash[LEN_OPCODES_HOOK_FUNCTION];
BOOL HookCryptCreateHash(
	HCRYPTPROV hProv,
	ALG_ID     Algid,
	HCRYPTKEY  hKey,
	DWORD      dwFlags,
	HCRYPTHASH *phHash
);

extern unsigned char OldHookGetUserNameA[LEN_OPCODES_HOOK_FUNCTION];
BOOL WINAPI HookGetUserNameA(
	LPSTR   lpBuffer,
	LPDWORD pcbBuffer
);

extern unsigned char OldHookRegOpenKeyExA[LEN_OPCODES_HOOK_FUNCTION];
LSTATUS WINAPI HookRegOpenKeyExA(
	HKEY   hKey,
	LPCSTR lpSubKey,
	DWORD  ulOptions,
	REGSAM samDesired,
	PHKEY  phkResult
);

extern unsigned char OldHookRegSetValueExA[LEN_OPCODES_HOOK_FUNCTION];
LSTATUS WINAPI HookRegSetValueExA(
	HKEY       hKey,
	LPCSTR     lpValueName,
	DWORD      Reserved,
	DWORD      dwType,
	const BYTE *lpData,
	DWORD      cbData
);

extern unsigned char OldHookRegCloseKey[LEN_OPCODES_HOOK_FUNCTION];
LSTATUS WINAPI HookRegCloseKey(
	HKEY hKey
);

// ************************************************************************************************************
// MSVCRT ****************************************************************************************************

extern unsigned char OldHookfopen[LEN_OPCODES_HOOK_FUNCTION];
FILE *Hookfopen(
	const char *filename,
	const char *mode
);

extern unsigned char OldHookfclose[LEN_OPCODES_HOOK_FUNCTION];
int Hookfclose(
	FILE *stream
);

extern unsigned char OldHookfwrite[LEN_OPCODES_HOOK_FUNCTION];
size_t Hookfwrite(
	const void *buffer,
	size_t size,
	size_t count,
	FILE *stream
);

// ************************************************************************************************************
// SHELL32 ****************************************************************************************************

extern unsigned char OldHookShellExecuteA[LEN_OPCODES_HOOK_FUNCTION];
HINSTANCE WINAPI HookShellExecuteA(
	HWND   hwnd,
	LPCSTR lpOperation,
	LPCSTR lpFile,
	LPCSTR lpParameters,
	LPCSTR lpDirectory,
	INT    nShowCmd
);

// ************************************************************************************************************
// WINMM ******************************************************************************************************

extern unsigned char OldHookwaveInOpen[LEN_OPCODES_HOOK_FUNCTION];
MMRESULT WINAPI HookwaveInOpen(
	LPHWAVEIN       phwi,
	UINT            uDeviceID,
	LPCWAVEFORMATEX pwfx,
	DWORD_PTR       dwCallback,
	DWORD_PTR       dwCallbackInstance,
	DWORD           fdwOpen
);

// ************************************************************************************************************
// KERNEL32 ***************************************************************************************************

extern unsigned char OldHookOpenProcess[LEN_OPCODES_HOOK_FUNCTION];
HANDLE WINAPI HookOpenProcess(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
);

extern unsigned char OldHookCreateToolhelp32Snapshot[LEN_OPCODES_HOOK_FUNCTION];
HANDLE WINAPI HookCreateToolhelp32Snapshot(
	DWORD dwFlags,
	DWORD th32ProcessID
);

extern unsigned char OldHookSleep[LEN_OPCODES_HOOK_FUNCTION];
void WINAPI HookSleep(
	DWORD dwMilliseconds
);

extern unsigned char OldHookSleepEx[LEN_OPCODES_HOOK_FUNCTION];
DWORD WINAPI HookSleepEx(
	DWORD dwMilliseconds,
	BOOL  bAlertable
);

extern unsigned char OldHookGetLocalTime[LEN_OPCODES_HOOK_FUNCTION];
void WINAPI HookGetLocalTime(
	LPSYSTEMTIME lpSystemTime
);

extern unsigned char OldHookGetCommandLineA[LEN_OPCODES_HOOK_FUNCTION];
LPSTR WINAPI HookGetCommandLineA();

extern unsigned char OldHookCreatePipe[LEN_OPCODES_HOOK_FUNCTION];
BOOL WINAPI HookCreatePipe(
	PHANDLE               hReadPipe,
	PHANDLE               hWritePipe,
	LPSECURITY_ATTRIBUTES lpPipeAttributes,
	DWORD                 nSize
);

extern unsigned char OldHookCreateProcessA[LEN_OPCODES_HOOK_FUNCTION];
BOOL WINAPI HookCreateProcessA(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
);

extern unsigned char OldHookCreateMutexA[LEN_OPCODES_HOOK_FUNCTION];
HANDLE WINAPI HookCreateMutexA(
	LPSECURITY_ATTRIBUTES lpMutexAttributes,
	BOOL                  bInitialOwner,
	LPCSTR                lpName
);

extern unsigned char OldHookFindFirstFileA[LEN_OPCODES_HOOK_FUNCTION];
HANDLE WINAPI HookFindFirstFileA(
	LPCSTR             lpFileName,
	LPWIN32_FIND_DATAA lpFindFileData
);

extern unsigned char OldHookFindNextFileA[LEN_OPCODES_HOOK_FUNCTION];
BOOL WINAPI HookFindNextFileA(
	HANDLE             hFindFile,
	LPWIN32_FIND_DATAA lpFindFileData
);

extern unsigned char OldHookFindClose[LEN_OPCODES_HOOK_FUNCTION];
BOOL WINAPI HookFindClose(
	HANDLE hFindFile
);

extern unsigned char OldHookCreateDirectoryA[LEN_OPCODES_HOOK_FUNCTION];
BOOL WINAPI HookCreateDirectoryA(
	LPCSTR                lpPathName,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

extern unsigned char OldHookRemoveDirectoryA[LEN_OPCODES_HOOK_FUNCTION];
BOOL WINAPI HookRemoveDirectoryA(
	LPCSTR lpPathName
);

extern unsigned char OldHookCreateFileA[LEN_OPCODES_HOOK_FUNCTION];
HANDLE WINAPI HookCreateFileA(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
);

extern unsigned char OldHookCloseHandle[LEN_OPCODES_HOOK_FUNCTION];
BOOL WINAPI HookCloseHandle(
	_In_ HANDLE hObject
);

extern unsigned char OldHookMoveFileA[LEN_OPCODES_HOOK_FUNCTION];
BOOL WINAPI HookMoveFileA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName
);

extern unsigned char OldHookDeleteFileA[LEN_OPCODES_HOOK_FUNCTION];
BOOL WINAPI HookDeleteFileA(
	LPCSTR lpFileName
);

extern unsigned char OldHookGetDriveTypeA[LEN_OPCODES_HOOK_FUNCTION];
UINT WINAPI HookGetDriveTypeA(
	LPCSTR lpRootPathName
);

extern unsigned char OldHookGetLogicalDrives[LEN_OPCODES_HOOK_FUNCTION];
DWORD WINAPI HookGetLogicalDrives();

extern unsigned char OldHookWinExec[LEN_OPCODES_HOOK_FUNCTION];
UINT WINAPI HookWinExec(
	LPCSTR lpCmdLine,
	UINT   uCmdShow
);

// ************************************************************************************************************
// USER32 *****************************************************************************************************

extern unsigned char OldHookEnumWindows[LEN_OPCODES_HOOK_FUNCTION];
BOOL WINAPI HookEnumWindows(
	WNDENUMPROC lpEnumFunc,
	LPARAM      lParam
);

extern unsigned char OldHookCreateWindowExA[LEN_OPCODES_HOOK_FUNCTION];
HWND WINAPI HookCreateWindowExA(
	DWORD     dwExStyle,
	LPCSTR    lpClassName,
	LPCSTR    lpWindowName,
	DWORD     dwStyle,
	int       X,
	int       Y,
	int       nWidth,
	int       nHeight,
	HWND      hWndParent,
	HMENU     hMenu,
	HINSTANCE hInstance,
	LPVOID    lpParam
);

// ************************************************************************************************************
// MSVCRT *****************************************************************************************************

extern unsigned char Old_beginthreadexHook[LEN_OPCODES_HOOK_FUNCTION];
uintptr_t _beginthreadexHook(
	void *security,
	unsigned stack_size,
	unsigned(__stdcall *start_address)(void *),
	void *arglist,
	unsigned initflag,
	unsigned *thrdaddr
);

// ************************************************************************************************************
// SECUR32 ****************************************************************************************************

extern unsigned char OldHookLsaGetLogonSessionData[LEN_OPCODES_HOOK_FUNCTION];
ULONG WINAPI HookLsaGetLogonSessionData(
	PLUID                        LogonId,
	PSECURITY_LOGON_SESSION_DATA *ppLogonSessionData
);

extern unsigned char OldHookLsaFreeReturnBuffer[LEN_OPCODES_HOOK_FUNCTION];
ULONG WINAPI HookLsaFreeReturnBuffer(
	PVOID Buffer
);

extern unsigned char OldHookLsaEnumerateLogonSessions[LEN_OPCODES_HOOK_FUNCTION];
ULONG WINAPI HookLsaEnumerateLogonSessions(
	PULONG LogonSessionCount,
	PLUID  *LogonSessionList
);