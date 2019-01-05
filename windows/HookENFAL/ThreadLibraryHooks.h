#pragma once

#include <windows.h>
#include <WinInet.h>
#include <winsock.h>

// WININET ****************************************************************************************************
extern unsigned char oldHookInternetOpenA[LEN_OPCODES_HOOK_FUNCTION];
HINTERNET WINAPI HookInternetOpenA(
	LPCSTR lpszAgent,
	DWORD  dwAccessType,
	LPCSTR lpszProxy,
	LPCSTR lpszProxyBypass,
	DWORD  dwFlags
);

extern unsigned char oldHookInternetConnectA[LEN_OPCODES_HOOK_FUNCTION];
HINTERNET WINAPI HookInternetConnectA(
	HINTERNET     hInternet,
	LPCSTR        lpszServerName,
	INTERNET_PORT nServerPort,
	LPCSTR        lpszUserName,
	LPCSTR        lpszPassword,
	DWORD         dwService,
	DWORD         dwFlags,
	DWORD_PTR     dwContext
);

extern unsigned char oldHookInternetOpenUrlA[LEN_OPCODES_HOOK_FUNCTION];
HINTERNET WINAPI HookInternetOpenUrlA(
	HINTERNET hInternet,
	LPCSTR lpszUrl,
	LPCSTR lpszHeaders,
	DWORD dwHeadersLength,
	DWORD dwFlags,
	DWORD_PTR dwContext
);

extern unsigned char OldHookHttpOpenRequestA[LEN_OPCODES_HOOK_FUNCTION];
HINTERNET WINAPI HookHttpOpenRequestA(
	HINTERNET hHttpSession,
	LPCSTR    lpszVerb,
	LPCSTR    lpszObjectName,
	LPCSTR    lpszVersion,
	LPCSTR    lpszReferrer,
	LPCSTR*   lpszAcceptTypes,
	DWORD     dwFlags,
	DWORD_PTR dwContext
);

extern unsigned char OldHookInternetCloseHandle[LEN_OPCODES_HOOK_FUNCTION];
BOOL WINAPI HookInternetCloseHandle(HINTERNET hInternet);

extern unsigned char OldHookHttpSendRequestA[LEN_OPCODES_HOOK_FUNCTION];
BOOL WINAPI HookHttpSendRequestA(
	HINTERNET hRequest,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	LPVOID    lpOptional,
	DWORD     dwOptionalLength
);

extern unsigned char OldHookInternetReadFile[LEN_OPCODES_HOOK_FUNCTION];
BOOL WINAPI HookInternetReadFile(
	HINTERNET hFile,
	LPVOID    lpBuffer,
	DWORD     dwNumberOfBytesToRead,
	LPDWORD   lpdwNumberOfBytesRead
);
// ************************************************************************************************************
// ADVAPI32 ***************************************************************************************************
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
// KERNEL32 ***************************************************************************************************
extern unsigned char OldHookFindFirstFileA[LEN_OPCODES_HOOK_FUNCTION];
HANDLE WINAPI HookFindFirstFileA(
	LPCSTR             lpFileName,
	LPWIN32_FIND_DATAA lpFindFileData
);

extern unsigned char OldHookFindNextFileA[LEN_OPCODES_HOOK_FUNCTION];
HANDLE WINAPI HookFindNextFileA(
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
// ws2_32 *****************************************************************************************************
extern unsigned char OldHookHtons[LEN_OPCODES_HOOK_FUNCTION];
u_short WINAPI HookHtons(
	u_short hostshort
);

// ************************************************************************************************************
// log only ***************************************************************************************************

extern unsigned char OldWrapperLoadLibraryA[LEN_OPCODES_HOOK_FUNCTION];
HMODULE WINAPI WrapperLoadLibraryA(
	LPCSTR lpLibFileName
);

extern unsigned char OldWrapperGetProcAddress[LEN_OPCODES_HOOK_FUNCTION];
// extern funcpointer OldGetProcAddress;
FARPROC WINAPI WrapperGetProcAddress(
	HMODULE hModule,
	LPCSTR  lpProcName
);
