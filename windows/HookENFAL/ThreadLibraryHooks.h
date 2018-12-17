#pragma once

#include <windows.h>
#include <WinInet.h>

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
HINTERNET HookInternetConnectA(
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
LSTATUS HookRegOpenKeyExA(
	HKEY   hKey,
	LPCSTR lpSubKey,
	DWORD  ulOptions,
	REGSAM samDesired,
	PHKEY  phkResult
);

extern unsigned char OldHookRegSetValueExA[LEN_OPCODES_HOOK_FUNCTION];
LSTATUS HookRegSetValueExA(
	HKEY       hKey,
	LPCSTR     lpValueName,
	DWORD      Reserved,
	DWORD      dwType,
	const BYTE *lpData,
	DWORD      cbData
);

extern unsigned char OldHookRegCloseKey[LEN_OPCODES_HOOK_FUNCTION];
LSTATUS HookRegCloseKey(
	HKEY hKey
);
// ************************************************************************************************************
// KERNEL32 ***************************************************************************************************
extern unsigned char OldHookFindFirstFileA[LEN_OPCODES_HOOK_FUNCTION];
HANDLE HookFindFirstFileA(
	LPCSTR             lpFileName,
	LPWIN32_FIND_DATAA lpFindFileData
);

extern unsigned char OldHookFindNextFileA[LEN_OPCODES_HOOK_FUNCTION];
HANDLE HookFindNextFileA(
	HANDLE             hFindFile,
	LPWIN32_FIND_DATAA lpFindFileData
);

extern unsigned char OldHookFindClose[LEN_OPCODES_HOOK_FUNCTION];
BOOL HookFindClose(
	HANDLE hFindFile
);

extern unsigned char OldHookCreateDirectoryA[LEN_OPCODES_HOOK_FUNCTION];
BOOL HookCreateDirectoryA(
	LPCSTR                lpPathName,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

extern unsigned char OldHookRemoveDirectoryA[LEN_OPCODES_HOOK_FUNCTION];
BOOL HookRemoveDirectoryA(
	LPCSTR lpPathName
);

extern unsigned char OldHookMoveFileA[LEN_OPCODES_HOOK_FUNCTION];
BOOL HookMoveFileA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName
);

extern unsigned char OldHookDeleteFileA[LEN_OPCODES_HOOK_FUNCTION];
BOOL HookDeleteFileA(
	LPCSTR lpFileName
);

extern unsigned char OldHookGetDriveTypeA[LEN_OPCODES_HOOK_FUNCTION];
UINT HookGetDriveTypeA(
	LPCSTR lpRootPathName
);

extern unsigned char OldHookGetLogicalDrives[LEN_OPCODES_HOOK_FUNCTION];
DWORD HookGetLogicalDrives();

extern unsigned char OldHookWinExec[LEN_OPCODES_HOOK_FUNCTION];
UINT HookWinExec(
	LPCSTR lpCmdLine,
	UINT   uCmdShow
);

// ************************************************************************************************************
