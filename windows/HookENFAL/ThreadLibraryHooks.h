#pragma once

#include <windows.h>
#include <WinInet.h>

extern unsigned char oldHookInternetOpenA[LEN_OPCODES_HOOK_FUNCTION];
HINTERNET WINAPI HookInternetOpenA(
	LPCSTR lpszAgent,
	DWORD  dwAccessType,
	LPCSTR lpszProxy,
	LPCSTR lpszProxyBypass,
	DWORD  dwFlags
);

extern unsigned char oldHookInternetConnect[LEN_OPCODES_HOOK_FUNCTION];
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