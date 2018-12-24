#include "stdafx.h"
#include "Util.h"
#include "ThreadLibraryHooks.h"
#include <set>

/// Keep track of dummy Internet handles that we've created
static std::set<HINTERNET> dummyHandles;

// WININET ****************************************************************************************************
unsigned char oldHookInternetOpenA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
HINTERNET WINAPI HookInternetOpenA (
	LPCSTR lpszAgent,
	DWORD  dwAccessType,
	LPCSTR lpszProxy,
	LPCSTR lpszProxyBypass,
	DWORD  dwFlags
)
{
	Message("HookInternetOpenA intercepted. Agent: %s\n", lpszAgent);
	HINTERNET resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));

	// Record the dummy handle so we can clean up afterwards
	dummyHandles.insert(resourceHandle);

	return resourceHandle;
}

unsigned char oldHookInternetConnectA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
HINTERNET WINAPI HookInternetConnectA (
	HINTERNET     hInternet,
	LPCSTR        lpszServerName,
	INTERNET_PORT nServerPort,
	LPCSTR        lpszUserName,
	LPCSTR        lpszPassword,
	DWORD         dwService,
	DWORD         dwFlags,
	DWORD_PTR     dwContext
)
{
	Message("Intercepted InternetConnectA(%p, %s, %hu, %s, %s, %d, &d, %p)",
		hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
	HINTERNET resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));
	// Record the dummy handle so we can clean up afterwards
	dummyHandles.insert(resourceHandle);
	return resourceHandle;
}

unsigned char oldHookInternetOpenUrlA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
HINTERNET WINAPI HookInternetOpenUrlA(
	HINTERNET hInternet,
	LPCSTR lpszUrl,
	LPCSTR lpszHeaders,
	DWORD dwHeadersLength,
	DWORD dwFlags,
	DWORD_PTR dwContext
) 
{
	Message("Intercepted InternetOpenUrlA(%p, %s, %s, 0x%x, 0x%x, %p)\n",
		hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);

	HINTERNET resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));

	// Record the dummy handle so we can clean up afterwards
	dummyHandles.insert(resourceHandle);

	return resourceHandle;
}

unsigned char OldHookInternetCloseHandle[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookInternetCloseHandle(HINTERNET hInternet) 
{
	Message("Intercepted InternetCloseHandle(%p)\n", hInternet);

	std::set<HINTERNET>::iterator it = dummyHandles.find(hInternet);

	if (it == dummyHandles.end()) {
		// The handle is not one of our dummy handles, so return false
		return FALSE;
	}
	else {
		// The handle is a dummy handle. Free it
		free(*it);
		dummyHandles.erase(it);

		return TRUE;
	}
}

unsigned char OldHookHttpOpenRequestA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
HINTERNET WINAPI HookHttpOpenRequestA(
	HINTERNET hHttpSession,
	LPCSTR    lpszVerb,
	LPCSTR    lpszObjectName,
	LPCSTR    lpszVersion,
	LPCSTR    lpszReferrer,
	LPCSTR*   lpszAcceptTypes,
	DWORD     dwFlags,
	DWORD_PTR dwContext
)
{
	Message("Intercepted HttpOpenRequestA(%p, %s, %s, %s, %s, 0x%x, %p)\n",
		hHttpSession, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, dwFlags, dwContext);

	HINTERNET resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));
	// Record the dummy handle so we can clean up afterwards
	dummyHandles.insert(resourceHandle);
	return resourceHandle;
}

unsigned char OldHookHttpSendRequestA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookHttpSendRequestA(
	HINTERNET hRequest,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	LPVOID    lpOptional,
	DWORD     dwOptionalLength
) 
{
	Message("Intercepted HttpSendRequestA(%p, %s, %d, %d)\n",
		hRequest, lpszHeaders, dwHeadersLength, dwOptionalLength);
	return TRUE;
}

DWORD callCounter = 0;
unsigned char OldHookInternetReadFile[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookInternetReadFile(
	HINTERNET hFile,
	LPVOID    lpBuffer,
	DWORD     dwNumberOfBytesToRead,
	LPDWORD   lpdwNumberOfBytesRead
) 
{
	Message("Intercepted InternetReadFile(%p, %p, %d, %p)\n",
		hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
	
	*lpdwNumberOfBytesRead = dwNumberOfBytesToRead;
	memset(lpBuffer, 0, dwNumberOfBytesToRead);

	if (callCounter == 0) {
		char buff[50];
		char* inbuff = (char*)lpBuffer;
		sprintf(buff, "InternetReadFile_%d", callCounter++);
		S2EMakeConcolic(inbuff, 16, buff);   // passing a stack variable should be safe
		S2EAssume(inbuff[8] == (20 ^ 0x45)); // otherwise, symbolic write...
	}

	return TRUE;
}

// ************************************************************************************************************
// ADVAPI32 ***************************************************************************************************

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
	Message("Intercepted RegOpenKeyExA(%08x, %s, %d)\n",
		hKey, lpSubKey, ulOptions);
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
	Message("Intercepted RegSetValueExA(%08x, %s)\n",
		hKey, lpValueName);
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
	Message("Intercepted FindFirstFileA(%s, %08x)\n", 
		lpFileName, lpFindFileData);

	return INVALID_HANDLE_VALUE; // fail
}

unsigned char OldHookFindNextFileA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
HANDLE WINAPI HookFindNextFileA(
	HANDLE             hFindFile,
	LPWIN32_FIND_DATAA lpFindFileData
)
{
	Message("Intercepted FindNextFileA(%08x, %08x)\n",
		hFindFile, lpFindFileData);

	return 0x0; // fail
}

unsigned char OldHookFindClose[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookFindClose(
	HANDLE hFindFile
)
{
	Message("Intercepted FindClose(%08x)\n",
		hFindFile);
	return TRUE;
}

unsigned char OldHookCreateDirectoryA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookCreateDirectoryA(
	LPCSTR                lpPathName,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
)
{
	Message("Intercepted CreateDirectoryA(%s, %08x)\n",
		lpPathName, lpSecurityAttributes);
	return FALSE;
}

unsigned char OldHookRemoveDirectoryA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookRemoveDirectoryA(
	LPCSTR lpPathName
)
{
	Message("Intercepted RemoveDirectoryA(%s)\n",
		lpPathName);
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
	Message("Intercepted CreateFileA(%s)\n",
		lpFileName);
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
	Message("Intercepted MoveFileA(%s, %s)\n",
		lpExistingFileName, lpNewFileName);
	return FALSE;
}

unsigned char OldHookDeleteFileA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookDeleteFileA(
	LPCSTR lpFileName
)
{
	Message("Intercepted DeleteFileA(%s)\n",
		lpFileName);
	return FALSE;
}

unsigned char OldHookGetDriveTypeA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
UINT WINAPI HookGetDriveTypeA(
	LPCSTR lpRootPathName
)
{
	Message("Intercepted GetDriveTypeA(%s)\n",
		lpRootPathName);
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
	Message("HookWinExec(%s, %d)\n",
		lpCmdLine, uCmdShow);
	return 32;
}

// ************************************************************************************************************
