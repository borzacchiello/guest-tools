#include "stdafx.h"
#include "Util.h"
#include "ThreadLibraryHooks.h"
#include <set>

/// Keep track of dummy Internet handles that we've created
static std::set<HINTERNET> dummyHandles;


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

unsigned char oldHookInternetConnect[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
HINTERNET HookInternetConnectA (
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
	Message("Intercepted HookInternetConnectA(%p, %s, %hu, %s, %s, %d, &d, %p)",
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

	// UINT8 returnResource = S2EConcolicChar("hInternet", 1);

	// Explore the program when InternetOpenUrlA "succeeds" by returning a
	// dummy resource handle. Because we know that the resource handle is
	// never used, we don't have to do anything fancy to create it.
	// However, we will need to keep track of it so we can free it when the
	// handle is closed.
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
	Message("Intercepted HookHttpSendRequestA(%p, %s, %d, %d)\n",
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
	Message("Intercepted HookInternetReadFile(%p, %p, %d, %p)\n",
		hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);

	if (callCounter > 0) 
		exit(1);
	
	*lpdwNumberOfBytesRead = dwNumberOfBytesToRead;
	memset(lpBuffer, 0, dwNumberOfBytesToRead);

	char buff[50];
	sprintf(buff, "InternetReadFile_%d", callCounter++);
	S2EMakeConcolic(lpBuffer, dwNumberOfBytesToRead, buff); // passing a stack variable should be safe

	return TRUE;
}

