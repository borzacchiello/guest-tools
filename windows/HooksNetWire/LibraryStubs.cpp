#include "stdafx.h"
#include <iostream>
#include <intrin.h>
#include "Util.h"
#include "LibraryStubs.h"
#include "Common.h"

#pragma intrinsic(_ReturnAddress)
#define USER_APP
extern "C" {
#include <s2e/s2e.h>
}

unsigned char oldWSAStartupHook[LEN_OPCODES_HOOK_FUNCTION];
int WINAPI WSAStartupHook(
	WORD      wVersionRequired,
	LPWSADATA lpWSAData
) {
	char* hex_WSAData = NULL;
	Message("WSAStartup called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic((LPVOID)&wVersionRequired, 1))
		S2EPrintExpression(wVersionRequired, "  [WSAStartup] 0: ");
	else
		Message("  [WSAStartup] 0: %d\n", wVersionRequired);

	if (S2EIsSymbolic((LPVOID)&lpWSAData, 1))
		S2EPrintExpression((UINT_PTR)lpWSAData, "  [WSAStartup] 1: ");
	else {
		Message("  [WSAStartup] 1: 0x%x\n", lpWSAData);
		if (S2EIsSymbolic((LPVOID)lpWSAData, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpWSAData), "  [WSAStartup] *1: ");
		else {
			hex_WSAData = data_to_hex_string((char*)lpWSAData, sizeof(lpWSAData));
			Message("  [WSAStartup] *1:%s\n", hex_WSAData);
		}
	}
#else
	Message("  [WSAStartup] 0: %d\n", wVersionRequired);
	Message("  [WSAStartup] 1: 0x%x\n", lpWSAData);
	hex_WSAData = data_to_hex_string((char*)lpWSAData, sizeof(lpWSAData));
	Message("  [WSAStartup] *1:%s\n", hex_WSAData);
#endif
	Message("  [WSAStartup] ret: 0\n");
	if (hex_WSAData != NULL)
		free(hex_WSAData);
	return 0;
}

unsigned char oldGetaddrinfoHook[LEN_OPCODES_HOOK_FUNCTION];
INT WSAAPI getaddrinfoHook(
	PCSTR           pNodeName,
	PCSTR           pServiceName,
	const ADDRINFOA *pHints,
	PADDRINFOA      *ppResult
) {
	char* hex_pHints = NULL;
	Message("getaddrinfo called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&pNodeName, 1))
		S2EPrintExpression((UINT_PTR)pNodeName, "[getaddrinfo] 0: ");
	else {
		Message("  [getaddrinfo] 0: 0x%x\n", pNodeName);
		if (S2EIsSymbolic((PVOID)pNodeName, 1))
			S2EPrintExpression((UINT_PTR)*pNodeName, "[getaddrinfo] *0: ");
		else
			Message("  [getaddrinfo] *0: %s\n", pNodeName);

	}
	if (S2EIsSymbolic(&pServiceName, 1))
		S2EPrintExpression((UINT_PTR)pServiceName, "[getaddrinfo] 1: ");
	else {
		Message("  [getaddrinfo] 1: 0x%x\n", pServiceName);
		if (S2EIsSymbolic((PVOID)pServiceName, 1))
			S2EPrintExpression((UINT_PTR)*pServiceName, "[getaddrinfo] *1: ");
		else
			Message("  [getaddrinfo] *1: %s\n", pServiceName);
	}
	if (S2EIsSymbolic(&pHints, 1))
		S2EPrintExpression((UINT_PTR)pHints, "[getaddrinfo] 2: ");
	else {
		Message("  [getaddrinfo] 2: 0x%x\n", pHints);
		if (S2EIsSymbolic((PVOID)pHints, 1))
			S2EPrintExpression((UINT_PTR)*((char*)pHints), "[getaddrinfo] *2: ");
		else {
			hex_pHints = data_to_hex_string((char*)pHints, sizeof(ADDRINFO));
			Message("  [getaddrinfo] *2: %s\n", hex_pHints);
		}

	}
	if (S2EIsSymbolic(&ppResult, 1))
		S2EPrintExpression((UINT_PTR)ppResult, "[getaddrinfo] 3: ");
	else
		Message("  [getaddrinfo] 3: 0x%x\n", ppResult);
#else
	hex_pHints = data_to_hex_string((char*)pHints, sizeof(ADDRINFO));
	Message("  [getaddrinfo] 0: 0x%x\n", pNodeName);
	Message("  [getaddrinfo] *0: %s\n", pNodeName);
	Message("  [getaddrinfo] 1: 0x%x\n", pServiceName);
	Message("  [getaddrinfo] *1: %s\n", pServiceName);
	Message("  [getaddrinfo] 2: 0x%x\n", pHints);
	Message("  [getaddrinfo] *2: %s\n", hex_pHints);
	Message("  [getaddrinfo] 3: 0x%x\n", ppResult);
#endif
	ADDRINFOA* ris = new ADDRINFOA(*pHints);
	*ppResult = ris;
	Message("  [getaddrinfo] ret: 0\n");
	if (hex_pHints != NULL) free(hex_pHints);
	return 0;
}

int i = 0;
int rets[] = { 0xdeadbeef, 0xcafecafe };
unsigned char oldSocketHook[LEN_OPCODES_HOOK_FUNCTION];
SOCKET WSAAPI socketHook(
	int af,
	int type,
	int protocol
)
{
	Message("socket called by 0x%x.\n", _ReturnAddress());
#if S2E

	if (S2EIsSymbolic(&af, 1))
		S2EPrintExpression((UINT_PTR)af, "[socket] 0: ");
	else
		Message("  [socket] 0: 0x%x\n", af);
	if (S2EIsSymbolic(&type, 1))
		S2EPrintExpression((UINT_PTR)type, "[socket] 1: ");
	else
		Message("  [socket] 1: 0x%x\n", type);
	if (S2EIsSymbolic(&protocol, 1))
		S2EPrintExpression((UINT_PTR)protocol, "[socket] 2: ");
	else
		Message("  [socket] 2: 0x%x\n", protocol);
#else

	Message("  [socket] 0: 0x%x\n", af);
	Message("  [socket] 1: 0x%x\n", type);
	Message("  [socket] 2: 0x%x\n", protocol);
#endif


	Message("  [socket] ret: 0x%x\n", rets[0]);
	return rets[0];
}


unsigned char oldConnectHook[LEN_OPCODES_HOOK_FUNCTION];
int WSAAPI connectHook(
	SOCKET         s,
	const sockaddr *name,
	int            namelen
)
{
	char* hex_name = NULL;

	Message("connect called by 0x%x.\n", _ReturnAddress());
#if S2E

	if (S2EIsSymbolic(&s, 1))
		S2EPrintExpression((UINT_PTR)s, "[connect] 0: ");
	else
		Message("  [connect] 0: 0x%x\n", s);
	if (S2EIsSymbolic(&name, 1))
		S2EPrintExpression((UINT_PTR)name, "[connect] 1: ");
	else {
		Message("  [connect] 1: 0x%x\n", name);
		if (S2EIsSymbolic((PVOID)name, 1))
			S2EPrintExpression((UINT_PTR)*((char*)name), "[connect] *1: ");
		else if (!S2EIsSymbolic(&namelen, 1)) {
			hex_name = data_to_hex_string((char*)name, namelen);
			Message("  [connect] *1: %s\n", hex_name);
		}
	}
	if (S2EIsSymbolic(&namelen, 1))
		S2EPrintExpression((UINT_PTR)namelen, "[connect] 2: ");
	else
		Message("  [connect] 2: 0x%x\n", namelen);
#else

	Message("  [connect] 0: 0x%x\n", s);
	Message("  [connect] 1: 0x%x\n", name);
	hex_name = data_to_hex_string((char*)name, namelen);
	Message("  [connect] *1: %s\n", hex_name);
	Message("  [connect] 2: 0x%x\n", namelen);
#endif

	if (hex_name != NULL) free(hex_name);

	Message("  [connect] ret: 0\n");
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
)
{
	char* hex_buf = NULL;

	Message("send called by 0x%x.\n", _ReturnAddress());
#if S2E

	if (S2EIsSymbolic(&s, 1))
		S2EPrintExpression((UINT_PTR)s, "[send] 0: ");
	else
		Message("  [send] 0: 0x%x\n", s);
	if (S2EIsSymbolic(&buf, 1))
		S2EPrintExpression((UINT_PTR)buf, "[send] 1: ");
	else {
		Message("  [send] 1: 0x%x\n", buf);
		if (S2EIsSymbolic((PVOID)buf, 1))
			S2EPrintExpression((UINT_PTR)*((char*)buf), "[send] *1: ");
		else {
			hex_buf = data_to_hex_string((char*)buf, len);
			Message("  [send] *1: %s\n", hex_buf);
		}
	}
	if (S2EIsSymbolic(&len, 1))
		S2EPrintExpression((UINT_PTR)len, "[send] 2: ");
	else
		Message("  [send] 2: 0x%x\n", len);
	if (S2EIsSymbolic(&flags, 1))
		S2EPrintExpression((UINT_PTR)flags, "[send] 3: ");
	else
		Message("  [send] 3: 0x%x\n", flags);
#else

	Message("  [send] 0: 0x%x\n", s);
	Message("  [send] 1: 0x%x\n", buf);
	hex_buf = data_to_hex_string((char*)buf, len);
	Message("  [send] *1:%s\n", hex_buf);
	Message("  [send] 2: 0x%x\n", len);
	Message("  [send] 3: 0x%x\n", flags);
#endif

	free(hex_buf);

	Message("  [send] ret: %d\n", len);
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
)
{
	char* hex_buf = NULL;

	Message("recv called by 0x%x.\n", _ReturnAddress());
#if S2E

	if (S2EIsSymbolic(&s, 1))
		S2EPrintExpression((UINT_PTR)s, "[recv] 0: ");
	else
		Message("  [recv] 0: 0x%x\n", s);
	if (S2EIsSymbolic(&buf, 1))
		S2EPrintExpression((UINT_PTR)buf, "[recv] 1: ");
	else
		Message("  [recv] 1: 0x%x\n", buf);
	if (S2EIsSymbolic(&len, 1))
		S2EPrintExpression((UINT_PTR)len, "[recv] 2: ");
	else
		Message("  [recv] 2: 0x%x\n", len);
	if (S2EIsSymbolic(&flags, 1))
		S2EPrintExpression((UINT_PTR)flags, "[recv] 3: ");
	else
		Message("  [recv] 3: 0x%x\n", flags);
#else

	Message("  [recv] 0: 0x%x\n", s);
	Message("  [recv] 1: 0x%x\n", buf);
	Message("  [recv] 2: 0x%x\n", len);
	Message("  [recv] 3: 0x%x\n", flags);
#endif

#if S2E
	if (S2EIsSymbolic((PVOID)&len, 4)) {
		// S2EPrintExpression(len, "symb_len");
		if (len > 0x45) S2EKillState(0, "limit len");
		else      		S2EConcretize(&len, 4);
		// S2EAssume(len = 0x41);
		Message("  [recv] Concretizing len to %d\n", len);
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
		buf[0] = 0x1c;
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
)
{
	char* hex_readfds = NULL;
	char* hex_writefds = NULL;
	char* hex_exceptfds = NULL;
	char* hex_timeout = NULL;

	Message("select called by 0x%x.\n", _ReturnAddress());
#if S2E

	if (S2EIsSymbolic(&nfds, 1))
		S2EPrintExpression((UINT_PTR)nfds, "[select] 0: ");
	else
		Message("  [select] 0: 0x%x\n", nfds);
	if (S2EIsSymbolic(&readfds, 1))
		S2EPrintExpression((UINT_PTR)readfds, "[select] 1: ");
	else {
		Message("  [select] 1: 0x%x\n", readfds);
		if (S2EIsSymbolic((PVOID)readfds, 1))
			S2EPrintExpression((UINT_PTR)*((char*)readfds), "[select] *1: ");
		else {
			hex_readfds = data_to_hex_string((char*)readfds, sizeof(readfds));
			Message("  [select] *1: %s\n", hex_readfds);
		}
	}
	if (S2EIsSymbolic(&writefds, 1))
		S2EPrintExpression((UINT_PTR)writefds, "[select] 2: ");
	else {
		Message("  [select] 2: 0x%x\n", writefds);
		if (S2EIsSymbolic((PVOID)writefds, 1))
			S2EPrintExpression((UINT_PTR)*((char*)writefds), "[select] *2: ");
		else {
			hex_writefds = data_to_hex_string((char*)writefds, sizeof(writefds));
			Message("  [select] *2: %s\n", hex_writefds);
		}
	}
	if (S2EIsSymbolic(&exceptfds, 1))
		S2EPrintExpression((UINT_PTR)exceptfds, "[select] 3: ");
	else {
		Message("  [select] 3: 0x%x\n", exceptfds);
		if (S2EIsSymbolic((PVOID)exceptfds, 1))
			S2EPrintExpression((UINT_PTR)*((char*)exceptfds), "[select] *3: ");
		else {
			hex_exceptfds = data_to_hex_string((char*)exceptfds, sizeof(exceptfds));
			Message("  [select] *3: %s\n", hex_exceptfds);
		}
	}
	if (S2EIsSymbolic(&timeout, 1))
		S2EPrintExpression((UINT_PTR)timeout, "[select] 4: ");
	else {
		Message("  [select] 4: 0x%x\n", timeout);
		if (S2EIsSymbolic((PVOID)timeout, 1))
			S2EPrintExpression((UINT_PTR)*((char*)timeout), "[select] *4: ");
		else {
			hex_timeout = data_to_hex_string((char*)timeout, sizeof(timeout));
			Message("  [select] *4: %s\n", hex_timeout);
		}
	}
#else

	Message("  [select] 0: 0x%x\n", nfds);
	Message("  [select] 1: 0x%x\n", readfds);
	hex_readfds = data_to_hex_string((char*)readfds, sizeof(readfds));
	Message("  [select] *1: %s\n", hex_readfds);
	Message("  [select] 2: 0x%x\n", writefds);
	hex_writefds = data_to_hex_string((char*)writefds, sizeof(writefds));
	Message("  [select] *2: %s\n", hex_writefds);
	Message("  [select] 3: 0x%x\n", exceptfds);
	hex_exceptfds = data_to_hex_string((char*)exceptfds, sizeof(exceptfds));
	Message("  [select] *3: %s\n", hex_exceptfds);
	Message("  [select] 4: 0x%x\n", timeout);
	hex_timeout = data_to_hex_string((char*)timeout, sizeof(timeout));
	Message("  [select] *4: %s\n", hex_timeout);
#endif

	free(hex_readfds);
	free(hex_writefds);
	free(hex_exceptfds);
	free(hex_timeout);

	Message("  [select] ret: 1\n");
	return 1;
}

unsigned char oldGethostbynameHook[LEN_OPCODES_HOOK_FUNCTION];
hostent *WSAAPI gethostbynameHook(
	const char *name
)
{
	Message("gethostbyname called by 0x%x.\n", _ReturnAddress());
#if S2E

	if (S2EIsSymbolic(&name, 1))
		S2EPrintExpression((UINT_PTR)name, "[gethostbyname] 0: ");
	else {
		Message("  [gethostbyname] 0: 0x%x\n", name);
		if (S2EIsSymbolic((PVOID)name, 1))
			S2EPrintExpression((UINT_PTR)*((char*)name), "[gethostbyname] *0: ");
		else {
			Message("  [gethostbyname] *0: %s\n", name);
		}
	}
#else

	Message("  [gethostbyname] 0: 0x%x\n", name);
	Message("  [gethostbyname] *0: %s\n", name);
#endif

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

	char* hex_ris = data_to_hex_string((char*)ris, sizeof(ris));
	Message("  [gethostbyname] ret: %s\n", hex_ris);
	free(hex_ris);
	return ris;
}

unsigned char OldHtonsHook[LEN_OPCODES_HOOK_FUNCTION];
u_short WINAPI htonsHook(
	u_short hostshort
)
{
	Message("htons called by 0x%x.\n", _ReturnAddress());
#if S2E

	if (S2EIsSymbolic(&hostshort, 1))
		S2EPrintExpression((UINT_PTR)hostshort, "[htons] 0: ");
	else
		Message("  [htons] 0: 0x%x\n", hostshort);
#else
	Message("  [htons] 0: 0x%x\n", hostshort);
#endif
	Message("  [htons] ret: 0\n");
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
	*phkResult = (HKEY)0xcafecafe; // dummy handle
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
	char* hex_lpSecurityAttributes = NULL;
	Message("CreateDirectoryA called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic((LPVOID)&lpPathName, 1)) 
		S2EPrintExpression((UINT_PTR)lpPathName, "[CreateDirectoryA] 0: ");
	else {
		Message("  [CreateDirectoryA] 0: 0x%x\n", lpPathName);
		if (S2EIsSymbolic((LPVOID)lpPathName, 1)) 
			S2EPrintExpression(*lpPathName, "[CreateDirectoryA] *0: ");
		else
			Message("  [CreateDirectoryA] *0: %s\n", lpPathName);
	}
	if (S2EIsSymbolic((LPVOID)&lpSecurityAttributes, 1))
		S2EPrintExpression((UINT_PTR)lpSecurityAttributes, "[CreateDirectoryA] 1: ");
	else {
		Message("  [CreateDirectoryA] 1: 0x%x\n", lpSecurityAttributes);
		if (S2EIsSymbolic((LPVOID)lpSecurityAttributes, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpSecurityAttributes), "[CreateDirectoryA] *1: ");
		else {
			hex_lpSecurityAttributes = data_to_hex_string((char*)lpSecurityAttributes, sizeof(lpSecurityAttributes));
			Message("  [CreateDirectoryA] *1: %s\n", hex_lpSecurityAttributes);
		}
	}
#else
	Message("  [CreateDirectoryA] 0: 0x%x\n", lpPathName);
	Message("  [CreateDirectoryA] *0: %s\n", lpPathName);
	Message("  [CreateDirectoryA] 1: 0x%x\n", lpSecurityAttributes);
	hex_lpSecurityAttributes = data_to_hex_string((char*)lpSecurityAttributes, sizeof(lpSecurityAttributes));
	Message("  [CreateDirectoryA] *1: %s\n", hex_lpSecurityAttributes);
#endif
	if (hex_lpSecurityAttributes != NULL)
		free(hex_lpSecurityAttributes);
	Message("  [CreateDirectoryA] ret: 0\n");
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

