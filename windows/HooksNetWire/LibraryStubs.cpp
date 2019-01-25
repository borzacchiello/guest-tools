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
	Message("closesocket called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&s, 1))
		S2EPrintExpression((UINT_PTR)s, "[closesocket] 0: ");
	else
		Message("  [closesocket] 0: 0x%x\n", s);
#else
	Message("  [closesocket] 0: 0x%x\n", s);
#endif

	Message("  [closesocket] ret: 0\n");
	return 0;
}


unsigned char oldFreeaddrinfoHook[LEN_OPCODES_HOOK_FUNCTION];
VOID WSAAPI freeaddrinfoHook(
	PADDRINFOA pAddrInfo
) {
    char* hex_pAddrInfo = NULL;
    Message("freeaddrinfo called by 0x%x.\n", _ReturnAddress());
#if S2E
    if (S2EIsSymbolic(&pAddrInfo, 1))
        S2EPrintExpression((UINT_PTR)pAddrInfo, "[freeaddrinfo] 0: ");
    else 
        Message("  [freeaddrinfo] 0: 0x%x\n",  pAddrInfo);
#else
    Message("  [freeaddrinfo] 0: 0x%x\n",  pAddrInfo);
#endif
}


unsigned char oldWSACleanupHook[LEN_OPCODES_HOOK_FUNCTION];
int WINAPI WSACleanupHook() {
	Message("WSACleanupHook called by 0x%x.\n", _ReturnAddress());
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
	Message("shutdown called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&s, 1))
		S2EPrintExpression((UINT_PTR)s, "[shutdown] 0: ");
	else
		Message("  [shutdown] 0: 0x%x\n", s);
	if (S2EIsSymbolic(&how, 1))
		S2EPrintExpression((UINT_PTR)how, "[shutdown] 1: ");
	else
		Message("  [shutdown] 1: 0x%x\n", how);
#else
	Message("  [shutdown] 0: 0x%x\n", s);
	Message("  [shutdown] 1: 0x%x\n", how);
#endif

	Message("  [shutdown] ret: 0\n");
	return 0;
}


unsigned char oldWSAGetLastErrorHook[LEN_OPCODES_HOOK_FUNCTION];
int WINAPI WSAGetLastErrorHook() {
	Message("WSAGetLastError called by 0x%x.\n", _ReturnAddress());
	Message("  [WSAGetLastError] ret: 42\n");
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
	}
	else if (callCounter == 1) {
		callCounter++;
		Message("KEY\n");
		// extracted using SE (TARGET: 0x040D3AD; AVOID: 0x040D3B6). First recv {0x41, 0x0, 0x0, 0x0}
		unsigned char tmp[] = { 0x5, 0x0, 0x0, 0x1, 0x4, 0x1, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x4, 0x1, 0x4, 0x0, 0x1, 0x4, 0x5, 0x10, 0x10, 0x7, 0x1d, 0x4, 0x2, 0x8f, 0xd2, 0xb, 0xcb, 0x42, 0x16, 0x36, 0x25, 0x65, 0x35, 0xfd, 0x4e, 0xa6, 0x98, 0xa, 0x41, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
		memcpy(buf, tmp, 0x41);
		// S2EMakeConcolic(buf, len, "recv_buf");
		// buf[0] = 0x5;
	}
	else {
#if S2E
		char name[50];
		sprintf(name, "recv_%d", callCounter++);
		S2EMakeConcolic(buf, len, name);   // passing a stack variable should be safe
#else
		if (len == 4)
			buf[0] = 0x6;
		else {
			buf[0] = 0x18;
			buf[1] = 0x4d;
			buf[2] = 0xda;
			buf[3] = 0x21;
			buf[4] = 0x51;
			buf[5] = 0x18;
		}
		callCounter++;
#endif
	}
	char* hex_tmp = NULL;
#if S2E
	if (S2EIsSymbolic(buf, 1))
		S2EPrintExpression((UINT_PTR)*buf, "[recv] write *1:");
	else {
		hex_tmp = data_to_hex_string((char*)buf, len);
		Message("  [recv] write *1: %s\n", hex_tmp);
	}
#else
	hex_tmp = data_to_hex_string((char*)buf, len);
	Message("  [recv] write *1: %s\n", hex_tmp);
#endif
	Message("  [recv] ret: %d\n", len);
	free(hex_tmp);
	return len;
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


// ************************************************************************************************************
// ADVAPI32 ***************************************************************************************************

unsigned char OldHookCryptCreateHash[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL HookCryptCreateHash(
	HCRYPTPROV hProv,
	ALG_ID     Algid,
	HCRYPTKEY  hKey,
	DWORD      dwFlags,
	HCRYPTHASH *phHash
)
{
	char* hex_phHash = NULL;
	Message("CryptCreateHash called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&hProv, 1))
		S2EPrintExpression((UINT_PTR)hProv, "[CryptCreateHash] 0: ");
	else
		Message("  [CryptCreateHash] 0: 0x%x\n", hProv);
	if (S2EIsSymbolic(&Algid, 1))
		S2EPrintExpression((UINT_PTR)Algid, "[CryptCreateHash] 1: ");
	else
		Message("  [CryptCreateHash] 1: 0x%x\n", Algid);
	if (S2EIsSymbolic(&hKey, 1))
		S2EPrintExpression((UINT_PTR)hKey, "[CryptCreateHash] 2: ");
	else
		Message("  [CryptCreateHash] 2: 0x%x\n", hKey);
	if (S2EIsSymbolic(&dwFlags, 1))
		S2EPrintExpression((UINT_PTR)dwFlags, "[CryptCreateHash] 3: ");
	else
		Message("  [CryptCreateHash] 3: 0x%x\n", dwFlags);
	if (S2EIsSymbolic(&phHash, 1))
		S2EPrintExpression((UINT_PTR)phHash, "[CryptCreateHash] 4: ");
	else {
		Message("  [CryptCreateHash] 4: 0x%x\n", phHash);
		if (S2EIsSymbolic((PVOID)phHash, 1))
			S2EPrintExpression((UINT_PTR)*((char*)phHash), "[CryptCreateHash] *4: ");
		else {
			hex_phHash = data_to_hex_string((char*)phHash, sizeof(phHash));
			Message("  [CryptCreateHash] *4: %s\n", hex_phHash);
		}
	}
#else
	Message("  [CryptCreateHash] 0: 0x%x\n", hProv);
	Message("  [CryptCreateHash] 1: 0x%x\n", Algid);
	Message("  [CryptCreateHash] 2: 0x%x\n", hKey);
	Message("  [CryptCreateHash] 3: 0x%x\n", dwFlags);
	Message("  [CryptCreateHash] 4: 0x%x\n", phHash);
	hex_phHash = data_to_hex_string((char*)phHash, sizeof(phHash));
	Message("  [CryptCreateHash] *4: %s\n", hex_phHash);
#endif
	free(hex_phHash);

	RestoreData(CryptCreateHash, OldHookCryptCreateHash, LEN_OPCODES_HOOK_FUNCTION);
	BOOL ris = CryptCreateHash(
		hProv,
		Algid,
		hKey,
		dwFlags,
		phHash
	);
	HookDynamicFunction("advapi32", "CryptCreateHash", (funcpointer)HookCryptCreateHash, OldHookCryptCreateHash);
	
	Message("  [CryptCreateHash] ret: 0x%x\n", ris);
	return ris;
}


unsigned char OldHookGetUserNameA[LEN_OPCODES_HOOK_FUNCTION];
BOOL WINAPI HookGetUserNameA(
	LPSTR   lpBuffer,
	LPDWORD pcbBuffer
)
{
	char* hex_pcbBuffer = NULL;
	Message("GetUserNameA called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&lpBuffer, 1))
		S2EPrintExpression((UINT_PTR)lpBuffer, "[GetUserNameA] 0: ");
	else 
		Message("  [GetUserNameA] 0: 0x%x\n", lpBuffer);
	if (S2EIsSymbolic(&pcbBuffer, 1))
		S2EPrintExpression((UINT_PTR)pcbBuffer, "[GetUserNameA] 1: ");
	else {
		Message("  [GetUserNameA] 1: 0x%x\n", pcbBuffer);
		if (S2EIsSymbolic((PVOID)pcbBuffer, 1))
			S2EPrintExpression((UINT_PTR)*((char*)pcbBuffer), "[GetUserNameA] *1: ");
		else {
			hex_pcbBuffer = data_to_hex_string((char*)pcbBuffer, sizeof(pcbBuffer));
			Message("  [GetUserNameA] *1: %s\n", hex_pcbBuffer);
		}
	}
#else
	Message("  [GetUserNameA] 0: 0x%x\n", lpBuffer);
	Message("  [GetUserNameA] 1: 0x%x\n", pcbBuffer);
	hex_pcbBuffer = data_to_hex_string((char*)pcbBuffer, sizeof(pcbBuffer));
	Message("  [GetUserNameA] *1: %s\n", hex_pcbBuffer);
#endif
	free(hex_pcbBuffer);

	RestoreData(GetUserNameA, OldHookGetUserNameA, LEN_OPCODES_HOOK_FUNCTION);
	BOOL ris = GetUserNameA(
		lpBuffer,
		pcbBuffer
	);
	HookDynamicFunction("advapi32", "GetUserNameA", (funcpointer)HookGetUserNameA, OldHookGetUserNameA);

#if S2E
	if (S2EIsSymbolic((PVOID)lpBuffer, 1))
		S2EPrintExpression((UINT_PTR)*((char*)lpBuffer), "[GetUserNameA] write 0: ");
	else
		Message("  [GetUserNameA] write *0: %s\n", lpBuffer);
#else
	Message("  [GetUserNameA] write *0: %s\n", lpBuffer);
#endif
	Message("  [GetUserNameA] ret: 0x%x\n", ris);
	return ris;
}

unsigned char OldHookRegOpenKeyExA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
LSTATUS WINAPI HookRegOpenKeyExA(
	HKEY   hKey,
	LPCSTR lpSubKey,
	DWORD  ulOptions,
	REGSAM samDesired,
	PHKEY  phkResult
)
{
	Message("RegOpenKeyExA called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&hKey, 1))
		S2EPrintExpression((UINT_PTR)hKey, "[RegOpenKeyExA] 0: ");
	else
		Message("  [RegOpenKeyExA] 0: 0x%x\n", hKey);
	if (S2EIsSymbolic(&lpSubKey, 1))
		S2EPrintExpression((UINT_PTR)lpSubKey, "[RegOpenKeyExA] 1: ");
	else {
		Message("  [RegOpenKeyExA] 1: 0x%x\n", lpSubKey);
		if (S2EIsSymbolic((PVOID)lpSubKey, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpSubKey), "[RegOpenKeyExA] *1: ");
		else
			Message("  [RegOpenKeyExA] *1: %s\n", lpSubKey);
	}
	if (S2EIsSymbolic(&ulOptions, 1))
		S2EPrintExpression((UINT_PTR)ulOptions, "[RegOpenKeyExA] 2: ");
	else
		Message("  [RegOpenKeyExA] 2: 0x%x\n", ulOptions);
	if (S2EIsSymbolic(&samDesired, 1))
		S2EPrintExpression((UINT_PTR)samDesired, "[RegOpenKeyExA] 3: ");
	else
		Message("  [RegOpenKeyExA] 3: 0x%x\n", samDesired);
	if (S2EIsSymbolic(&phkResult, 1))
		S2EPrintExpression((UINT_PTR)phkResult, "[RegOpenKeyExA] 4: ");
	else 
		Message("  [RegOpenKeyExA] 4: 0x%x\n", phkResult);
#else
	Message("  [RegOpenKeyExA] 0: 0x%x\n", hKey);
	Message("  [RegOpenKeyExA] 1: 0x%x\n", lpSubKey);
	Message("  [RegOpenKeyExA] *1: %s\n", lpSubKey);
	Message("  [RegOpenKeyExA] 2: 0x%x\n", ulOptions);
	Message("  [RegOpenKeyExA] 3: 0x%x\n", samDesired);
	Message("  [RegOpenKeyExA] 4: 0x%x\n", phkResult);
#endif

	//RestoreData(RegOpenKeyExA, OldHookRegOpenKeyExA, LEN_OPCODES_HOOK_FUNCTION);
	//LSTATUS ris = RegOpenKeyExA(
	//	hKey,
	//	lpSubKey,
	//	ulOptions,
	//	samDesired,
	//	phkResult
	//);
	//HookDynamicFunction("advapi32", "RegOpenKeyExA", (funcpointer)&HookRegOpenKeyExA, OldHookRegOpenKeyExA);

	Message("  [RegOpenKeyExA] ret: 0x%x\n", ERROR_SUCCESS);
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
	char* hex_lpData = NULL;
	Message("RegSetValueExA called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&hKey, 1))
		S2EPrintExpression((UINT_PTR)hKey, "[RegSetValueExA] 0: ");
	else
		Message("  [RegSetValueExA] 0: 0x%x\n", hKey);
	if (S2EIsSymbolic(&lpValueName, 1))
		S2EPrintExpression((UINT_PTR)lpValueName, "[RegSetValueExA] 1: ");
	else {
		Message("  [RegSetValueExA] 1: 0x%x\n", lpValueName);
		if (S2EIsSymbolic((PVOID)lpValueName, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpValueName), "[RegSetValueExA] *1: ");
		else
			Message("  [RegSetValueExA] *1: %s\n", lpValueName);
	}
	if (S2EIsSymbolic(&Reserved, 1))
		S2EPrintExpression((UINT_PTR)Reserved, "[RegSetValueExA] 2: ");
	else
		Message("  [RegSetValueExA] 2: 0x%x\n", Reserved);
	if (S2EIsSymbolic(&dwType, 1))
		S2EPrintExpression((UINT_PTR)dwType, "[RegSetValueExA] 3: ");
	else
		Message("  [RegSetValueExA] 3: 0x%x\n", dwType);
	if (S2EIsSymbolic(&lpData, 1))
		S2EPrintExpression((UINT_PTR)lpData, "[RegSetValueExA] 4: ");
	else {
		Message("  [RegSetValueExA] 4: 0x%x\n", lpData);
		if (S2EIsSymbolic((PVOID)lpData, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpData), "[RegSetValueExA] *4: ");
		else {
			hex_lpData = data_to_hex_string((char*)lpData, sizeof(lpData));
			Message("  [RegSetValueExA] *4: %s\n", hex_lpData);
		}
	}
	if (S2EIsSymbolic(&cbData, 1))
		S2EPrintExpression((UINT_PTR)cbData, "[RegSetValueExA] 5: ");
	else
		Message("  [RegSetValueExA] 5: 0x%x\n", cbData);
#else
	Message("  [RegSetValueExA] 0: 0x%x\n", hKey);
	Message("  [RegSetValueExA] 1: 0x%x\n", lpValueName);
	Message("  [RegSetValueExA] *1: %s\n", lpValueName);
	Message("  [RegSetValueExA] 2: 0x%x\n", Reserved);
	Message("  [RegSetValueExA] 3: 0x%x\n", dwType);
	Message("  [RegSetValueExA] 4: 0x%x\n", lpData);
	hex_lpData = data_to_hex_string((char*)lpData, sizeof(lpData));
	Message("  [RegSetValueExA] *4: %s\n", hex_lpData);
	Message("  [RegSetValueExA] 5: 0x%x\n", cbData);
#endif
	free(hex_lpData);

	//RestoreData(RegSetValueExA, OldHookRegSetValueExA, LEN_OPCODES_HOOK_FUNCTION);
	//LSTATUS ris = RegSetValueExA(
	//	hKey,
	//	lpValueName,
	//	Reserved,
	//	dwType,
	//	lpData,
	//	cbData
	//);
	//HookDynamicFunction("advapi32", "RegSetValueExA", (funcpointer)&HookRegSetValueExA, OldHookRegSetValueExA);

	Message("  [RegSetValueExA] ret: 0x%x\n", ERROR_SUCCESS);
	return ERROR_SUCCESS;
}


unsigned char OldHookRegCloseKey[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
LSTATUS WINAPI HookRegCloseKey(
	HKEY hKey
)
{
	Message("RegCloseKey called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&hKey, 1))
		S2EPrintExpression((UINT_PTR)hKey, "[RegCloseKey] 0: ");
	else
		Message("  [RegCloseKey] 0: 0x%x\n", hKey);
#else
	Message("  [RegCloseKey] 0: 0x%x\n", hKey);
#endif

	//RestoreData(RegCloseKey, OldHookRegCloseKey, LEN_OPCODES_HOOK_FUNCTION);
	//LSTATUS ris = RegCloseKey(hKey);
	//HookDynamicFunction("advapi32", "RegCloseKey", (funcpointer)&HookRegCloseKey, OldHookRegCloseKey);

	Message("  [RegCloseKey] ret: 0x%x\n", ERROR_SUCCESS);
	return ERROR_SUCCESS;
}

// ************************************************************************************************************
// MSVCRT ****************************************************************************************************

unsigned char OldHookfopen[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
FILE *Hookfopen(
	const char *filename,
	const char *mode
)
{
	char* hex_mode = NULL;
	Message("*fopen called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&filename, 1))
		S2EPrintExpression((UINT_PTR)filename, "[*fopen] 0: ");
	else {
		Message("  [*fopen] 0: 0x%x\n", filename);
		if (S2EIsSymbolic((PVOID)filename, 1))
			S2EPrintExpression((UINT_PTR)*((char*)filename), "[*fopen] *0: ");
		else {
			Message("  [*fopen] *0: %s\n", filename);
		}
	}
	if (S2EIsSymbolic(&mode, 1))
		S2EPrintExpression((UINT_PTR)mode, "[*fopen] 1: ");
	else {
		Message("  [*fopen] 1: 0x%x\n", mode);
		if (S2EIsSymbolic((PVOID)mode, 1))
			S2EPrintExpression((UINT_PTR)*((char*)mode), "[*fopen] *1: ");
		else {
			hex_mode = data_to_hex_string((char*)mode, sizeof(mode));
			Message("  [*fopen] *1: %s\n", hex_mode);
		}
	}
#else
	Message("  [*fopen] 0: 0x%x\n", filename);
	Message("  [*fopen] *0: %s\n", filename);
	Message("  [*fopen] 1: 0x%x\n", mode);
	hex_mode = data_to_hex_string((char*)mode, sizeof(mode));
	Message("  [*fopen] *1: %s\n", hex_mode);
#endif
	free(hex_mode);
	Message("  [*fopen] ret: 0\n");
	return 0;
}

// ************************************************************************************************************
// SHELL32 ****************************************************************************************************


unsigned char OldHookShellExecuteA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
HINSTANCE HookShellExecuteA(
	HWND   hwnd,
	LPCSTR lpOperation,
	LPCSTR lpFile,
	LPCSTR lpParameters,
	LPCSTR lpDirectory,
	INT    nShowCmd
)
{
	Message("ShellExecuteA called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&hwnd, 1))
		S2EPrintExpression((UINT_PTR)hwnd, "[ShellExecuteA] 0: ");
	else
		Message("  [ShellExecuteA] 0: 0x%x\n", hwnd);
	if (S2EIsSymbolic(&lpOperation, 1))
		S2EPrintExpression((UINT_PTR)lpOperation, "[ShellExecuteA] 1: ");
	else {
		Message("  [ShellExecuteA] 1: 0x%x\n", lpOperation);
		if (S2EIsSymbolic((PVOID)lpOperation, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpOperation), "[ShellExecuteA] *1: ");
		else
			Message("  [ShellExecuteA] *1: %s\n", lpOperation);
	}
	if (S2EIsSymbolic(&lpFile, 1))
		S2EPrintExpression((UINT_PTR)lpFile, "[ShellExecuteA] 2: ");
	else {
		Message("  [ShellExecuteA] 2: 0x%x\n", lpFile);
		if (S2EIsSymbolic((PVOID)lpFile, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpFile), "[ShellExecuteA] *2: ");
		else
			Message("  [ShellExecuteA] *2: %s\n", lpFile);
	}
	if (S2EIsSymbolic(&lpParameters, 1))
		S2EPrintExpression((UINT_PTR)lpParameters, "[ShellExecuteA] 3: ");
	else {
		Message("  [ShellExecuteA] 3: 0x%x\n", lpParameters);
		if (S2EIsSymbolic((PVOID)lpParameters, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpParameters), "[ShellExecuteA] *3: ");
		else
			Message("  [ShellExecuteA] *3: %s\n", lpParameters);
	}
	if (S2EIsSymbolic(&lpDirectory, 1))
		S2EPrintExpression((UINT_PTR)lpDirectory, "[ShellExecuteA] 4: ");
	else {
		Message("  [ShellExecuteA] 4: 0x%x\n", lpDirectory);
		if (S2EIsSymbolic((PVOID)lpDirectory, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpDirectory), "[ShellExecuteA] *4: ");
		else
			Message("  [ShellExecuteA] *4: %s\n", lpDirectory);
	}
	if (S2EIsSymbolic(&nShowCmd, 1))
		S2EPrintExpression((UINT_PTR)nShowCmd, "[ShellExecuteA] 5: ");
	else
		Message("  [ShellExecuteA] 5: 0x%x\n", nShowCmd);
#else
	Message("  [ShellExecuteA] 0: 0x%x\n", hwnd);
	Message("  [ShellExecuteA] 1: 0x%x\n", lpOperation);
	Message("  [ShellExecuteA] *1: %s\n", lpOperation);
	Message("  [ShellExecuteA] 2: 0x%x\n", lpFile);
	Message("  [ShellExecuteA] *2: %s\n", lpFile);
	Message("  [ShellExecuteA] 3: 0x%x\n", lpParameters);
	Message("  [ShellExecuteA] *3: %s\n", lpParameters);
	Message("  [ShellExecuteA] 4: 0x%x\n", lpDirectory);
	Message("  [ShellExecuteA] *4: %s\n", lpDirectory);
	Message("  [ShellExecuteA] 5: 0x%x\n", nShowCmd);
#endif

	Message("  [ShellExecuteA] ret: 0\n");
	return 0;
}


// ************************************************************************************************************
// WINMM ******************************************************************************************************

unsigned char OldHookwaveInOpen[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
MMRESULT HookwaveInOpen(
	LPHWAVEIN       phwi,
	UINT            uDeviceID,
	LPCWAVEFORMATEX pwfx,
	DWORD_PTR       dwCallback,
	DWORD_PTR       dwCallbackInstance,
	DWORD           fdwOpen
)
{
	char* hex_phwi = NULL;
	char* hex_pwfx = NULL;
	Message("waveInOpen called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&phwi, 1))
		S2EPrintExpression((UINT_PTR)phwi, "[waveInOpen] 0: ");
	else {
		Message("  [waveInOpen] 0: 0x%x\n", phwi);
		if (S2EIsSymbolic((PVOID)phwi, 1))
			S2EPrintExpression((UINT_PTR)*((char*)phwi), "[waveInOpen] *0: ");
		else {
			hex_phwi = data_to_hex_string((char*)phwi, sizeof(phwi));
			Message("  [waveInOpen] *0: %s\n", hex_phwi);
		}
	}
	if (S2EIsSymbolic(&uDeviceID, 1))
		S2EPrintExpression((UINT_PTR)uDeviceID, "[waveInOpen] 1: ");
	else
		Message("  [waveInOpen] 1: 0x%x\n", uDeviceID);
	if (S2EIsSymbolic(&pwfx, 1))
		S2EPrintExpression((UINT_PTR)pwfx, "[waveInOpen] 2: ");
	else {
		Message("  [waveInOpen] 2: 0x%x\n", pwfx);
		if (S2EIsSymbolic((PVOID)pwfx, 1))
			S2EPrintExpression((UINT_PTR)*((char*)pwfx), "[waveInOpen] *2: ");
		else {
			hex_pwfx = data_to_hex_string((char*)pwfx, sizeof(pwfx));
			Message("  [waveInOpen] *2: %s\n", hex_pwfx);
		}
	}
	if (S2EIsSymbolic(&dwCallback, 1))
		S2EPrintExpression((UINT_PTR)dwCallback, "[waveInOpen] 3: ");
	else
		Message("  [waveInOpen] 3: 0x%x\n", dwCallback);
	if (S2EIsSymbolic(&dwCallbackInstance, 1))
		S2EPrintExpression((UINT_PTR)dwCallbackInstance, "[waveInOpen] 4: ");
	else
		Message("  [waveInOpen] 4: 0x%x\n", dwCallbackInstance);
	if (S2EIsSymbolic(&fdwOpen, 1))
		S2EPrintExpression((UINT_PTR)fdwOpen, "[waveInOpen] 5: ");
	else
		Message("  [waveInOpen] 5: 0x%x\n", fdwOpen);
#else
	Message("  [waveInOpen] 0: 0x%x\n", phwi);
	hex_phwi = data_to_hex_string((char*)phwi, sizeof(phwi));
	Message("  [waveInOpen] *0: %s\n", hex_phwi);
	Message("  [waveInOpen] 1: 0x%x\n", uDeviceID);
	Message("  [waveInOpen] 2: 0x%x\n", pwfx);
	hex_pwfx = data_to_hex_string((char*)pwfx, sizeof(pwfx));
	Message("  [waveInOpen] *2: %s\n", hex_pwfx);
	Message("  [waveInOpen] 3: 0x%x\n", dwCallback);
	Message("  [waveInOpen] 4: 0x%x\n", dwCallbackInstance);
	Message("  [waveInOpen] 5: 0x%x\n", fdwOpen);
#endif
	free(hex_phwi);
	free(hex_pwfx);
	Message("  [waveInOpen] ret: 0x%x\n", MMSYSERR_NODRIVER);
	return MMSYSERR_NODRIVER;
}

// ************************************************************************************************************
// KERNEL32 ***************************************************************************************************


unsigned char OldHookGetLocalTime[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
void WINAPI HookGetLocalTime(
	LPSYSTEMTIME lpSystemTime
)
{
	Message("GetLocalTime called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&lpSystemTime, 1))
		S2EPrintExpression((UINT_PTR)lpSystemTime, "[GetLocalTime] 0: ");
	else 
		Message("  [GetLocalTime] 0: 0x%x\n", lpSystemTime);
#else
	Message("  [GetLocalTime] 0: 0x%x\n", lpSystemTime);
#endif

	RestoreData(GetLocalTime, OldHookGetLocalTime, LEN_OPCODES_HOOK_FUNCTION);
	_SYSTEMTIME ris;
	GetLocalTime(&ris);
	memcpy(lpSystemTime, &ris, sizeof(ris));
	HookDynamicFunction("kernel32", "GetLocalTime", (funcpointer)HookGetLocalTime, OldHookGetLocalTime);

	char* hex_lpSystemTime = data_to_hex_string((char*)lpSystemTime, sizeof(lpSystemTime));
	Message("  [GetLocalTime] write *0: %s\n", hex_lpSystemTime);
	free(hex_lpSystemTime);
}

unsigned char OldHookGetCommandLineA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
LPSTR WINAPI HookGetCommandLineA()
{
	Message("GetCommandLineA called by 0x%x.\n", _ReturnAddress());
	RestoreData(GetCommandLineA, OldHookGetCommandLineA, LEN_OPCODES_HOOK_FUNCTION);
	LPSTR ris = GetCommandLineA();
	HookDynamicFunction("kernel32", "GetCommandLineA", (funcpointer)HookGetCommandLineA, OldHookGetCommandLineA);
	Message("  [GetCommandLineA] ret: %s\n", ris);
	return ris;
}

unsigned char OldHookCreatePipe[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookCreatePipe(
	PHANDLE               hReadPipe,
	PHANDLE               hWritePipe,
	LPSECURITY_ATTRIBUTES lpPipeAttributes,
	DWORD                 nSize
)
{
	char* hex_lpPipeAttributes = NULL;
	Message("CreatePipe called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&hReadPipe, 1))
		S2EPrintExpression((UINT_PTR)hReadPipe, "[CreatePipe] 0: ");
	else
		Message("  [CreatePipe] 0: 0x%x\n", hReadPipe);
	if (S2EIsSymbolic(&hWritePipe, 1))
		S2EPrintExpression((UINT_PTR)hWritePipe, "[CreatePipe] 1: ");
	else
		Message("  [CreatePipe] 1: 0x%x\n", hWritePipe);
	if (S2EIsSymbolic(&lpPipeAttributes, 1))
		S2EPrintExpression((UINT_PTR)lpPipeAttributes, "[CreatePipe] 2: ");
	else {
		Message("  [CreatePipe] 2: 0x%x\n", lpPipeAttributes);
		if (S2EIsSymbolic((PVOID)lpPipeAttributes, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpPipeAttributes), "[CreatePipe] *2: ");
		else {
			hex_lpPipeAttributes = data_to_hex_string((char*)lpPipeAttributes, sizeof(lpPipeAttributes));
			Message("  [CreatePipe] *2: %s\n", hex_lpPipeAttributes);
		}
	}
	if (S2EIsSymbolic(&nSize, 1))
		S2EPrintExpression((UINT_PTR)nSize, "[CreatePipe] 3: ");
	else
		Message("  [CreatePipe] 3: 0x%x\n", nSize);
#else
	Message("  [CreatePipe] 0: 0x%x\n", hReadPipe);
	Message("  [CreatePipe] 1: 0x%x\n", hWritePipe);
	Message("  [CreatePipe] 2: 0x%x\n", lpPipeAttributes);
	hex_lpPipeAttributes = data_to_hex_string((char*)lpPipeAttributes, sizeof(lpPipeAttributes));
	Message("  [CreatePipe] *2: %s\n", hex_lpPipeAttributes);
	Message("  [CreatePipe] 3: 0x%x\n", nSize);
#endif

	free(hex_lpPipeAttributes);
	Message("  [CreatePipe] ret: 0\n");
	return 0; // fail
}


unsigned char OldHookCreateProcessA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
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
)
{
	char* hex_lpProcessAttributes = NULL;
	char* hex_lpThreadAttributes = NULL;
	char* hex_lpEnvironment = NULL;
	char* hex_lpStartupInfo = NULL;
	char* hex_lpProcessInformation = NULL;
	Message("CreateProcessA called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&lpApplicationName, 1))
		S2EPrintExpression((UINT_PTR)lpApplicationName, "[CreateProcessA] 0: ");
	else {
		Message("  [CreateProcessA] 0: 0x%x\n", lpApplicationName);
		if (S2EIsSymbolic((PVOID)lpApplicationName, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpApplicationName), "[CreateProcessA] *0: ");
		else
			Message("  [CreateProcessA] *0: %s\n", lpApplicationName);
	}
	if (S2EIsSymbolic(&lpCommandLine, 1))
		S2EPrintExpression((UINT_PTR)lpCommandLine, "[CreateProcessA] 1: ");
	else {
		Message("  [CreateProcessA] 1: 0x%x\n", lpCommandLine);
		if (S2EIsSymbolic((PVOID)lpCommandLine, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpCommandLine), "[CreateProcessA] *1: ");
		else
			Message("  [CreateProcessA] *1: %s\n", lpCommandLine);
	}
	if (S2EIsSymbolic(&lpProcessAttributes, 1))
		S2EPrintExpression((UINT_PTR)lpProcessAttributes, "[CreateProcessA] 2: ");
	else {
		Message("  [CreateProcessA] 2: 0x%x\n", lpProcessAttributes);
		if (S2EIsSymbolic((PVOID)lpProcessAttributes, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpProcessAttributes), "[CreateProcessA] *2: ");
		else {
			hex_lpProcessAttributes = data_to_hex_string((char*)lpProcessAttributes, sizeof(lpProcessAttributes));
			Message("  [CreateProcessA] *2: %s\n", hex_lpProcessAttributes);
		}
	}
	if (S2EIsSymbolic(&lpThreadAttributes, 1))
		S2EPrintExpression((UINT_PTR)lpThreadAttributes, "[CreateProcessA] 3: ");
	else {
		Message("  [CreateProcessA] 3: 0x%x\n", lpThreadAttributes);
		if (S2EIsSymbolic((PVOID)lpThreadAttributes, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpThreadAttributes), "[CreateProcessA] *3: ");
		else {
			hex_lpThreadAttributes = data_to_hex_string((char*)lpThreadAttributes, sizeof(lpThreadAttributes));
			Message("  [CreateProcessA] *3: %s\n", hex_lpThreadAttributes);
		}
	}
	if (S2EIsSymbolic(&bInheritHandles, 1))
		S2EPrintExpression((UINT_PTR)bInheritHandles, "[CreateProcessA] 4: ");
	else
		Message("  [CreateProcessA] 4: 0x%x\n", bInheritHandles);
	if (S2EIsSymbolic(&dwCreationFlags, 1))
		S2EPrintExpression((UINT_PTR)dwCreationFlags, "[CreateProcessA] 5: ");
	else
		Message("  [CreateProcessA] 5: 0x%x\n", dwCreationFlags);
	if (S2EIsSymbolic(&lpEnvironment, 1))
		S2EPrintExpression((UINT_PTR)lpEnvironment, "[CreateProcessA] 6: ");
	else {
		Message("  [CreateProcessA] 6: 0x%x\n", lpEnvironment);
		if (S2EIsSymbolic((PVOID)lpEnvironment, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpEnvironment), "[CreateProcessA] *6: ");
		else {
			hex_lpEnvironment = data_to_hex_string((char*)lpEnvironment, sizeof(lpEnvironment));
			Message("  [CreateProcessA] *6: %s\n", hex_lpEnvironment);
		}
	}
	if (S2EIsSymbolic(&lpCurrentDirectory, 1))
		S2EPrintExpression((UINT_PTR)lpCurrentDirectory, "[CreateProcessA] 7: ");
	else {
		Message("  [CreateProcessA] 7: 0x%x\n", lpCurrentDirectory);
		if (S2EIsSymbolic((PVOID)lpCurrentDirectory, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpCurrentDirectory), "[CreateProcessA] *7: ");
		else
			Message("  [CreateProcessA] *7: %s\n", lpCurrentDirectory);
	}
	if (S2EIsSymbolic(&lpStartupInfo, 1))
		S2EPrintExpression((UINT_PTR)lpStartupInfo, "[CreateProcessA] 8: ");
	else {
		Message("  [CreateProcessA] 8: 0x%x\n", lpStartupInfo);
		if (S2EIsSymbolic((PVOID)lpStartupInfo, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpStartupInfo), "[CreateProcessA] *8: ");
		else {
			hex_lpStartupInfo = data_to_hex_string((char*)lpStartupInfo, sizeof(lpStartupInfo));
			Message("  [CreateProcessA] *8: %s\n", hex_lpStartupInfo);
		}
	}
	if (S2EIsSymbolic(&lpProcessInformation, 1))
		S2EPrintExpression((UINT_PTR)lpProcessInformation, "[CreateProcessA] 9: ");
	else {
		Message("  [CreateProcessA] 9: 0x%x\n", lpProcessInformation);
		if (S2EIsSymbolic((PVOID)lpProcessInformation, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpProcessInformation), "[CreateProcessA] *9: ");
		else {
			hex_lpProcessInformation = data_to_hex_string((char*)lpProcessInformation, sizeof(lpProcessInformation));
			Message("  [CreateProcessA] *9: %s\n", hex_lpProcessInformation);
		}
	}
#else
	Message("  [CreateProcessA] 0: 0x%x\n", lpApplicationName);
	Message("  [CreateProcessA] *0: %s\n", lpApplicationName);
	Message("  [CreateProcessA] 1: 0x%x\n", lpCommandLine);
	Message("  [CreateProcessA] *1: %s\n", lpCommandLine);
	Message("  [CreateProcessA] 2: 0x%x\n", lpProcessAttributes);
	hex_lpProcessAttributes = data_to_hex_string((char*)lpProcessAttributes, sizeof(lpProcessAttributes));
	Message("  [CreateProcessA] *2: %s\n", hex_lpProcessAttributes);
	Message("  [CreateProcessA] 3: 0x%x\n", lpThreadAttributes);
	hex_lpThreadAttributes = data_to_hex_string((char*)lpThreadAttributes, sizeof(lpThreadAttributes));
	Message("  [CreateProcessA] *3: %s\n", hex_lpThreadAttributes);
	Message("  [CreateProcessA] 4: 0x%x\n", bInheritHandles);
	Message("  [CreateProcessA] 5: 0x%x\n", dwCreationFlags);
	Message("  [CreateProcessA] 6: 0x%x\n", lpEnvironment);
	hex_lpEnvironment = data_to_hex_string((char*)lpEnvironment, sizeof(lpEnvironment));
	Message("  [CreateProcessA] *6: %s\n", hex_lpEnvironment);
	Message("  [CreateProcessA] 7: 0x%x\n", lpCurrentDirectory);
	Message("  [CreateProcessA] *7: %s\n", lpCurrentDirectory);
	Message("  [CreateProcessA] 8: 0x%x\n", lpStartupInfo);
	hex_lpStartupInfo = data_to_hex_string((char*)lpStartupInfo, sizeof(lpStartupInfo));
	Message("  [CreateProcessA] *8: %s\n", hex_lpStartupInfo);
	Message("  [CreateProcessA] 9: 0x%x\n", lpProcessInformation);
	hex_lpProcessInformation = data_to_hex_string((char*)lpProcessInformation, sizeof(lpProcessInformation));
	Message("  [CreateProcessA] *9: %s\n", hex_lpProcessInformation);
#endif
	free(hex_lpProcessAttributes);
	free(hex_lpThreadAttributes);
	free(hex_lpEnvironment);
	free(hex_lpStartupInfo);
	free(hex_lpProcessInformation);
	Message("  [CreateProcessA] ret: 0x%x\n", 0);
	return 0; // fail
}

unsigned char OldHookFindFirstFileA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
HANDLE WINAPI HookFindFirstFileA(
	LPCSTR             lpFileName,
	LPWIN32_FIND_DATAA lpFindFileData
)
{
	Message("FindFirstFileA called by 0x%x.\n", _ReturnAddress());
#if S2E

	if (S2EIsSymbolic(&lpFileName, 1))
		S2EPrintExpression((UINT_PTR)lpFileName, "[FindFirstFileA] 0: ");
	else {
		Message("  [FindFirstFileA] 0: 0x%x\n", lpFileName);
		if (S2EIsSymbolic((PVOID)lpFileName, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpFileName), "[FindFirstFileA] *0: ");
		else
			Message("  [FindFirstFileA] *0: %s\n", lpFileName);
	}
	if (S2EIsSymbolic(&lpFindFileData, 1))
		S2EPrintExpression((UINT_PTR)lpFindFileData, "[FindFirstFileA] 1: ");
	else
		Message("  [FindFirstFileA] 1: 0x%x\n", lpFindFileData);
#else

	Message("  [FindFirstFileA] 0: 0x%x\n", lpFileName);
	Message("  [FindFirstFileA] *0: %s\n", lpFileName);
	Message("  [FindFirstFileA] 1: 0x%x\n", lpFindFileData);
#endif

	//RestoreData(FindFirstFileA, OldHookFindFirstFileA, LEN_OPCODES_HOOK_FUNCTION);
	//HANDLE ris = FindFirstFileA(
	//	lpFileName,
	//	lpFindFileData
	//);
	//HookDynamicFunction("kernel32", "FindFirstFileA", (funcpointer)&HookFindFirstFileA, OldHookFindFirstFileA);

	Message("  [FindFirstFileA] ret: 0x%x\n", INVALID_HANDLE_VALUE);
	return INVALID_HANDLE_VALUE;
}

unsigned char OldHookFindNextFileA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookFindNextFileA(
	HANDLE             hFindFile,
	LPWIN32_FIND_DATAA lpFindFileData
)
{
	char* hex_lpFindFileData = NULL;
	Message("FindNextFileA called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&hFindFile, 1))
		S2EPrintExpression((UINT_PTR)hFindFile, "[FindNextFileA] 0: ");
	else
		Message("  [FindNextFileA] 0: 0x%x\n", hFindFile);
	if (S2EIsSymbolic(&lpFindFileData, 1))
		S2EPrintExpression((UINT_PTR)lpFindFileData, "[FindNextFileA] 1: ");
	else {
		Message("  [FindNextFileA] 1: 0x%x\n", lpFindFileData);
		if (S2EIsSymbolic((PVOID)lpFindFileData, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpFindFileData), "[FindNextFileA] *1: ");
		else {
			hex_lpFindFileData = data_to_hex_string((char*)lpFindFileData, sizeof(lpFindFileData));
			Message("  [FindNextFileA] *1: %s\n", hex_lpFindFileData);
		}
	}
#else
	Message("  [FindNextFileA] 0: 0x%x\n", hFindFile);
	Message("  [FindNextFileA] 1: 0x%x\n", lpFindFileData);
	hex_lpFindFileData = data_to_hex_string((char*)lpFindFileData, sizeof(lpFindFileData));
	Message("  [FindNextFileA] *1: %s\n", hex_lpFindFileData);
#endif
	free(hex_lpFindFileData);

	//RestoreData(FindNextFileA, OldHookFindNextFileA, LEN_OPCODES_HOOK_FUNCTION);
	//BOOL ris = FindNextFileA(
	//	hFindFile,
	//	lpFindFileData
	//);
	//HookDynamicFunction("kernel32", "FindNextFileA", (funcpointer)&HookFindNextFileA, OldHookFindNextFileA);

	Message("  [FindNextFileA] ret: 0x%x\n", FALSE);
	return FALSE;
}


unsigned char OldHookFindClose[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookFindClose(
	HANDLE hFindFile
)
{
	Message("FindClose called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&hFindFile, 1))
		S2EPrintExpression((UINT_PTR)hFindFile, "[FindClose] 0: ");
	else
		Message("  [FindClose] 0: 0x%x\n", hFindFile);
#else
	Message("  [FindClose] 0: 0x%x\n", hFindFile);
#endif

	//RestoreData(FindClose, OldHookFindClose, LEN_OPCODES_HOOK_FUNCTION);
	//BOOL ris = FindClose(
	//	hFindFile
	//);
	//HookDynamicFunction("kernel32", "FindClose", (funcpointer)&HookFindClose, OldHookFindClose);

	Message("  [FindClose] ret: 0x%x\n", TRUE);
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
	Message("RemoveDirectoryA called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&lpPathName, 1))
		S2EPrintExpression((UINT_PTR)lpPathName, "[RemoveDirectoryA] 0: ");
	else {
		Message("  [RemoveDirectoryA] 0: 0x%x\n", lpPathName);
		if (S2EIsSymbolic((PVOID)lpPathName, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpPathName), "[RemoveDirectoryA] *0: ");
		else
			Message("  [RemoveDirectoryA] *0: %s\n", lpPathName);
	}
#else
	Message("  [RemoveDirectoryA] 0: 0x%x\n", lpPathName);
	Message("  [RemoveDirectoryA] *0: %s\n", lpPathName);
#endif
	Message("  [RemoveDirectoryA] ret: 0\n");
	return 0;
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
	char* hex_lpSecurityAttributes = NULL;

	Message("CreateFileA called by 0x%x.\n", _ReturnAddress());
#if S2E

	if (S2EIsSymbolic(&lpFileName, 1))
		S2EPrintExpression((UINT_PTR)lpFileName, "[CreateFileA] 0: ");
	else {
		Message("  [CreateFileA] 0: 0x%x\n", lpFileName);
		if (S2EIsSymbolic((PVOID)lpFileName, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpFileName), "[CreateFileA] *0: ");
		else
			Message("  [CreateFileA] *0: %s\n", lpFileName);
	}
	if (S2EIsSymbolic(&dwDesiredAccess, 1))
		S2EPrintExpression((UINT_PTR)dwDesiredAccess, "[CreateFileA] 1: ");
	else
		Message("  [CreateFileA] 1: 0x%x\n", dwDesiredAccess);
	if (S2EIsSymbolic(&dwShareMode, 1))
		S2EPrintExpression((UINT_PTR)dwShareMode, "[CreateFileA] 2: ");
	else
		Message("  [CreateFileA] 2: 0x%x\n", dwShareMode);
	if (S2EIsSymbolic(&lpSecurityAttributes, 1))
		S2EPrintExpression((UINT_PTR)lpSecurityAttributes, "[CreateFileA] 3: ");
	else {
		Message("  [CreateFileA] 3: 0x%x\n", lpSecurityAttributes);
		if (S2EIsSymbolic((PVOID)lpSecurityAttributes, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpSecurityAttributes), "[CreateFileA] *3: ");
		else {
			hex_lpSecurityAttributes = data_to_hex_string((char*)lpSecurityAttributes, sizeof(lpSecurityAttributes));
			Message("  [CreateFileA] *3: %s\n", hex_lpSecurityAttributes);
		}
	}
	if (S2EIsSymbolic(&dwCreationDisposition, 1))
		S2EPrintExpression((UINT_PTR)dwCreationDisposition, "[CreateFileA] 4: ");
	else
		Message("  [CreateFileA] 4: 0x%x\n", dwCreationDisposition);
	if (S2EIsSymbolic(&dwFlagsAndAttributes, 1))
		S2EPrintExpression((UINT_PTR)dwFlagsAndAttributes, "[CreateFileA] 5: ");
	else
		Message("  [CreateFileA] 5: 0x%x\n", dwFlagsAndAttributes);
	if (S2EIsSymbolic(&hTemplateFile, 1))
		S2EPrintExpression((UINT_PTR)hTemplateFile, "[CreateFileA] 6: ");
	else
		Message("  [CreateFileA] 6: 0x%x\n", hTemplateFile);
#else

	Message("  [CreateFileA] 0: 0x%x\n", lpFileName);
	Message("  [CreateFileA] *0: %s\n", lpFileName);
	Message("  [CreateFileA] 1: 0x%x\n", dwDesiredAccess);
	Message("  [CreateFileA] 2: 0x%x\n", dwShareMode);
	Message("  [CreateFileA] 3: 0x%x\n", lpSecurityAttributes);
	hex_lpSecurityAttributes = data_to_hex_string((char*)lpSecurityAttributes, sizeof(lpSecurityAttributes));
	Message("  [CreateFileA] *3: %s\n", hex_lpSecurityAttributes);
	Message("  [CreateFileA] 4: 0x%x\n", dwCreationDisposition);
	Message("  [CreateFileA] 5: 0x%x\n", dwFlagsAndAttributes);
	Message("  [CreateFileA] 6: 0x%x\n", hTemplateFile);
#endif

	free(hex_lpSecurityAttributes);

	RestoreData(CreateFileA, OldHookCreateFileA, LEN_OPCODES_HOOK_FUNCTION);
	HANDLE ris = CreateFileA(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile);
	HookDynamicFunction("kernel32", "CreateFileA", (funcpointer)&HookCreateFileA, OldHookCreateFileA);

	Message("  [CreateFileA] ret: 0x%x\n", ris);
	return ris;
}

unsigned char OldHookMoveFileA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookMoveFileA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName
)
{
	Message("MoveFileA called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&lpExistingFileName, 1))
		S2EPrintExpression((UINT_PTR)lpExistingFileName, "[MoveFileA] 0: ");
	else {
		Message("  [MoveFileA] 0: 0x%x\n", lpExistingFileName);
		if (S2EIsSymbolic((PVOID)lpExistingFileName, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpExistingFileName), "[MoveFileA] *0: ");
		else
			Message("  [MoveFileA] *0: %s\n", lpExistingFileName);
	}
	if (S2EIsSymbolic(&lpNewFileName, 1))
		S2EPrintExpression((UINT_PTR)lpNewFileName, "[MoveFileA] 1: ");
	else {
		Message("  [MoveFileA] 1: 0x%x\n", lpNewFileName);
		if (S2EIsSymbolic((PVOID)lpNewFileName, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpNewFileName), "[MoveFileA] *1: ");
		else
			Message("  [MoveFileA] *1: %s\n", lpNewFileName);
	}
#else
	Message("  [MoveFileA] 0: 0x%x\n", lpExistingFileName);
	Message("  [MoveFileA] *0: %s\n", lpExistingFileName);
	Message("  [MoveFileA] 1: 0x%x\n", lpNewFileName);
	Message("  [MoveFileA] *1: %s\n", lpNewFileName);
#endif
	Message("  [MoveFileA] ret: 0x%x\n", FALSE);
	return FALSE;
}


unsigned char OldHookDeleteFileA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookDeleteFileA(
	LPCSTR lpFileName
)
{
	Message("DeleteFileA called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&lpFileName, 1))
		S2EPrintExpression((UINT_PTR)lpFileName, "[DeleteFileA] 0: ");
	else {
		Message("  [DeleteFileA] 0: 0x%x\n", lpFileName);
		if (S2EIsSymbolic((PVOID)lpFileName, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpFileName), "[DeleteFileA] *0: ");
		else
			Message("  [DeleteFileA] *0: %s\n", lpFileName);
	}
#else
	Message("  [DeleteFileA] 0: 0x%x\n", lpFileName);
	Message("  [DeleteFileA] *0: %s\n", lpFileName);
#endif

	Message("  [DeleteFileA] ret: 0x%x\n", FALSE);
	return FALSE;
}

unsigned char OldHookGetDriveTypeA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
UINT WINAPI HookGetDriveTypeA(
	LPCSTR lpRootPathName
)
{
	Message("GetDriveTypeA called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&lpRootPathName, 1))
		S2EPrintExpression((UINT_PTR)lpRootPathName, "[GetDriveTypeA] 0: ");
	else {
		Message("  [GetDriveTypeA] 0: 0x%x\n", lpRootPathName);
		if (S2EIsSymbolic((PVOID)lpRootPathName, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpRootPathName), "[GetDriveTypeA] *0: ");
		else
			Message("  [GetDriveTypeA] *0: %s\n", lpRootPathName);
	}
#else
	Message("  [GetDriveTypeA] 0: 0x%x\n", lpRootPathName);
	Message("  [GetDriveTypeA] *0: %s\n", lpRootPathName);
#endif
	Message("  [GetDriveTypeA] ret: 0x%x\n", DRIVE_UNKNOWN);
	return DRIVE_UNKNOWN;
}


unsigned char OldHookGetLogicalDrives[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
DWORD WINAPI HookGetLogicalDrives()
{
	Message("GetLogicalDrives called by 0x%x.\n", _ReturnAddress());
	Message("  [GetLogicalDrives] ret: 0\n");
	return 0; // no drive
}

unsigned char OldHookWinExec[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
UINT WINAPI HookWinExec(
	LPCSTR lpCmdLine,
	UINT   uCmdShow
)
{
	Message("WinExec called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&lpCmdLine, 1))
		S2EPrintExpression((UINT_PTR)lpCmdLine, "[WinExec] 0: ");
	else {
		Message("  [WinExec] 0: 0x%x\n", lpCmdLine);
		if (S2EIsSymbolic((PVOID)lpCmdLine, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpCmdLine), "[WinExec] *0: ");
		else
			Message("  [WinExec] *0: %s\n", lpCmdLine);
	}
	if (S2EIsSymbolic(&uCmdShow, 1))
		S2EPrintExpression((UINT_PTR)uCmdShow, "[WinExec] 1: ");
	else
		Message("  [WinExec] 1: 0x%x\n", uCmdShow);
#else
	Message("  [WinExec] 0: 0x%x\n", lpCmdLine);
	Message("  [WinExec] *0: %s\n", lpCmdLine);
	Message("  [WinExec] 1: 0x%x\n", uCmdShow);
#endif

	Message("  [WinExec] ret: 0x%x\n", 32);
	return 32;
}

unsigned char OldHookCloseHandle[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
BOOL WINAPI HookCloseHandle(
	_In_ HANDLE hObject
)
{
	Message("CloseHandle called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&hObject, 1))
		S2EPrintExpression((UINT_PTR)hObject, "[CloseHandle] 0: ");
	else
		Message("  [CloseHandle] 0: 0x%x\n", hObject);
#else
	Message("  [CloseHandle] 0: 0x%x\n", hObject);
#endif

	RestoreData(CloseHandle, OldHookCloseHandle, LEN_OPCODES_HOOK_FUNCTION);
	BOOL res = CloseHandle(hObject);
	HookDynamicFunction("kernel32", "CloseHandle", (funcpointer)&HookCloseHandle, OldHookCloseHandle);
	Message("  [CloseHandle] ret: 0x%x\n", res);
	return res;
}

unsigned char OldHookCreateMutexA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
HANDLE WINAPI HookCreateMutexA(
	LPSECURITY_ATTRIBUTES lpMutexAttributes,
	BOOL                  bInitialOwner,
	LPCSTR                lpName
)
{
	char* hex_lpMutexAttributes = NULL;
	Message("CreateMutexA called by 0x%x.\n", _ReturnAddress());
#if S2E
	if (S2EIsSymbolic(&lpMutexAttributes, 1))
		S2EPrintExpression((UINT_PTR)lpMutexAttributes, "[CreateMutexA] 0: ");
	else {
		Message("  [CreateMutexA] 0: 0x%x\n", lpMutexAttributes);
		if (S2EIsSymbolic((PVOID)lpMutexAttributes, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpMutexAttributes), "[CreateMutexA] *0: ");
		else {
			hex_lpMutexAttributes = data_to_hex_string((char*)lpMutexAttributes, sizeof(lpMutexAttributes));
			Message("  [CreateMutexA] *0: %s\n", hex_lpMutexAttributes);
		}
	}
	if (S2EIsSymbolic(&bInitialOwner, 1))
		S2EPrintExpression((UINT_PTR)bInitialOwner, "[CreateMutexA] 1: ");
	else
		Message("  [CreateMutexA] 1: 0x%x\n", bInitialOwner);
	if (S2EIsSymbolic(&lpName, 1))
		S2EPrintExpression((UINT_PTR)lpName, "[CreateMutexA] 2: ");
	else {
		Message("  [CreateMutexA] 2: 0x%x\n", lpName);
		if (S2EIsSymbolic((PVOID)lpName, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpName), "[CreateMutexA] *2: ");
		else
			Message("  [CreateMutexA] *2: %s\n", lpName);
	}
#else
	Message("  [CreateMutexA] 0: 0x%x\n", lpMutexAttributes);
	hex_lpMutexAttributes = data_to_hex_string((char*)lpMutexAttributes, sizeof(lpMutexAttributes));
	Message("  [CreateMutexA] *0: %s\n", hex_lpMutexAttributes);
	Message("  [CreateMutexA] 1: 0x%x\n", bInitialOwner);
	Message("  [CreateMutexA] 2: 0x%x\n", lpName);
	Message("  [CreateMutexA] *2: %s\n", lpName);
#endif
	free(hex_lpMutexAttributes);

	RestoreData(CreateMutexA, OldHookCreateMutexA, LEN_OPCODES_HOOK_FUNCTION);
	HANDLE ris = CreateMutexA(
		lpMutexAttributes,
		bInitialOwner,
		lpName
	);
	HookDynamicFunction("kernel32", "CreateMutexA", (funcpointer)HookCreateMutexA, OldHookCreateMutexA);
	Message("  [CreateMutexA] ret: 0x%x\n", ris);
	return ris;
}



// ************************************************************************************************************
// USER 32 ****************************************************************************************************

unsigned char OldHookCreateWindowExA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
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
)
{
	char* hex_lpParam = NULL;

	Message("CreateWindowExA called by 0x%x.\n", _ReturnAddress());
#if S2E

	if (S2EIsSymbolic(&dwExStyle, 1))
		S2EPrintExpression((UINT_PTR)dwExStyle, "[CreateWindowExA] 0: ");
	else
		Message("  [CreateWindowExA] 0: 0x%x\n", dwExStyle);
	if (S2EIsSymbolic(&lpClassName, 1))
		S2EPrintExpression((UINT_PTR)lpClassName, "[CreateWindowExA] 1: ");
	else {
		Message("  [CreateWindowExA] 1: 0x%x\n", lpClassName);
		if (S2EIsSymbolic((PVOID)lpClassName, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpClassName), "[CreateWindowExA] *1: ");
		else
			Message("  [CreateWindowExA] *1: %s\n", lpClassName);
	}
	if (S2EIsSymbolic(&lpWindowName, 1))
		S2EPrintExpression((UINT_PTR)lpWindowName, "[CreateWindowExA] 2: ");
	else {
		Message("  [CreateWindowExA] 2: 0x%x\n", lpWindowName);
		if (S2EIsSymbolic((PVOID)lpWindowName, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpWindowName), "[CreateWindowExA] *2: ");
		else
			Message("  [CreateWindowExA] *2: %s\n", lpWindowName);
	}
	if (S2EIsSymbolic(&dwStyle, 1))
		S2EPrintExpression((UINT_PTR)dwStyle, "[CreateWindowExA] 3: ");
	else
		Message("  [CreateWindowExA] 3: 0x%x\n", dwStyle);
	if (S2EIsSymbolic(&X, 1))
		S2EPrintExpression((UINT_PTR)X, "[CreateWindowExA] 4: ");
	else
		Message("  [CreateWindowExA] 4: 0x%x\n", X);
	if (S2EIsSymbolic(&Y, 1))
		S2EPrintExpression((UINT_PTR)Y, "[CreateWindowExA] 5: ");
	else
		Message("  [CreateWindowExA] 5: 0x%x\n", Y);
	if (S2EIsSymbolic(&nWidth, 1))
		S2EPrintExpression((UINT_PTR)nWidth, "[CreateWindowExA] 6: ");
	else
		Message("  [CreateWindowExA] 6: 0x%x\n", nWidth);
	if (S2EIsSymbolic(&nHeight, 1))
		S2EPrintExpression((UINT_PTR)nHeight, "[CreateWindowExA] 7: ");
	else
		Message("  [CreateWindowExA] 7: 0x%x\n", nHeight);
	if (S2EIsSymbolic(&hWndParent, 1))
		S2EPrintExpression((UINT_PTR)hWndParent, "[CreateWindowExA] 8: ");
	else
		Message("  [CreateWindowExA] 8: 0x%x\n", hWndParent);
	if (S2EIsSymbolic(&hMenu, 1))
		S2EPrintExpression((UINT_PTR)hMenu, "[CreateWindowExA] 9: ");
	else
		Message("  [CreateWindowExA] 9: 0x%x\n", hMenu);
	if (S2EIsSymbolic(&hInstance, 1))
		S2EPrintExpression((UINT_PTR)hInstance, "[CreateWindowExA] 10: ");
	else
		Message("  [CreateWindowExA] 10: 0x%x\n", hInstance);
	if (S2EIsSymbolic(&lpParam, 1))
		S2EPrintExpression((UINT_PTR)lpParam, "[CreateWindowExA] 11: ");
	else {
		Message("  [CreateWindowExA] 11: 0x%x\n", lpParam);
		if (S2EIsSymbolic((PVOID)lpParam, 1))
			S2EPrintExpression((UINT_PTR)*((char*)lpParam), "[CreateWindowExA] *11: ");
		else {
			hex_lpParam = data_to_hex_string((char*)lpParam, sizeof(lpParam));
			Message("  [CreateWindowExA] *11: %s\n", hex_lpParam);
		}
	}
#else

	Message("  [CreateWindowExA] 0: 0x%x\n", dwExStyle);
	Message("  [CreateWindowExA] 1: 0x%x\n", lpClassName);
	Message("  [CreateWindowExA] *1: %s\n", lpClassName);
	Message("  [CreateWindowExA] 2: 0x%x\n", lpWindowName);
	Message("  [CreateWindowExA] *2: %s\n", lpWindowName);
	Message("  [CreateWindowExA] 3: 0x%x\n", dwStyle);
	Message("  [CreateWindowExA] 4: 0x%x\n", X);
	Message("  [CreateWindowExA] 5: 0x%x\n", Y);
	Message("  [CreateWindowExA] 6: 0x%x\n", nWidth);
	Message("  [CreateWindowExA] 7: 0x%x\n", nHeight);
	Message("  [CreateWindowExA] 8: 0x%x\n", hWndParent);
	Message("  [CreateWindowExA] 9: 0x%x\n", hMenu);
	Message("  [CreateWindowExA] 10: 0x%x\n", hInstance);
	Message("  [CreateWindowExA] 11: 0x%x\n", lpParam);
	hex_lpParam = data_to_hex_string((char*)lpParam, sizeof(lpParam));
	Message("  [CreateWindowExA] *11: %s\n", hex_lpParam);
#endif

	free(hex_lpParam);

	RestoreData((LPVOID)CreateWindowExA, OldHookCreateWindowExA, LEN_OPCODES_HOOK_FUNCTION);
	HWND ris = CreateWindowExA(
		dwExStyle,
		lpClassName,
		lpWindowName,
		dwStyle,
		X,
		Y,
		nWidth,
		nHeight,
		hWndParent,
		hMenu,
		hInstance,
		lpParam
	);
	HookDynamicFunction("user32", "CreateWindowExA", (funcpointer)HookCreateWindowExA, OldHookCreateWindowExA);

	Message("  [CreateWindowExA] ret: 0x%x\n", ris);
	return ris;
}

// ************************************************************************************************************
// MSVCRT *****************************************************************************************************

unsigned char Old_beginthreadexHook[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
uintptr_t _beginthreadexHook(
	void *security,
	unsigned stack_size,
	unsigned(__stdcall *start_address)(void *),
	void *arglist,
	unsigned initflag,
	unsigned *thrdaddr
)
{
	char* hex_security = NULL;
	char* hex_arglist = NULL;
	char* hex_thrdaddr = NULL;

	Message("_beginthreadex called by 0x%x.\n", _ReturnAddress());
#if S2E

	if (S2EIsSymbolic(&security, 1))
		S2EPrintExpression((UINT_PTR)security, "[_beginthreadex] 0: ");
	else {
		Message("  [_beginthreadex] 0: 0x%x\n", security);
		if (S2EIsSymbolic((PVOID)security, 1))
			S2EPrintExpression((UINT_PTR)*((char*)security), "[_beginthreadex] *0: ");
		else {
			hex_security = data_to_hex_string((char*)security, sizeof(security));
			Message("  [_beginthreadex] *0: %s\n", hex_security);
		}
	}
	if (S2EIsSymbolic(&stack_size, 1))
		S2EPrintExpression((UINT_PTR)stack_size, "[_beginthreadex] 1: ");
	else
		Message("  [_beginthreadex] 1: 0x%x\n", stack_size);
	if (S2EIsSymbolic(&start_address, 1))
		S2EPrintExpression((UINT_PTR)start_address, "[_beginthreadex] 2: ");
	else 
		Message("  [_beginthreadex] 2: 0x%x\n", start_address);
	if (S2EIsSymbolic(&arglist, 1))
		S2EPrintExpression((UINT_PTR)arglist, "[_beginthreadex] 3: ");
	else {
		Message("  [_beginthreadex] 3: 0x%x\n", arglist);
		if (S2EIsSymbolic((PVOID)arglist, 1))
			S2EPrintExpression((UINT_PTR)*((char*)arglist), "[_beginthreadex] *3: ");
		else {
			hex_arglist = data_to_hex_string((char*)arglist, sizeof(arglist));
			Message("  [_beginthreadex] *3: %s\n", hex_arglist);
		}
	}
	if (S2EIsSymbolic(&initflag, 1))
		S2EPrintExpression((UINT_PTR)initflag, "[_beginthreadexHook] 4: ");
	else
		Message("  [_beginthreadex] 4: 0x%x\n", initflag);
	if (S2EIsSymbolic(&thrdaddr, 1))
		S2EPrintExpression((UINT_PTR)thrdaddr, "[_beginthreadexHook] 5: ");
	else {
		Message("  [_beginthreadex] 5: 0x%x\n", thrdaddr);
		if (S2EIsSymbolic((PVOID)thrdaddr, 1))
			S2EPrintExpression((UINT_PTR)*((char*)thrdaddr), "[_beginthreadexHook] *5: ");
		else {
			hex_thrdaddr = data_to_hex_string((char*)thrdaddr, sizeof(thrdaddr));
			Message("  [_beginthreadex] *5: %s\n", hex_thrdaddr);
		}
	}
#else

	Message("  [_beginthreadex] 0: 0x%x\n", security);
	hex_security = data_to_hex_string((char*)security, sizeof(security));
	Message("  [_beginthreadex] *0: %s\n", hex_security);
	Message("  [_beginthreadex] 1: 0x%x\n", stack_size);
	Message("  [_beginthreadex] 2: 0x%x\n", start_address);
	Message("  [_beginthreadex] 3: 0x%x\n", arglist);
	hex_arglist = data_to_hex_string((char*)arglist, sizeof(arglist));
	Message("  [_beginthreadex] *3: %s\n", hex_arglist);
	Message("  [_beginthreadex] 4: 0x%x\n", initflag);
	Message("  [_beginthreadex] 5: 0x%x\n", thrdaddr);
	hex_thrdaddr = data_to_hex_string((char*)thrdaddr, sizeof(thrdaddr));
	Message("  [_beginthreadex] *5: %s\n", hex_thrdaddr);
#endif

	free(hex_security);
	free(hex_arglist);
	free(hex_thrdaddr);

	Message("  [_beginthreadex] ret: -1\n");
	return -1L;
}

