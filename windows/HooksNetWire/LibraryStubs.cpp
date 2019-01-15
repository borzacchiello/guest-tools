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
	char* dst = (char*)malloc(sizeof(char)*len+1);
	memcpy(dst, buf, len);
	dst[len] = NULL;
	Message("send called. buf=%s\n", dst);
	free(dst);
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
		S2EConcretize(&len, 4);
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
		// extracted using SE (TARGET: 0x040D3AD; AVOID: 0x040D3B6). First recv {0x41, 0x0, 0x0, 0x0}
		unsigned char tmp[] = { 0x5, 0x88, 0x50, 0x19, 0x8, 0x54, 0x8d, 0xc0, 0xd0, 0x88, 0x50, 0x1a,  \
			0x7, 0x5a, 0x85, 0xc0, 0xd0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x3, 0x11, 0x3c, 0x2, \
			0xa9, 0x1e, 0x19, 0x6, 0x1b, 0xd1, 0x32, 0xf1, 0xbe, 0x78, 0x16, 0x61, 0x58, 0x63, 0xe2,   \
			0x0, 0x9e, 0x3c, 0x87, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,    \
			0x0, 0x0, 0x0, 0x0 };
		memcpy(buf, tmp, 0x41);
		return len;
	}
#if S2E
	char name[50];
	sprintf(name, "recv_%d", callCounter++);
	S2EMakeConcolic(buf, len, name);   // passing a stack variable should be safe
	return len;
#else
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