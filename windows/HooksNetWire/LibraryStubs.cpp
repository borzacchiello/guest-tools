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

unsigned char oldSocketHook[LEN_OPCODES_HOOK_FUNCTION];
SOCKET WSAAPI socketHook(
	int af,
	int type,
	int protocol
) {
	Message("socket called.\n");
	return 0xdeadbeef;
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
		// S2EKillState(0, "ciao");
		S2EConcretize(&len, 4);
		Message("Concretizing len to %d\n", len);
	}
	memset(buf, 0, len);
	char name[50];
	sprintf(name, "recv_%d", callCounter++);
	S2EMakeConcolic(buf, len, name);   // passing a stack variable should be safe
	return len;
#else
	buf[0] = 'A'; buf[1] = 0; buf[2] = 0; buf[3] = 0;
	return 4;
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
	hostent* ris = new hostent();
	char* h_name = (char*)calloc(sizeof(char), 1);
	char* addr1 = (char*)calloc(sizeof(char), 1);
	char** h_addr_list = (char**)malloc(sizeof(char*) * 2);
	h_addr_list[0] = addr1; h_addr_list[1] = NULL;

	ris->h_name = h_name;
	ris->h_length = 0;
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
	// return hostshort; // at 0x4035D4, symbolic write
	return 0;
}