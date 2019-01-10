// dllmain.cpp : Definisce il punto di ingresso per l'applicazione DLL.
#include "stdafx.h"
#include "Util.h"
#define USER_APP
extern "C" {
#include <s2e/s2e.h>
}

#define ENTRY_ADDRESS 0x4A2AD0

INT s2eVersion = 0;
BOOL executed = false;

unsigned char oldKill[18] = { 0 };
static void kill(unsigned long eax, unsigned long ebx, unsigned long ecx,
	unsigned long edx, unsigned long edi, unsigned long esi)
{
	Message("REACHED.\n");
	exit(1);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

	if (!executed) {
		executed = true;
		s2eVersion = S2EGetVersion();
		if (! s2eVersion) InitDebugFile();
		Message("Initialization phase.\n");
		HookInstruction((funcpointer)ENTRY_ADDRESS, (funcpointer)&kill, (funcpointer)ENTRY_ADDRESS, oldKill);
	}
    return TRUE;
}

