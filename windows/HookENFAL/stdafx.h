// stdafx.h: file di inclusione per file di inclusione del sistema standard
// o file di inclusione specifici del progetto usati di frequente, ma
// modificati raramente
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Escludere gli elementi usati raramente dalle intestazioni di Windows
// File di intestazione di Windows
#include <windows.h>
#include <cstdlib>
#include <iostream>

#define USER_APP
extern "C" {
#include <s2e/s2e.h>
}


// fare riferimento qui alle intestazioni aggiuntive richieste dal programma
