#include "Common.h"
#include "stdafx.h"

char* data_to_hex_string(const char* data, int size)
{
	if (data == NULL) return (char*)data;
	int i, j;
	char* ris = (char*)malloc(size * 5 + 1); // for each byte BB, print ' 0xBB'
	ris[size * 5] = 0;
	for (i = 0; i < size; ++i) {
		char el_0 = data[i] & 0x0F;
		char el_1 = (data[i] >> 4) & 0x0F;
		j = 5 * i;
		ris[j] = ' ';
		ris[j + 1] = '0';
		ris[j + 2] = 'x';
		ris[j + 3] = el_1 < 10 ? '0' + el_1 : 'A' + (el_1 - 10);
		ris[j + 4] = el_0 < 10 ? '0' + el_0 : 'A' + (el_0 - 10);
	}
	return ris;
}