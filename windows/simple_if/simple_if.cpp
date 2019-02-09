// simple_if.cpp : Questo file contiene la funzione 'main', in cui inizia e termina l'esecuzione del programma.
//

#include "pch.h"
#include <iostream>
#define USER_APP
extern "C" {
#include <s2e/s2e.h>
}
using namespace std;

int main(int argc, char const *argv[])
{
	if (argc != 2) exit(1);
	S2EMakeConcolic((void*)argv[1], 1, "input");

	int n = argv[1][0];
	if (n == 97) {
		cout << "ciao" << endl;
	}
	else {
		cout << "nope" << endl;
	}
	return 0;
}