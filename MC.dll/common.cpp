#include "common.h"
#include <TlHelp32.h>
#include <Psapi.h>

#pragma warning(disable:4996)

void WINAPI ConsoleInit()
{
	if (!AllocConsole()) return;

	char* input = (char *)malloc(256);
	//ZeroMemory()
	memset(input, 0, sizeof(input));

	SetConsoleTitle(L"Console");
	freopen("CONIN$", "rb", stdin);
	freopen("CONOUT$", "wb", stdout);
	freopen("CONOUT$", "wb", stderr);

	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SMALL_RECT rect = { 0, 0, 200, 500 };
	COORD consoleSize = { (short)100, (short)1000 };
	SetConsoleWindowInfo(hConsole, TRUE, &rect);
	SetConsoleScreenBufferSize(hConsole, consoleSize);
}


MODULEINFO GetModuleInfo(char *szModule)
{
	MODULEINFO modInfo = { 0 };
	HMODULE hModule = GetModuleHandleA(szModule);
	if (hModule != 0)
		GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));
	return modInfo;
}
