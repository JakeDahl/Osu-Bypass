#pragma once
#include <WinSock2.h>
#include <iostream>
#include <Windows.h>
#include <MinHook.h>
#include <Rpc.h>
#include <iphlpapi.h>

#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "MinHook.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")

//DWORD findPattern(HANDLE processHandle, const unsigned char pattern[], const char* mask, const int offset, size_t begin);
//DWORD FindPattern(char* module, char* pattern, char* mask);

void WINAPI ConsoleInit();
void InstallHooks();