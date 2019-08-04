#pragma once
#include <WinSock2.h>
#include <iostream>
#include <Windows.h>
#include <MinHook.h>
#include <Rpc.h>
#include <iphlpapi.h>

//Not all are used... old imports.
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "MinHook.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")

void WINAPI ConsoleInit();
void InstallHooks();
