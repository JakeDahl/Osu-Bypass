#include "Hooks.h"
#include <sstream>
#include <Mstcpip.h>
#include <ws2tcpip.h>
#include <iostream>
#include <fstream>
#include <string>
#include <atlstr.h>
#include <Psapi.h>
#include <WinTrust.h>
#include <vector>

#pragma comment(lib, "WinTrust.lib")

#pragma warning(disable:4996)

DWORD mscorlibBase = NULL;


bool WINAPI DetourShellExecuteExW(SHELLEXECUTEINFOW *pExecInfo) //Detoured to open web browser to beat map vs. shell execute.
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	int len = lstrlenW(pExecInfo->lpFile);
	std::string str;
	for (size_t i = 0; i < len; i++)
	{
		char x = (char)pExecInfo->lpFile[i];
		str += x;
	}

	CStringA command_line;
	command_line.Format("cmd.exe /c start \"link\" \"%s\"", str.c_str());

	if (!CreateProcessA(NULL,  command_line.GetBuffer(),NULL, NULL,FALSE,NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW,NULL,NULL,&si,&pi))
	{
		return oShellExecuteExW(pExecInfo);
	}
	return oShellExecuteExW(pExecInfo);
}

int WINAPI DetourUuidCreate(UUID* Uuid)
{
	int ret = oUuidCreate(Uuid);
	return RPC_S_UUID_LOCAL_ONLY;
}

ULONG WINAPI DetourGetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved, PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer)
{
	ULONG ret = oGetAdaptersAddresses(Family, 0x0200, Reserved, AdapterAddresses, SizePointer);
	return ERROR_NO_DATA;
}

LSTATUS WINAPI DetourRegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
	int len = lstrlenW(lpValueName);
	std::string str;
	for (size_t i = 0; i < len; i++)
	{
		char x = (char)lpValueName[i];
		str += x;
	}

	if ((strcmp(str.c_str(), "UninstallID") == 0) || (strcmp(str.c_str(), "CurrentBuildNumber") == 0))
	{
		oRegQueryValueExW(hKey, lpValueName, lpReserved, lpType, NULL, lpcbData);
		return ERROR_FILE_NOT_FOUND;
	}

	return oRegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}


void InstallHooks()
{
	MH_Initialize();
	MH_CreateHook(&UuidCreate, &DetourUuidCreate, reinterpret_cast<LPVOID*>(&oUuidCreate));
	MH_CreateHook(&GetAdaptersAddresses, &DetourGetAdaptersAddresses, reinterpret_cast<LPVOID*>(&oGetAdaptersAddresses));
	MH_CreateHook(&RegQueryValueExW, &DetourRegQueryValueExW, reinterpret_cast<LPVOID*>(&oRegQueryValueExW));
	MH_CreateHook(&ShellExecuteExW, &DetourShellExecuteExW, reinterpret_cast<LPVOID*>(&oShellExecuteExW));
	MH_EnableHook(MH_ALL_HOOKS);
}
