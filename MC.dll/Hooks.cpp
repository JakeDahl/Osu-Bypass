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

int WINAPI DetourUuidEqual(UUID* Uuid1, UUID* Uuid2, RPC_STATUS* Status)
{
	//std::cout << "DetourUuidEqual Hit" << std::endl;
	return oUuidEqual(Uuid1, Uuid2, Status);
}

int WINAPI DetourUuidCreate(UUID* Uuid)
{
	int ret = oUuidCreate(Uuid);
	if (Uuid)
	{
		//std::cout << Uuid->Data1 << std::endl;
		//std::cout << Uuid->Data2 << std::endl;
		//std::cout << Uuid->Data3 << std::endl;
//std::cout << "::::::::::::::::::::::::::::::::::::::::::::" << std::endl;
	}
	return RPC_S_UUID_LOCAL_ONLY;
}

ULONG WINAPI DetourGetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved, PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer)
{
	//std::cout << "DetourGetAdapterAddresses Hit" << std::endl;
	ULONG ret = oGetAdaptersAddresses(Family, 0x0200, Reserved, AdapterAddresses, SizePointer);
	return ERROR_NO_DATA;
}

LSTATUS WINAPI DetourRegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
	return oRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
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
		//std::cout << "Blocked:" << (int)hKey << std::endl;
		return ERROR_FILE_NOT_FOUND;
	}

	return oRegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

SOCKET WINAPI DetourWSASocketW(int af, int type, int protocol, LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags)
{

}

int WSAAPI DetourSend(SOCKET s, const char *buf, int len, int flags)
{
	return oSend(s, buf, len, flags);
}

bool on = false;

int64_t PerformanceCounterBase;
ULONGLONG WINAPI DetourGetTickCount64()
{
	if (GetAsyncKeyState(VK_NUMPAD5) & 1)
	{
		if (!on)
		{
			QueryPerformanceCounter((LARGE_INTEGER*)&PerformanceCounterBase);
			std::cout << "off" << std::endl;
			on = !on;
			return oGetTickCount64();
		}
		on = !on;
		std::cout << "on" << std::endl;
	}
	return oGetTickCount64();
}

BOOL WINAPI DetourQueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)
{
	if (on)
	{
		int64_t current_counter;

		if (oQueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&current_counter)))
			return false;

		auto new_counter = PerformanceCounterBase + ((current_counter - PerformanceCounterBase) * .5);

		*lpPerformanceCount = *reinterpret_cast<LARGE_INTEGER*>(&new_counter);
		return true;
	}

	return oQueryPerformanceCounter(lpPerformanceCount);
}

PVOID WINAPI DetourEncodePointer(PVOID Ptr)
{
	//PVOID ret = oEncodePointer(Ptr);
	//std::cout << std::hex << (DWORD)ret << std::endl;
	return oEncodePointer(Ptr);
}


bool fuzzer = false;
BOOL WINAPI DetourGetCursorPos(LPPOINT lpPoint)
{
	return oGetCursorPos(lpPoint);
}

std::string wstrtostr(const std::wstring &wstr)
{
	std::string strTo;
	char *szTo = new char[wstr.length() + 1];
	szTo[wstr.size()] = '\0';
	WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, szTo, (int)wstr.length(), NULL, NULL);
	strTo = szTo;
	delete[] szTo;
	return strTo;
}

HMODULE WINAPI DetourLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	if (strstr(wstrtostr(lpLibFileName).c_str(), "clrcompression"))
	{
		std::cout << wstrtostr(lpLibFileName) << std::endl;
	}
	
	return oLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

FARPROC WINAPI DetourGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	if (((DWORD)lpProcName >> 16) == 0)
	{
		return oGetProcAddress(hModule, lpProcName);
	}

	if(strstr(lpProcName, "GetCursorPos"))
	{
		std::cout << &DetourGetCursorPos << std::endl;
		return (FARPROC)(&DetourGetCursorPos);
	}

	return oGetProcAddress(hModule, lpProcName);
}

LONG WINAPI DetourWinVerifyTrust(HWND hwnd, GUID *pgActionID, LPVOID pWVTDATA)
{
	
	LONG ret = oWinVerifyTrust(hwnd, pgActionID, pWVTDATA);

	if (ret != S_OK)
	{
		return S_OK;
	}
	
	return ret;
}


HANDLE lastHandle = NULL;
bool first = false;

std::vector<HANDLE> handles;
HANDLE WINAPI DetourCreateFileW(LPCWSTR lpFileName, DWORD dwDesireAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	if (wcsstr(lpFileName, L"osu!.cfg"))
	{

		HANDLE ret = oCreateFileW(lpFileName, dwDesireAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
		handles.push_back(ret);
		return ret;

	}
	return oCreateFileW(lpFileName, dwDesireAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


#include <algorithm>
BOOL WINAPI DetourReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{


	if (std::find(handles.begin(), handles.end(), hFile) != handles.end()) {
		BOOL ret = oReadFile(hFile, NULL, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
	}
	else {
		return oReadFile(hFile, NULL, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
	}
	
	return oReadFile(hFile, NULL, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}
//
//
//DWORD dwOld;
//LONG WINAPI UnhandledExceptionFilter1(EXCEPTION_POINTERS *pExceptionInfo)
//{
//	std::cout << std::hex << "Eax: " << pExceptionInfo->ContextRecord->Eax << " ECX: " << pExceptionInfo->ContextRecord->Ecx << std::endl;
//	pExceptionInfo->ContextRecord->Eip = pExceptionInfo->ContextRecord->Esp;
//	//std::cout << "Eax: " << pExceptionInfo->ContextRecord->Eax << " ECX: " << pExceptionInfo->ContextRecord->Ecx << std::endl;
//	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) // This is going to return true whenever any of our PAGE_GUARD'ed memory page is accessed.
//	{
//		std::cout << "Eax: " << pExceptionInfo->ContextRecord->Eax << " ECX: " << pExceptionInfo->ContextRecord->Ecx << std::endl;
//		if (pExceptionInfo->ContextRecord->Eip == mscorlibBase + 0x9E236) // Here we check to see if the instruction pointer is at the place where we want to hook.
//		{
//			std::cout << "Eax: " << pExceptionInfo->ContextRecord->Eax << " ECX: " << pExceptionInfo->ContextRecord->Ecx << std::endl;
//			//dwJmpBack = (DWORD*)(pExceptionInfo->ContextRecord->Esp + 0); // Find the return address for the JMP/EIP back into the target program's code.
//			//dwJmpBack = (DWORD)pExceptionInfo->ContextRecord->Eip + 5; // or just skip X number of bytes.
//			//pExceptionInfo->ContextRecord->Eip = (DWORD)hkFunction; // Point EIP to hook handle.
//		}
//
//		pExceptionInfo->ContextRecord->EFlags |= 0x100; //Set single step flag, causing only one line of code to be executed and then throwing the STATUS_SINGLE_STEP exception.
//
//		return EXCEPTION_CONTINUE_EXECUTION; // When we return to the page, it will no longer be PAGE_GUARD'ed, so we rely on single stepping to re-apply it. (If we re-applied it here, we'd never move forward.)
//	}
//
//	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) // This is now going to return true on the next line of execution within our page, where we re-apply PAGE_GUARD and repeat.
//	{
//		/*DWORD dwOld;*/
//		VirtualProtect((void*)(mscorlibBase + 0x9E236), 1, PAGE_EXECUTE | PAGE_GUARD, &dwOld);
//
//		return EXCEPTION_CONTINUE_EXECUTION;
//	}
//
//	return EXCEPTION_CONTINUE_SEARCH;
//}


void InstallHooks()
{
	//mscorlibBase = (DWORD)GetModuleHandle(L"mscorlib.ni.dll");

	//VirtualProtect((void*)(mscorlibBase + 0x9E236), 1, PAGE_EXECUTE | PAGE_GUARD, &dwOld); // This sets the protection for whatever memory page that 0x08048fb7 is located in to PAGE_EXECUTE & PAGE_GUARD.
	//AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)UnhandledExceptionFilter1); // Registers our vectored exception handler which is going to catch the exceptions thrown.


	MH_Initialize();
	MH_CreateHook(&UuidCreate, &DetourUuidCreate, reinterpret_cast<LPVOID*>(&oUuidCreate));
	MH_CreateHook(&UuidEqual, &DetourUuidEqual, reinterpret_cast<LPVOID*>(&oUuidEqual));
	MH_CreateHook(&GetAdaptersAddresses, &DetourGetAdaptersAddresses, reinterpret_cast<LPVOID*>(&oGetAdaptersAddresses));
	MH_CreateHook(&RegOpenKeyExW, &DetourRegOpenKeyExW, reinterpret_cast<LPVOID*>(&oRegOpenKeyExW));
	MH_CreateHook(&RegQueryValueExW, &DetourRegQueryValueExW, reinterpret_cast<LPVOID*>(&oRegQueryValueExW));
	MH_CreateHook(&ShellExecuteExW, &DetourShellExecuteExW, reinterpret_cast<LPVOID*>(&oShellExecuteExW));
	//MH_CreateHook(&QueryPerformanceCounter, &DetourQueryPerformanceCounter, reinterpret_cast<LPVOID*>(&oQueryPerformanceCounter));
	MH_CreateHook(&LoadLibraryExW, &DetourLoadLibraryExW, reinterpret_cast<LPVOID*>(&oLoadLibraryExW));
	MH_CreateHook(&WinVerifyTrust, &DetourWinVerifyTrust, reinterpret_cast<LPVOID*>(&oWinVerifyTrust));
	//MH_CreateHook(&GetCursorPos, &DetourGetCursorPos, reinterpret_cast<LPVOID*>(&oGetCursorPos));
	//MH_CreateHook(&GetProcAddress, &DetourGetProcAddress, reinterpret_cast<LPVOID*>(&oGetProcAddress));
	//MH_CreateHook(reinterpret_cast<LPVOID*>(&addr), &DetourTimer, reinterpret_cast<LPVOID*>(&oTimer));
	//MH_CreateHook(&GetTickCount64, &DetourGetTickCount64, reinterpret_cast<LPVOID*>(&oGetTickCount64));
	//MH_CreateHook(&send, &DetourSend, reinterpret_cast<LPVOID*>(&oSend));
	//MH_CreateHook(&DecodePointer, &DetourEncodePointer, reinterpret_cast<LPVOID*>(&oEncodePointer));
	//MH_CreateHook(&CreateFileW, &DetourCreateFileW, reinterpret_cast<LPVOID*>(&oCreateFileW));
	//MH_CreateHook(&MapViewOfFile, &DetourMapViewOfFile, reinterpret_cast<LPVOID*>(&oMapViewOfFile));
	//MH_CreateHook(&ReadFile, &DetourReadFile, reinterpret_cast<LPVOID*>(&oReadFile));
	MH_EnableHook(MH_ALL_HOOKS);
}