#pragma once
#include "common.h"

bool timewarp = false;


typedef LSTATUS(WINAPI *tRegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
tRegOpenKeyExW oRegOpenKeyExW = NULL;

typedef ULONG(WINAPI *tGetAdaptersAddresses)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
tGetAdaptersAddresses oGetAdaptersAddresses = NULL;

typedef RPC_STATUS(WINAPI *tUuidCreate)(UUID*);
tUuidCreate oUuidCreate = NULL;

typedef int (WINAPI *tUuidEqual)(UUID*, UUID*, RPC_STATUS*);
tUuidEqual oUuidEqual = NULL;

typedef LSTATUS(WINAPI *tRegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
tRegQueryValueExW oRegQueryValueExW = NULL;

typedef int (WSAAPI *tSend)(SOCKET s, const char *buf, int len, int flags);
tSend oSend = NULL;

typedef ULONGLONG(WINAPI *tGetTickCount64)();
tGetTickCount64 oGetTickCount64 = NULL;

typedef SOCKET(WINAPI *tWSASocketW)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
tWSASocketW oWSASocketW = NULL;

typedef PVOID(WINAPI *tEncodePointer)(PVOID);
tEncodePointer oEncodePointer = NULL;

typedef HANDLE(WINAPI *tCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
tCreateFileW oCreateFileW = NULL;

typedef BOOL(WINAPI *tShellExecuteExW)(SHELLEXECUTEINFOW*);
tShellExecuteExW oShellExecuteExW = NULL;

typedef LPVOID(WINAPI *tMapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
tMapViewOfFile oMapViewOfFile = NULL;

typedef BOOL(WINAPI *tReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
tReadFile oReadFile = NULL;

typedef BOOL(WINAPI *tGetCursorPos)(LPPOINT);
tGetCursorPos oGetCursorPos = NULL;

typedef HMODULE(WINAPI *tLoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
tLoadLibraryExW oLoadLibraryExW = NULL;

typedef FARPROC(WINAPI *tGetProcAddress)(HMODULE, LPCSTR);
tGetProcAddress oGetProcAddress = NULL;

typedef BOOL(WINAPI* tQueryPerformanceCounter)(LARGE_INTEGER*);
tQueryPerformanceCounter oQueryPerformanceCounter = NULL;

typedef LONG(WINAPI* tWinVerifyTrust)(HWND, GUID*, LPVOID);
tWinVerifyTrust oWinVerifyTrust = NULL;

