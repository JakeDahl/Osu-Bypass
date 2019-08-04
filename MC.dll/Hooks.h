#pragma once
#include "common.h"

typedef ULONG(WINAPI *tGetAdaptersAddresses)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
tGetAdaptersAddresses oGetAdaptersAddresses = NULL;

typedef RPC_STATUS(WINAPI *tUuidCreate)(UUID*);
tUuidCreate oUuidCreate = NULL;

typedef LSTATUS(WINAPI *tRegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
tRegQueryValueExW oRegQueryValueExW = NULL;

typedef BOOL(WINAPI *tShellExecuteExW)(SHELLEXECUTEINFOW*);
tShellExecuteExW oShellExecuteExW = NULL;
