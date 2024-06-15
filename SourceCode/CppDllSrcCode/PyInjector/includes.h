#pragma once
#include <iostream>
#include <Windows.h>
#include <filesystem>
#include <stdio.h>
#include <TlHelp32.h>
namespace fs = std::filesystem;
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(DWORD *)(name)
using namespace std;
DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
    WORD wIndex = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;

    pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

    pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    if (dwRva < pSectionHeader[0].PointerToRawData)
        return dwRva;

    for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
    {
        if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
            return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
    }

    return 0;
}
bool startProcess(const char* exePath)
{
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);
	bool retVal = CreateProcess((LPCWSTR)exePath, nullptr, nullptr, nullptr, false, 0, nullptr, nullptr, &si, &pi);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return retVal;
}

DWORD getProcessID(const std::string& procName)
{
	DWORD id = 0;
	PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
	HANDLE processes = 0;
	while (!id) {
		processes = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (Process32First(processes, &pe)) {
			do {
				if (!strcmp((const char*)pe.szExeFile, procName.c_str())) {
					id = pe.th32ProcessID;
					break;
				}
			} while (Process32Next(processes, &pe));
		}
	}
	CloseHandle(processes);
	return id;
}

void inject(const std::string& processName, const std::string& dllPath, DWORD sleep = 0)
{
	Sleep(sleep);
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, 0, getProcessID(processName));
	void* address = VirtualAllocEx(process, 0, dllPath.size(), MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(process, address, dllPath.c_str(), dllPath.size(), 0);
	CreateRemoteThread(process, 0, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibrary((LPCWSTR)"kernel32"), "LoadLibraryA"), address, 0, 0);
	CloseHandle(process);
}
