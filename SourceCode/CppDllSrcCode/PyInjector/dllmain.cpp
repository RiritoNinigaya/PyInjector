// dllmain.cpp : Defines the entry point for the DLL application.
#include "includes.h"
#define DLL_EXPORT __declspec(dllexport)

DLL_EXPORT void Inject(std::string exePath, std::string procName, std::string dllName) 
{
    DWORD sleep = 0;
    startProcess(exePath.c_str());
    Sleep(16000);
    inject(procName, dllName, sleep);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        printf("[PyInjector] WELCOME TO THE MY FIRST DLL LIBRARY FOR PYTHON INJECTOR!!! MADE BY RIRITONINIGAYA!!! \nSO ENJOY TO USE THIS!!!");
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

