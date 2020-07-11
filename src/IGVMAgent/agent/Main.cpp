/*++

Copyright (c) Microsoft Corporation

    Main.cpp

Abstract:

    Test IGVM Agent implementation

--*/

#include "pch.h"

using namespace agent;

// A single global instance of Test Agent class.
IGVmAgent g_IGVmAgent;
// A manually set event to signal process to exit.
HANDLE g_ExitEvent = NULL;


//
// The following two functions are required by RPC to allow the application
// control over memory handling.
//
extern "C" void* MIDL_user_allocate(_In_ size_t Size)
{
    void *memory = malloc(Size);
    if (memory != nullptr)
    {
        RtlZeroMemory(memory, Size);
    }

    return memory;
}

extern "C" void MIDL_user_free(_In_ _Post_invalid_ void* Memory)
{
    if (Memory != nullptr)
    {
        free(Memory);
    }
}


HRESULT
InitializeProcess()
/*++

Routine Description:

    This routine initializes process.

--*/
{
    RETURN_IF_FAILED(g_IGVmAgent.Initialize());

    // Initialize event.
    g_ExitEvent = ::CreateEvent(
        NULL,
        TRUE,  // manual reset required to set the event state to nonsignaled
        FALSE, // initial state is nonsignaled
        NULL);
    if (g_ExitEvent == NULL)
    {
        RETURN_WIN32(GetLastError());
    }

    return S_OK;
}


VOID
WaitForTermination()
/*++
Routine Description:

    This method waits until the shutdown event signals.

--*/
{
    // Wait for exit
    ::WaitForSingleObject(g_ExitEvent, INFINITE);
}


VOID TeardownProcess()
/*++

Routine Description:

    This routine tears down process.

--*/
{
    g_IGVmAgent.Teardown();

    if (g_ExitEvent != NULL)
    {
        ::CloseHandle(g_ExitEvent);
        g_ExitEvent = NULL;
    }
}


VOID __cdecl
wmain(
    _In_                int     Argc,
    _In_reads_(Argc)    LPWSTR  Argv[]
    )
/*++

Routine Description:

    This is the main entry point of the process.

Arguments:

    Argc - The number of command line arguments.

    Argv - Command line arguments.

Return Value:

--*/
{
    UNREFERENCED_PARAMETER(Argc);
    UNREFERENCED_PARAMETER(Argv);

    LOG_INFO(L"IGVmAgent process starts...");

    if (InitializeProcess() == S_OK)
    {
        WaitForTermination();
    }

    TeardownProcess();

    return;
}
