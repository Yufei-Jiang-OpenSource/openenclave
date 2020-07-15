/*++

Copyright (c) Microsoft Corporation

Module Name:

    Rpc.cpp

Abstract:

    This module contains routines related to the RPC server interface of
    IGVM Agent.  Test code to allow a system to behave like an Azure host.

--*/

#include "pch.h"

using namespace agent;

HRESULT
RpcIGVmAttest(
    /* [in] */ handle_t BindingHandle,
    /* [in] */ GUID VmId,
    /* [in,  ref, string] */ __RPC__in_string LPCWSTR VmName,
    /* [in, range(0, 512)] */ __RPC__in_range(0, 512) UINT32 AttestationURISize,
    /* [in,  ref, size_is(URISize)] */ __RPC__in_ecount_full(KeyURISize) BYTE* AttestationURI,
    /* [in, range(0, 512)] */ __RPC__in_range(0, 512) UINT32 KeyURISize,
    /* [in,  ref, size_is(URISize)] */ __RPC__in_ecount_full(KeyURISize) BYTE* KeyURI,
    /* [in, range(0, 4096)] */ __RPC__in_range(0, 4096) UINT32 ReportSize,
    /* [in,  ref, size_is(ReportSize)] */ __RPC__in_ecount_full(ReportSize) BYTE* Report,
    /* [in, range(0, 4096)] */ __RPC__in_range(0, 4096) UINT32 ResponseBufferSize,
    /* [out] */ __RPC__out UINT32* ResponseWrittenSize,
    /* [out, ref, size_is(ResponseBufferSize), length_is(*ResponseWrittenSize)] */
    __RPC__out_ecount_part(ResponseBufferSize, *ResponseWrittenSize) BYTE* Response
    )
/*++

Routine Description:

    This routine handles the "key release" request from client.
    Generally this would involve getting an attestation report and a
    secure key release.  This version just packages up a canned
    encryption seed.  Not intended to be secure, or actually
    protect IGVM data at rest.

Arguments:

    BindingHandle - Binding handle representing the RPC client.

    VmId - Corresponds to VmUniqueId and VM BIOS GUID.

    VmName - VmName.

    AttestationURISize - Size of Attestation URI.

    AttestationKeyURI - URI that defines requested resource for attestation.

    KeyURISize - Size of Key URI.

    KeyURI - URI that defines requested resource for key release.

    ReportSize - Size of attestation report.

    Report - Attestation report.

    ResponseBufferSize - Size of response buffer (in).

    ResponseWrittenSize - Size of response buffer (out).

    Response    - Response payload.

Return Value:

    HRESULT

--*/
{
    LOG_INFO(L"RPC server function RpcIGVmAttest starts...");

    UNREFERENCED_PARAMETER(BindingHandle);
    UNREFERENCED_PARAMETER(VmId);
    UNREFERENCED_PARAMETER(KeyURISize);
    UNREFERENCED_PARAMETER(KeyURI);

    LOG_INFO(L"VmName is %ws", VmName);
    return g_IGVmAgent.IGVmAttest(Report, ReportSize, AttestationURI, AttestationURISize, { Response, Response + ResponseBufferSize }, ResponseWrittenSize);
}