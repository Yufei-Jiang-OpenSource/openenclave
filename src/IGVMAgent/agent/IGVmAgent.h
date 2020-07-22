/*++

Copyright (c) Microsoft Corporation

Abstract:

    IGVM Agent header file

--*/

#pragma once

#include "pch.h"

class IGVmAgent
{
public:
    IGVmAgent();

    ~IGVmAgent();

    HRESULT Initialize();

    VOID Teardown();

    VOID SignalConnected();

    VOID SignalDisconnected();

    VOID TerminateProcess();

    HRESULT
    IGVmAttest(
        _In_reads_bytes_(ReportSize) const BYTE* Report,
                                         UINT32  ReportSize,
                                     const BYTE* AttestationURI,
                                         UINT32  AttestationURISize,
                                gsl::span<BYTE>  ResponseBuffer,
        _Inout_                         UINT32*  WrittenSize
        );

private:

    HRESULT InitRpcServer();

    HRESULT
    IGVmKeyReleaseRequest(
        _In_reads_bytes_(ReportSize) const BYTE* Report,
                                        UINT32   ReportSize,
                                     const BYTE* AttestationURI,
                                        UINT32   AttestationURISize,
                                gsl::span<BYTE>  ResponseBuffer,
        _Inout_                         UINT32*  WrittenSize
        );

    HRESULT
        SnpIGVmKeyReleaseRequest(
            _In_reads_bytes_(ReportSize) const BYTE* Report,
                                             UINT32  ReportSize,
                                         const BYTE* AttestationURI,
                                             UINT32  AttestationURISize,
                                    gsl::span<BYTE>  ResponseBuffer,
            _Inout_                          UINT32* WrittenSize
        );

    HRESULT
    IGVmEkCertRequest(
        _In_reads_bytes_(ReportSize) const BYTE* Report,
                                        UINT32   ReportSize,
                                gsl::span<BYTE>  ResponseBuffer,
        _Inout_                         UINT32*  WrittenSize
        );

    HRESULT
    ParseReport(
        _In_reads_bytes_(ReportBufferSize) const BYTE*  ReportBuffer,
                                                UINT32  ReportBufferSize,
        _Out_                                   BYTE*&  UserData,
        _Out_                                   UINT32& UserDataBufferSize
        );

    HRESULT
    CreateResponse(
       _In_ IGVM_REQUEST_DATA*  UserData,
                        UINT32  UserDataBufferSize,
                        UINT8*  EncryptedTransportKey,
                        UINT32  EncryptedTransportKeySize,
                        UINT8*  WrappedReleasedKey,
                        UINT32  WrappedReleasedKeySize,
               gsl::span<BYTE>  ResponseBuffer,
                       UINT32*  WrittenSize
        );

   bool m_IGVmAgentIfRegistered = false;
   agent::identity m_igvmIdentity;
};


extern IGVmAgent g_IGVmAgent;
extern HANDLE g_ExitEvent;