/*++

Copyright (c) Microsoft Corporation

Module Name:

    IGVmAgent.cpp

Abstract:

    This module implements Hyper-V test IGVM Agent.

--*/

#include "pch.h"
#include <include\clients\ccf_skr_client.h>

using namespace web::http;
using namespace web::http::client;
using namespace base64;
using namespace agent;
using namespace clients;

IGVmAgent::IGVmAgent()
: m_igvmIdentity(U("72f988bf-86f1-41af-91ab-2d7cd011db47"), 
                 U("78dc3e40-2d45-4b3c-96c2-64e8373b76a0"), 
                 U("6.iCi4Q21mg7Wi5~UmSc2_s.r10c4hwYFh"))
{
    //Nothing to do
}

IGVmAgent::~IGVmAgent()
/*++

Routine Description:

    This routine destroys an instance of IGVmAgent class.

--*/
{
    Teardown();
}

HRESULT
IGVmAgent::Initialize()
/*++

Routine Description:

    This routine initializes IGVmAgent RPC server.

--*/
{
    RETURN_IF_FAILED(InitRpcServer());

    LOG_STRING(L"IGVmAgent server initialized.");
    return S_OK;
}


VOID
IGVmAgent::Teardown()
/*++

Routine Description:

    This routine tears down IGVmAgent RPC server.

--*/
{

    if (m_IGVmAgentIfRegistered)
    {
        (void)::RpcServerUnregisterIf(IGVmAgentRpcApi_ServerIfHandle, NULL, FALSE);
        m_IGVmAgentIfRegistered = false;

        LOG_STRING(L"IGVmAgent server stopped.");
    }
}


HRESULT
IGVmAgent::InitRpcServer()
/*++

Routine Description:

    This routine initializes the session information used for creating the RPC
    server.

--*/
{
    RPC_STATUS  status;

    // Initialize RPC server.
    status = ::RpcServerUseProtseqEpW(
        (RPC_WSTR)L"ncalrpc",
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        (RPC_WSTR)IGVM_AGENT_RPC_ENDPOINT,
        NULL);
    if (status != RPC_S_OK)
    {
        RETURN_WIN32(status);
    }

    status = ::RpcServerRegisterIfEx(
        IGVmAgentRpcApi_ServerIfHandle,
        NULL,
        NULL,
        RPC_IF_AUTOLISTEN | RPC_IF_ALLOW_LOCAL_ONLY | RPC_IF_ALLOW_SECURE_ONLY,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        NULL);
    if (status != RPC_S_OK)
    {
        RETURN_WIN32(status);
    }

    m_IGVmAgentIfRegistered = true;

    return S_OK;
}


VOID
IGVmAgent::SignalConnected()
/*++

Routine Description:

    This method signals that client is connected.

--*/
{
    // Does nothing
}


VOID
IGVmAgent::SignalDisconnected()
/*++

Routine Description:

    This method signals that client is disconnected.

--*/
{
    // Does nothing
}

VOID
IGVmAgent::TerminateProcess()
/*++

Routine Description:

    This method signals exit event.
    Not currently called (process persists).

--*/
{
    SetEvent(g_ExitEvent);
}

HRESULT
IGVmAgent::ParseReport(
    _In_reads_bytes_(ReportBufferSize) const BYTE*  ReportBuffer,
                                            UINT32  ReportBufferSize,
    _Out_                                   BYTE*&  UserData,
    _Out_                                   UINT32& UserDataBufferSize
    )
/*++

Routine Description:

    This routine checks an attestation report, making sure
    buffer contains entire report & user data.

Arguments:

    ReportBuffer - Input from the HCL

    ReportBufferSize - The size

    UserData - User data portion of the report, holds transport key

    UserDataBufferSize - The size of user data

Return Values:

    HRESULT

--*/
{
    UINT32 reportSize = sizeof(HW_ATTESTATION);

    // Set offset and size for User Data
    UserData = (BYTE *)(ReportBuffer + reportSize);
    UserDataBufferSize = ReportBufferSize - reportSize;

    return S_OK;
}

HRESULT
IGVmAgent::CreateResponse(
    _In_ IGVM_REQUEST_DATA* UserData,
                    UINT32  UserDataBufferSize,
            gsl::span<BYTE> ResponseBuffer,
                    UINT32* WrittenSize
    )
/*++

Routine Description:

    This routine creates the attestation response,
    ingress and egress keys wrapped by a
    random AES-GCM key, which is wrapped by the
    user provided (transport) RSA KEK.

Arguments:

    UserData - Holds the KEK

    ResponseBuffer - Output payload

    WrittenSize - Size of output

Return Values:

    HRESULT

--*/
{
    HRESULT hr = S_OK;
    UINT32 offset = 0;

    *WrittenSize = 0;

    RETURN_HR_IF(E_INVALIDARG,
        (UserDataBufferSize < sizeof(IGVM_REQUEST_DATA)) ||
        (UserDataBufferSize < sizeof(IGVM_REQUEST_DATA) + UserData->KeyDataSize) ||
        (UserData->Version != IGVM_ATTEST_VERSION_CURRENT));

    auto cleanup = wil::scope_exit([&]
    {
        if (FAILED(hr))
        {
            RtlSecureZeroMemory(ResponseBuffer.data(), ResponseBuffer.size());
        }
    });

    //
    // Start response generation
    //

    RtlZeroMemory(ResponseBuffer.data(), ResponseBuffer.size());
    RETURN_HR_IF(E_INVALIDARG, ResponseBuffer.size() < sizeof(IGVM_KEY_MESSAGE_HEADER));

    //
    // Any failure path from here onwards needs to set hr, to clear ResponseBuffer on error
    //

    IGVM_KEY_MESSAGE_HEADER* payloadHeader = (IGVM_KEY_MESSAGE_HEADER*)ResponseBuffer.data();
    payloadHeader->Version = IGVM_KEY_MESSAGE_HEADER_VERSION_1;
    offset = FIELD_OFFSET(IGVM_KEY_MESSAGE_HEADER, Payload);

    payloadHeader->DataSize = 0;

    return S_OK;
}

HRESULT
IGVmAgent::IGVmKeyReleaseRequest(
    _In_reads_bytes_(ReportSize) const BYTE* Report,
                                     UINT32  ReportSize,
                                 const BYTE* AttestationURI,
                                     UINT32  AttestationURISize,
                            gsl::span<BYTE>  ResponseBuffer,
    _Inout_                          UINT32* WrittenSize
    )
/*++

Routine Description:

    This routine is called to release canned IVM keys,
    and can apply to all Isolated VM variants.
    Does no attesation of report.

Arguments:

    Response - Buffer to receive reponse.

    ResponseSize -
        _In_ Response buffer size.
        _Out_ Length of data written to buffer.

Return Value:

    HRESULT

--*/
{
    LOG_STRING(L"Key release request received.");

//    TODO: Have to temporarily comment the predicate below out as current HclData doesn't contain a valid report type.
//          Will add the predicate below back when a valid report type is available in the HclData.
//    if (((ATTESTATION_REPORT*)Report)->HclData.ReportType == SnpVmReport)
//    {
        LOG_INFO(L"ReportType is SnpVmReport");
        RETURN_IF_FAILED(SnpIGVmKeyReleaseRequest(Report, ReportSize, AttestationURI, AttestationURISize, ResponseBuffer, WrittenSize));
//    }

    return S_OK;
}

HRESULT
IGVmAgent::SnpIGVmKeyReleaseRequest(
    _In_reads_bytes_(ReportSize) const BYTE* Report,
                                     UINT32  ReportSize,
                                 const BYTE* AttestationURI,
                                     UINT32  AttestationURISize,
                            gsl::span<BYTE>  ResponseBuffer,
    _Inout_                          UINT32* WrittenSize
    )
/*++

Routine Description:

    This routine is called to release canned IVM keys,
    only for AMD-SNP CVM.
    Does no attesation of report.

Arguments:

    Response - Buffer to receive reponse.

    ResponseSize -
        _In_ Response buffer size.
        _Out_ Length of data written to buffer.

Return Value:

    HRESULT

--*/
{
    IGVM_REQUEST_DATA* userData = NULL;
    UINT32 userDataBufferSize = 0;
    SNP_VM_REPORT* snpReport = NULL;

    LOG_STRING(L"Snp Key release request received.");

    snpReport = (SNP_VM_REPORT*)Report;
    printf("SnpVersion 0x%x\n", snpReport->SnpVersion);
    printf("SnpGuestSvn 0x%x\n", snpReport->SnpGuestSvn);
    printf("SnpPolicy 0x%llx\n", snpReport->SnpPolicy);
    printf("SnpVMPL 0x%x\n", snpReport->SnpVMPL);
    printf("SnpSignatureAlgo 0x%x\n", snpReport->SnpSignatureAlgo);
    printf("SnpTcbVersion 0x%llx\n", snpReport->SnpTcbVersion);
    printf("SnpPlatformInfo 0x%llx\n", snpReport->SnpPlatformInfo);
    printf("SnpReportFlags 0x%x\n", snpReport->SnpReportFlags);

    RETURN_IF_FAILED(ParseReport(Report, ReportSize, (BYTE*&)userData, userDataBufferSize));

    utility::string_t maa_token;
    clients::maa_client maaClientInstance(m_igvmIdentity);

    // Covert the snpReport into base64 format.
    std::vector<BYTE> hwReportByteVec(Report, Report + sizeof(SNP_VM_REPORT));
    utility::string_t hwReportBase64 = base64::Base64Encode<std::wstring, std::vector<BYTE>>(hwReportByteVec, 1);
    LOG_INFO(L"Hardware Report in base64 format: \n%ws\n", hwReportBase64.c_str());

    // Convert the user data into base64 format.
    std::vector<BYTE> userDataByteVec((BYTE*)userData, (BYTE*)userData + userDataBufferSize);
    utility::string_t userDataBase64 = base64::Base64Encode<std::wstring, std::vector<BYTE>>(userDataByteVec, 1);
    LOG_INFO(L"User data in base64 format: \n%ws\n", userDataBase64.c_str());

    //TODO: Temporarily override hardware report and user data with SGX reprot and data 
    //      to ping currently available endpoints to have the end-to-end control flow verified.
    //      These two lines below will be removed after AMD-SNP MAA endpoints being available.
    hwReportBase64 = L"AQAAAAIAAADoEQAAAAAAAAMAAgAAAAAABQAKAJOacjP3nEyplAoNs5V_BgeeI-eujEnsDJz4BT53cU7nAAAAAA8PAwX_gAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAAAAAAABwAAAAAAAAA4EWJEqsFnOBFv1j_uNy3bz-yWNAVHRiTytDWO-d6jYwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATBrC29x85xqG4y4HWo_VBbkozUxyMI7Gxr9c7HocBz4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkbSi2Yi_YwNrPJyHKZjN_h5xL1R3i13f-7oAWxXch_8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADQQAABuFwY-HLJGP0sZ6hZXXxM50lBn9MJ-ZblBe10wcsc8Sp7hccMkn7b1sbGiz82mZ-gds4Xe0kmCcGA5wh_QNtdFAm-AIOOvJh8b6XhyVI3m143_h_4h8Dvv80ERF1gBWwM2yoMnqFREOR1-QHl7Yq3jqD7ORx3nSXUt6fJtXvEWvQ8PAwX_gAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABUAAAAAAAAABwAAAAAAAADNyt-32yKtpf1gNFXN4b-folj6XyhNzW4MYzkvYzoRBQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjE9XddeWUD6WE393xoqCmgBWrI3tcBQLCBsJRJDFe_8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQWfhdLK2OCFiv0ekj4VKlTSjlcHRRZZReYHO0i7Yg20AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKeUy7FRWOVzti7uO-RWgsqYJiwR9Bk1aUeiy04Ep2pNXoXlUQoMT34CpobS33Xn3F8MpTB77eyhmLR8yfEiYrggAAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fBQDMDQAALS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVnVENDQkNhZ0F3SUJBZ0lVYmtuQkRoU05xRWhReEFqeDRQVnR3RWlHZnZBd0NnWUlLb1pJemowRUF3SXcKY1RFak1DRUdBMVVFQXd3YVNXNTBaV3dnVTBkWUlGQkRTeUJRY205alpYTnpiM0lnUTBFeEdqQVlCZ05WQkFvTQpFVWx1ZEdWc0lFTnZjbkJ2Y21GMGFXOXVNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFCkNBd0NRMEV4Q3pBSkJnTlZCQVlUQWxWVE1CNFhEVEl3TURRd09EQTNNakF4TjFvWERUSTNNRFF3T0RBM01qQXgKTjFvd2NERWlNQ0FHQTFVRUF3d1pTVzUwWld3Z1UwZFlJRkJEU3lCRFpYSjBhV1pwWTJGMFpURWFNQmdHQTFVRQpDZ3dSU1c1MFpXd2dRMjl5Y0c5eVlYUnBiMjR4RkRBU0JnTlZCQWNNQzFOaGJuUmhJRU5zWVhKaE1Rc3dDUVlEClZRUUlEQUpEUVRFTE1Ba0dBMVVFQmhNQ1ZWTXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBU2IKSk9WWitvU2dkUjZhcGRHeTczK3RIYW5pWDFCNFBIMGlQakNSR2VWK2dscjVyY3FUbFkzZWRHZThZL25aV25EdApoWCs5ODNaOXp2THl1amQ1M21IaG80SUNtekNDQXBjd0h3WURWUjBqQkJnd0ZvQVUwT2lxMm5YWCtTNUpGNWc4CmV4UmwwTlh5V1Uwd1h3WURWUjBmQkZnd1ZqQlVvRktnVUlaT2FIUjBjSE02THk5aGNHa3VkSEoxYzNSbFpITmwKY25acFkyVnpMbWx1ZEdWc0xtTnZiUzl6WjNndlkyVnlkR2xtYVdOaGRHbHZiaTkyTWk5d1kydGpjbXcvWTJFOQpjSEp2WTJWemMyOXlNQjBHQTFVZERnUVdCQlNua2g2SXpjNGkrc0Q4Tm9pMHg5bjdrc2l0WmpBT0JnTlZIUThCCkFmOEVCQU1DQnNBd0RBWURWUjBUQVFIL0JBSXdBRENDQWRRR0NTcUdTSWI0VFFFTkFRU0NBY1V3Z2dIQk1CNEcKQ2lxR1NJYjRUUUVOQVFFRUVJQVBkSlJjSHp2TEc1eXVMOGNwc0tBd2dnRmtCZ29xaGtpRytFMEJEUUVDTUlJQgpWREFRQmdzcWhraUcrRTBCRFFFQ0FRSUJEakFRQmdzcWhraUcrRTBCRFFFQ0FnSUJEakFRQmdzcWhraUcrRTBCCkRRRUNBd0lCQWpBUUJnc3Foa2lHK0UwQkRRRUNCQUlCQkRBUUJnc3Foa2lHK0UwQkRRRUNCUUlCQVRBUkJnc3EKaGtpRytFMEJEUUVDQmdJQ0FJQXdFQVlMS29aSWh2aE5BUTBCQWdjQ0FRWXdFQVlMS29aSWh2aE5BUTBCQWdnQwpBUUF3RUFZTEtvWklodmhOQVEwQkFna0NBUUF3RUFZTEtvWklodmhOQVEwQkFnb0NBUUF3RUFZTEtvWklodmhOCkFRMEJBZ3NDQVFBd0VBWUxLb1pJaHZoTkFRMEJBZ3dDQVFBd0VBWUxLb1pJaHZoTkFRMEJBZzBDQVFBd0VBWUwKS29aSWh2aE5BUTBCQWc0Q0FRQXdFQVlMS29aSWh2aE5BUTBCQWc4Q0FRQXdFQVlMS29aSWh2aE5BUTBCQWhBQwpBUUF3RUFZTEtvWklodmhOQVEwQkFoRUNBUW93SHdZTEtvWklodmhOQVEwQkFoSUVFQTRPQWdRQmdBWUFBQUFBCkFBQUFBQUF3RUFZS0tvWklodmhOQVEwQkF3UUNBQUF3RkFZS0tvWklodmhOQVEwQkJBUUdBSkJ1MVFBQU1BOEcKQ2lxR1NJYjRUUUVOQVFVS0FRQXdDZ1lJS29aSXpqMEVBd0lEU1FBd1JnSWhBUHVsVFVkblBFYXZycjNlMXFOOQpNOFBXcXVwWUxwaW0yY29WOGdPbVBWenRBaUVBbFZEQy9nT2dkbG5Kd1JiNnFoY0dabGs2WXRoN3VhNUVoaUxjClNZOVQ1eHc9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNsekNDQWo2Z0F3SUJBZ0lWQU5Eb3F0cDExL2t1U1JlWVBIc1VaZERWOGxsTk1Bb0dDQ3FHU000OUJBTUMKTUdneEdqQVlCZ05WQkFNTUVVbHVkR1ZzSUZOSFdDQlNiMjkwSUVOQk1Sb3dHQVlEVlFRS0RCRkpiblJsYkNCRApiM0p3YjNKaGRHbHZiakVVTUJJR0ExVUVCd3dMVTJGdWRHRWdRMnhoY21FeEN6QUpCZ05WQkFnTUFrTkJNUXN3CkNRWURWUVFHRXdKVlV6QWVGdzB4T0RBMU1qRXhNRFExTURoYUZ3MHpNekExTWpFeE1EUTFNRGhhTUhFeEl6QWgKQmdOVkJBTU1Ha2x1ZEdWc0lGTkhXQ0JRUTBzZ1VISnZZMlZ6YzI5eUlFTkJNUm93R0FZRFZRUUtEQkZKYm5SbApiQ0JEYjNKd2IzSmhkR2x2YmpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnUTJ4aGNtRXhDekFKQmdOVkJBZ01Ba05CCk1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTDlxK05NcDJJT2cKdGRsMWJrL3VXWjUrVEdRbThhQ2k4ejc4ZnMrZktDUTNkK3VEelhuVlRBVDJaaERDaWZ5SXVKd3ZOM3dOQnA5aQpIQlNTTUpNSnJCT2pnYnN3Z2Jnd0h3WURWUjBqQkJnd0ZvQVVJbVVNMWxxZE5JbnpnN1NWVXI5UUd6a25CcXd3ClVnWURWUjBmQkVzd1NUQkhvRVdnUTRaQmFIUjBjSE02THk5alpYSjBhV1pwWTJGMFpYTXVkSEoxYzNSbFpITmwKY25acFkyVnpMbWx1ZEdWc0xtTnZiUzlKYm5SbGJGTkhXRkp2YjNSRFFTNWpjbXd3SFFZRFZSME9CQllFRk5EbwpxdHAxMS9rdVNSZVlQSHNVWmREVjhsbE5NQTRHQTFVZER3RUIvd1FFQXdJQkJqQVNCZ05WSFJNQkFmOEVDREFHCkFRSC9BZ0VBTUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUMvOWorODRUK0h6dFZPL3NPUUJXSmJTZCsvMnVleEsKNCthQTBqY0ZCTGNwQWlBM2RoTXJGNWNENTJ0NkZxTXZBSXBqOFhkR215MmJlZWxqTEpLK3B6cGNSQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNqakNDQWpTZ0F3SUJBZ0lVSW1VTTFscWROSW56ZzdTVlVyOVFHemtuQnF3d0NnWUlLb1pJemowRUF3SXcKYURFYU1CZ0dBMVVFQXd3UlNXNTBaV3dnVTBkWUlGSnZiM1FnUTBFeEdqQVlCZ05WQkFvTUVVbHVkR1ZzSUVOdgpjbkJ2Y21GMGFXOXVNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFQ0F3Q1EwRXhDekFKCkJnTlZCQVlUQWxWVE1CNFhEVEU0TURVeU1URXdOREV4TVZvWERUTXpNRFV5TVRFd05ERXhNRm93YURFYU1CZ0cKQTFVRUF3d1JTVzUwWld3Z1UwZFlJRkp2YjNRZ1EwRXhHakFZQmdOVkJBb01FVWx1ZEdWc0lFTnZjbkJ2Y21GMAphVzl1TVJRd0VnWURWUVFIREF0VFlXNTBZU0JEYkdGeVlURUxNQWtHQTFVRUNBd0NRMEV4Q3pBSkJnTlZCQVlUCkFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVDNm5Fd01ESVlaT2ovaVBXc0N6YUVLaTcKMU9pT1NMUkZoV0dqYm5CVkpmVm5rWTR1M0lqa0RZWUwwTXhPNG1xc3lZamxCYWxUVll4RlAyc0pCSzV6bEtPQgp1ekNCdURBZkJnTlZIU01FR0RBV2dCUWlaUXpXV3AwMGlmT0R0SlZTdjFBYk9TY0dyREJTQmdOVkhSOEVTekJKCk1FZWdSYUJEaGtGb2RIUndjem92TDJObGNuUnBabWxqWVhSbGN5NTBjblZ6ZEdWa2MyVnlkbWxqWlhNdWFXNTAKWld3dVkyOXRMMGx1ZEdWc1UwZFlVbTl2ZEVOQkxtTnliREFkQmdOVkhRNEVGZ1FVSW1VTTFscWROSW56ZzdTVgpVcjlRR3prbkJxd3dEZ1lEVlIwUEFRSC9CQVFEQWdFR01CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRRXdDZ1lJCktvWkl6ajBFQXdJRFNBQXdSUUlnUVFzLzA4cnljZFBhdUNGazhVUFFYQ01BbHNsb0JlN053YVFHVGNkcGEwRUMKSVFDVXQ4U0d2eEttanBjTS96MFdQOUR2bzhoMms1ZHUxaVdEZEJrQW4rMGlpQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KAA";
    userDataBase64 = L"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFqOXR1aGgzT21LNXFJUUdxRTAwRQpDZTBXa2pXQnliQStIdWQ1QkRIc3VtMGg4V3dJM2VjRm5XTXdEWmF3cndBS3AxOHRTdE00ZU9LdjhTOGtOUUg1Ck9rajFPZVNpTDBESVdocjQ4YmJoNE5VczFTa0ZHWW9sb1Q5OVJ1dE9lZlZnWDlnbFNSNWdCbXNiMjl6VnZoN3gKUUZiSDNVSGxIZERTQkI2NEN2SXRQdzVzY0xoRUliVEhzWUNzREhCdjJzc3QrZjFEVFdVc0Mvc0h0R3JFMTJMcQovTTErRlN1d2x4bHhxV0pZZjRDaG5MOTgzZk5ZeWYzaFhocEVuQ2lIaFdqRnQ4S0FlY21mM2pVcVc1NEZ6aWM1CmZSZFVRTHp0YnUwVnkwczB1NnBnVWVvLzc2dnFCUDJxeFgvZ0V2ZExldzB3Q3VCaHlCVEorQzRyb2xMNjcraFoKcVFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // Get the MAA token based on hwReport and userData.
    maa_token = maaClientInstance.GetMAAToken(hwReportBase64, userDataBase64).get();
    LOG_INFO(L"MAA token: \n%ws\n", maa_token.c_str());

    UINT32 keyDataSize = ((ATTESTATION_REPORT*)Report)->HclData.KeyDataSize;
    UINT8* keyData = ((ATTESTATION_REPORT*)Report)->HclData.KeyData;
    LOG_INFO(L"Key data size in HCL data: \n%d\n", keyDataSize);
    LOG_INFO(L"Key data in HCL data:\n");
    for (UINT32 i = 0; i < keyDataSize; i++) {
        LOG_INFO("%02x ", keyData[i]);
    }
    LOG_INFO(L"\n");

    ((ATTESTATION_REPORT*)Report)->HclData.KeyData;
    clients::ccf_skr_client ccfSkrClientInstance(m_igvmIdentity);
    // TODO: Temporarily override the maa_token with the hardcoded value that can be accepted by ccf server.
    maa_token = L"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkN0VHVoTUptRDVNN0RMZHpEMnYyeDNRS1NSWSIsImtpZCI6IkN0VHVoTUptRDVNN0RMZHpEMnYyeDNRS1NSWSJ9.eyJhdWQiOiJodHRwczovL3ZhdWx0LmF6dXJlLm5ldCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzcyZjk4OGJmLTg2ZjEtNDFhZi05MWFiLTJkN2NkMDExZGI0Ny8iLCJpYXQiOjE1ODgwMjg4MzQsIm5iZiI6MTU4ODAyODgzNCwiZXhwIjoxNTg4MTE1NTM0LCJhaW8iOiI0MmRnWUhqanhaZWQrYWJBLzdsUVVoNXZpZXdjQUE9PSIsImFwcGlkIjoiNzZjMzA3YzYtOWMwMS00NDk3LTg5MTEtMzRkNDFlZjE2YTM1IiwiYXBwaWRhY3IiOiIxIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3LyIsIm9pZCI6ImUzMDQ1YmJmLWIyNDMtNDhmOC1hNDA2LWMwZWUwMTcwOGQwMCIsInJoIjoiMC5BUm9BdjRqNWN2R0dyMEdScXkxODBCSGJSOFlIdzNZQm5KZEVpUkUwMUI3eGFqVWFBQUEuIiwic3ViIjoiZTMwNDViYmYtYjI0My00OGY4LWE0MDYtYzBlZTAxNzA4ZDAwIiwidGlkIjoiNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3IiwidXRpIjoiWjhzbEFGaS1HMGFmVG54c2Z0TnlBQSIsInZlciI6IjEuMCJ9.VJW1gy4I3ztpngGgTYmR1Y6oxoV5Tgc_MbVpGmZaH5FW2jljGgasF8wSWLwSex0PmWTdJJ7eq3-JCblrL0bTJOkKspTLayDZFKs81kuh6UQxxnR0xvzKvMGfLuYmzi33LCYtAgf_ApVtUGGQjCIrI-_REu__Eu1CJiArClOwZqiTQGn6-Yf4C7RywWcvCvdc5viPh1Y1awTa-6n9AyeP82qnvq5J7vKZXaUJLDZYTG7gLQbg7xyXsUevvGJcpxSU9kk0ViXNTREtPHc-O5ahrYIkbUVNUBb4tgNcwLJoz5rN0YV_MMKZpNqpRUSMR7kOOelsk3eFEeRW0rrQDUXKrA";
    auto ccfKey = ccfSkrClientInstance.release_key(U("hardcoded_key_for_test_0"), U("3"), maa_token, U("secret_0")).get();
    LOG_INFO(L"ccf-released key size: \n%d\n", ccfKey.size());
    LOG_INFO(L"ccf-released key:\n");
    for (int i = 0; i < ccfKey.size(); i++)
    {
        LOG_INFO("%02x ", ccfKey[i]);
    }
    LOG_INFO(L"\n");

    RETURN_IF_FAILED(CreateResponse(userData, userDataBufferSize, ResponseBuffer, WrittenSize));
    return S_OK;
}

HRESULT
IGVmAgent::IGVmEkCertRequest(
    _In_reads_bytes_(ReportSize) const BYTE* Report,
                                    UINT32   ReportSize,
                            gsl::span<BYTE>  ResponseBuffer,
    _Inout_                         UINT32*  WrittenSize
    )
/*++

Routine Description:

    This routine is called to return an Ek Cert.
    The Report UserData contains EkPub.

Arguments:

    Response - Buffer to receive reponse.

    ResponseSize -
        _In_ Response buffer size.
        _Out_ Length of data written to buffer.

Return Value:

    HRESULT

--*/
{
    UNREFERENCED_PARAMETER(Report);
    UNREFERENCED_PARAMETER(ReportSize);
    UNREFERENCED_PARAMETER(ResponseBuffer);

    LOG_STRING(L"EKCert request received.");
    *WrittenSize = 0;
    return S_OK;
}


HRESULT
IGVmAgent::IGVmAttest(
    _In_reads_bytes_(ReportSize) const BYTE* Report,
                                     UINT32  ReportSize,
                                 const BYTE* AttestationURI,
                                     UINT32  AttestationURISize,
                            gsl::span<BYTE>  ResponseBuffer,
    _Inout_                          UINT32* WrittenSize
    )
/*++

Routine Description:

    This routine is called on attestation requests,
    and calls specific routines for different request types.

Arguments:

    Response - Buffer to receive reponse.

    ResponseSize -
        _In_ Response buffer size.
        _Out_ Length of data written to buffer.

Return Value:

    HRESULT

--*/
{
    RETURN_HR_IF(E_INVALIDARG, ReportSize < sizeof(ATTESTATION_REPORT));

    if (((ATTESTATION_REPORT *)Report)->HclData.RequestType == KeyReleaseRequest)
    {
        return IGVmKeyReleaseRequest(Report, ReportSize, AttestationURI, AttestationURISize, ResponseBuffer, WrittenSize);
    }
    else if (((ATTESTATION_REPORT *)Report)->HclData.RequestType == EkCertRequest)
    {
        return IGVmEkCertRequest(Report, ReportSize, ResponseBuffer, WrittenSize);
    }
    else
    {
        RETURN_HR(E_INVALIDARG);
    }
}
