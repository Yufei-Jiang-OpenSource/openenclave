#include <tests.h>
#include <IGVmAgentRpc.h>
#include "pch.h"
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <iomanip>

using namespace std;
using namespace agent;

const UINT32 EXPECTED_HCL_DATA_SIZE = 303;
const UINT32 EXPECTED_VERSION = 1;
const UINT32 EXPECTED_TOTAL_SIZE = 339; 
const UINT32 RESPONSE_BUFFER_SIZE = 4096;
const char *REPORT_FILE = "./data/snp_report_mem.bin";

int call_remote_function(
    GUID VmId,
    LPCWSTR VmName,
    UINT32 KeyURISize,
    BYTE *KeyURI,
    UINT32 AttestationURISize,
    BYTE *AttestationURI,
    UINT32 ReportSize,
    BYTE *Report,
    UINT32 ResponseBufferSize,
    UINT32 *ResponseWrittenSize,
    BYTE *Response)
{
    RPC_STATUS status;
    RPC_WSTR szStringBinding = nullptr;
    handle_t hRpcBinding = nullptr;

    status = RpcStringBindingComposeW(
        NULL,
        (RPC_WSTR)L"ncalrpc",
        NULL,
        (RPC_WSTR)IGVM_AGENT_RPC_ENDPOINT,
        NULL,
        &szStringBinding);

    if (status)
        exit(status);

    status = RpcBindingFromStringBindingW(
        szStringBinding,
        &hRpcBinding);

    RpcTryExcept
    {
        RpcIGVmAttest(
            hRpcBinding,
            VmId,
            VmName,
            AttestationURISize,
            AttestationURI,
            KeyURISize,
            KeyURI,
            ReportSize,
            Report,
            ResponseBufferSize,
            ResponseWrittenSize,
            Response);
    }
    RpcExcept(1)
    {
        LOG_ERROR("Runtime reported exception: %lu", RpcExceptionCode());
    }
    RpcEndExcept

    status = RpcStringFreeW(&szStringBinding);
    if (status)
        exit(status);

    status = RpcBindingFree(
        &hRpcBinding);

    if (status)
        exit(status);

    return status;
}

void main()
{
    UINT32 ResponseWrittenSize = 0;
    GUID dummy_vmid = {0x11f83073, 0x7ff4, 0xbc41, 0xa4, 0xff, 0xe7, 0x92, 0xd0, 0x73, 0xf4, 0x1f};
    char *key_uri = "key_uri";
    char *attestation_uri = "https://tradewinds.us.attest.azure.net";

    std::ifstream fs(REPORT_FILE, ios::in | ios::binary | ios::ate);
    streampos report_size;
    char *report_block = NULL;

    if (fs.is_open())
    {
        report_size = fs.tellg();
        report_block = new char[report_size];
        fs.seekg(0, ios::beg);
        fs.read(report_block, report_size);
        fs.close();

        LOG_INFO(L"the entire report struct is in memory");
    }

    BYTE Response[RESPONSE_BUFFER_SIZE];
    memset(Response, 0, RESPONSE_BUFFER_SIZE);

    ATTESTATION_REPORT* report = (ATTESTATION_REPORT*)report_block;
    AGENT_TEST(report->HclData.ReportType == SnpVmReport);
    AGENT_TEST(report->Header.ReportSize == sizeof(ATTESTATION_HEADER) + sizeof(HW_ATTESTATION) + EXPECTED_HCL_DATA_SIZE);
    AGENT_TEST(report->HclData.DataSize == EXPECTED_HCL_DATA_SIZE);

    int status = call_remote_function(
        dummy_vmid,
        L"dummy_vm_name",
        (UINT32)strlen(attestation_uri),
        (BYTE*)attestation_uri,
        (UINT32)strlen(key_uri),
        (BYTE *)key_uri,
        (UINT32)report_size,
        (BYTE *)report_block,
        RESPONSE_BUFFER_SIZE,
        &ResponseWrittenSize,
        Response);
    AGENT_TEST(status == 0);

    IGVM_KEY_MESSAGE_HEADER* payloadHeader = (IGVM_KEY_MESSAGE_HEADER*)Response;
    LOG_INFO("IGVM_KEY_MESSAGE_HEADER Data: %d", payloadHeader->DataSize);
    LOG_INFO("IGVM_KEY_MESSAGE_HEADER Version: %d", payloadHeader->Version);
    LOG_INFO("IGVM_KEY_MESSAGE_HEADER EncryptedTransportKeyOffset: %d", payloadHeader->EncryptedTransportKeyOffset);
    LOG_INFO("IGVM_KEY_MESSAGE_HEADER EncryptedTransportKeyLength: %d", payloadHeader->EncryptedTransportKeyLength);
    LOG_INFO("IGVM_KEY_MESSAGE_HEADER EncryptedKeyArrayOffset: %d", payloadHeader->EncryptedKeyArrayOffset);
    LOG_INFO("IGVM_KEY_MESSAGE_HEADER EncryptedKeyArrayLength: %d", payloadHeader->EncryptedKeyArrayLength);
    LOG_INFO("ResponseWrittenSize: %d", ResponseWrittenSize);
    AGENT_TEST(payloadHeader->Version == EXPECTED_VERSION);
    AGENT_TEST(payloadHeader->DataSize == EXPECTED_TOTAL_SIZE);

    utility::ostringstream_t ccfKeyStream;
    ccfKeyStream << std::hex;
    for (UINT32 i = 0; i < payloadHeader->EncryptedKeyArrayLength; i++)
    {
        ccfKeyStream << std::setfill(L'0') << std::setw(2) << (int)Response[payloadHeader->EncryptedKeyArrayOffset+i] << ' ';
    }
    LOG_INFO(L"ccf-released key: \n%ws", ccfKeyStream.str().c_str());

    if (report_block)
    {
        delete [] report_block;
    }
}

void *__RPC_USER midl_user_allocate(size_t size)
{
    return malloc(size);
}

void __RPC_USER midl_user_free(void *p)
{
    free(p);
}