/*++
Copyright (c) Microsoft Corporation
--*/

#include <tests.h>
#include <clients/maa_client.h>

using namespace clients;
using namespace agent;

std::wstring read_file(std::wstring file_path)
{
    std::wifstream fs(file_path);
    AGENT_TEST(fs);
    std::wstringstream string_stream;
    string_stream << fs.rdbuf();
    return string_stream.str();
}

void main()
{
    static constexpr auto IGVM_TENANT_ID = U("72f988bf-86f1-41af-91ab-2d7cd011db47");
    static constexpr auto IGVM_CLIENT_ID = U("78dc3e40-2d45-4b3c-96c2-64e8373b76a0");
    static constexpr auto IGVM_CLIENT_SECRET = U("6.iCi4Q21mg7Wi5~UmSc2_s.r10c4hwYFh");

    static constexpr auto OE_SGX_EVIDENCE_BASE64_FILE = U("./data/oe_sgx_evidence_base64");
    static constexpr auto SGX_ENC_HELD_DATA_BASE64_FILE = U("./data/sgx_enc_held_data_base64");

    identity igvm_id(IGVM_TENANT_ID, IGVM_CLIENT_ID, IGVM_CLIENT_SECRET);
    maa_client client_instance(igvm_id);

    std::wstring oe_sgx_evidence_base64 = read_file(OE_SGX_EVIDENCE_BASE64_FILE);
    std::wstring sgx_enc_held_data_base64 = read_file(SGX_ENC_HELD_DATA_BASE64_FILE);
    utility::string_t maa_token = U("");
    printf("OE SGX evidence in base64 format: \n%ws\n", oe_sgx_evidence_base64.c_str());
    printf("SGX enclave held data in base64 format: \n%ws\n", sgx_enc_held_data_base64.c_str());

    try
    {
        auto task = client_instance.GetMAAToken(
            oe_sgx_evidence_base64,
            sgx_enc_held_data_base64);
        maa_token = task.get();

        printf("MAA token: \n%ws\n", maa_token.c_str());
        AGENT_TEST(!maa_token.empty());
    }
    catch (std::exception& e)
    {
        printf("Exception: %s\n", e.what());
        AGENT_TEST(false);
    }
}