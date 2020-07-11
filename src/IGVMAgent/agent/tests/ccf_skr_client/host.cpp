/*++
Copyright (c) Microsoft Corporation
--*/

#include <windows.h>
#include <tests.h>
#include <clients/ccf_skr_client.h>

#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>

const utility::string_t POLICY_FILE = L"./data/skr_policy.json";
static const std::vector<utility::string_t> NEGATIVE_TEST_POLICIES = {
    L"./data/skr_policy invalid_mrsigner.json",
    L"./data/skr_policy invalid_key_size.json",
    L"./data/skr_policy invalid_not_exportable.json"
};

using namespace clients;
using namespace agent;

utility::string_t _maa_token = L"eyJhbGciOiAiUlMyNTYiLCAiamt1IjogImh0dHBzOi8vc2hhcmVkdWtzLnVrcy5hdHRlc3QuYXp1cmUubmV0L2NlcnRzIiwgImtpZCI6ICJLUUZBSHJrMXhBTEtIQkQ0YjR1N1RDdkNKMU13ME1sWVplK3J4ZGVQT3RnPSIsICJ0eXAiOiAiSldUIn0.eyJhYXMtZWhkIjogIkxTMHRMUzFDUlVkSlRpQlFWVUpNU1VNZ1MwVlpMUzB0TFMwS1RVbEpRa2xxUVU1Q1oydHhhR3RwUnpsM01FSkJVVVZHUVVGUFEwRlJPRUZOU1VsQ1EyZExRMEZSUlVGcU9YUjFhR2d6VDIxTE5YRkpVVWR4UlRBd1JRcERaVEJYYTJwWFFubGlRU3RJZFdRMVFrUkljM1Z0TUdnNFYzZEpNMlZqUm01WFRYZEVXbUYzY25kQlMzQXhPSFJUZEUwMFpVOUxkamhUT0d0T1VVZzFDazlyYWpGUFpWTnBUREJFU1Zkb2NqUTRZbUpvTkU1VmN6RlRhMFpIV1c5c2IxUTVPVkoxZEU5bFpsWm5XRGxuYkZOU05XZENiWE5pTWpsNlZuWm9OM2dLVVVaaVNETlZTR3hJWkVSVFFrSTJORU4yU1hSUWR6VnpZMHhvUlVsaVZFaHpXVU56UkVoQ2RqSnpjM1FyWmpGRVZGZFZjME12YzBoMFIzSkZNVEpNY1FvdlRURXJSbE4xZDJ4NGJIaHhWMHBaWmpSRGFHNU1PVGd6Wms1WmVXWXphRmhvY0VWdVEybElhRmRxUm5RNFMwRmxZMjFtTTJwVmNWYzFORVo2YVdNMUNtWlNaRlZSVEhwMFluVXdWbmt3Y3pCMU5uQm5WV1Z2THpjMmRuRkNVREp4ZUZndlowVjJaRXhsZHpCM1EzVkNhSGxDVkVvclF6UnliMnhNTmpjcmFGb0tjVkZKUkVGUlFVSUtMUzB0TFMxRlRrUWdVRlZDVEVsRElFdEZXUzB0TFMwdENnQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBIiwgImV4cCI6IDE1OTQ0MzQ1NzYsICJpYXQiOiAxNTk0NDA1Nzc2LCAiaXMtZGVidWdnYWJsZSI6IHRydWUsICJpc3MiOiAiaHR0cHM6Ly9zaGFyZWR1a3MudWtzLmF0dGVzdC5henVyZS5uZXQiLCAibWFhLWF0dGVzdGF0aW9uY29sbGF0ZXJhbCI6IHsibWFhLXFlaWRjZXJ0c2hhc2giOiAiMWIyYTdjZDU5NjY5MjlhZWMxZTA2MWY0N2FiYTAzYWU0MjJjMTFlOWY4ZGNlNDIxMmMyYmIzNjA5MjIyZjMyNCIsICJtYWEtcWVpZGNybGhhc2giOiAiZWEzODI1YjhkM2E5NDRjM2UxZDg0OWNhODE3ZGE1NGEzZDRiODM0OWM0NzY5NjcwODhkMDczODZlZTA2MjE0MiIsICJtYWEtcWVpZGhhc2giOiAiNjY4MjZjNWQxZjI3OGEzMDNmZTExYzZiZDlkNDNlZGRiMzIyOTBiYzViYTY0MTQ3YjExZjIxYWI4Nzc4N2I0MyIsICJtYWEtcXVvdGVoYXNoIjogImEwYTI3YzY3NTMxYTRlYTdhNGIxYWNiNTNkMDFiYTE2NTU4M2RkYTRlZDEwNzA5OWFmNGZmMWNjYjQyNGY3NGYiLCAibWFhLXRjYmluZm9jZXJ0c2hhc2giOiAiMWIyYTdjZDU5NjY5MjlhZWMxZTA2MWY0N2FiYTAzYWU0MjJjMTFlOWY4ZGNlNDIxMmMyYmIzNjA5MjIyZjMyNCIsICJtYWEtdGNiaW5mb2NybGhhc2giOiAiZWEzODI1YjhkM2E5NDRjM2UxZDg0OWNhODE3ZGE1NGEzZDRiODM0OWM0NzY5NjcwODhkMDczODZlZTA2MjE0MiIsICJtYWEtdGNiaW5mb2hhc2giOiAiMDA4MWQwMzJhYTZmODViZmJmZDk1YTI2MzQxZjY2OWM2NDllMWRiNGFiOWYwOWI3ODMyODM0NTc3YzdkNzFiNyJ9LCAibWFhLWVoZCI6ICJMUzB0TFMxQ1JVZEpUaUJRVlVKTVNVTWdTMFZaTFMwdExTMEtUVWxKUWtscVFVNUNaMnR4YUd0cFJ6bDNNRUpCVVVWR1FVRlBRMEZST0VGTlNVbENRMmRMUTBGUlJVRnFPWFIxYUdnelQyMUxOWEZKVVVkeFJUQXdSUXBEWlRCWGEycFhRbmxpUVN0SWRXUTFRa1JJYzNWdE1HZzRWM2RKTTJWalJtNVhUWGRFV21GM2NuZEJTM0F4T0hSVGRFMDBaVTlMZGpoVE9HdE9VVWcxQ2s5cmFqRlBaVk5wVERCRVNWZG9jalE0WW1Kb05FNVZjekZUYTBaSFdXOXNiMVE1T1ZKMWRFOWxabFpuV0RsbmJGTlNOV2RDYlhOaU1qbDZWblpvTjNnS1VVWmlTRE5WU0d4SVpFUlRRa0kyTkVOMlNYUlFkelZ6WTB4b1JVbGlWRWh6V1VOelJFaENkakp6YzNRclpqRkVWRmRWYzBNdmMwaDBSM0pGTVRKTWNRb3ZUVEVyUmxOMWQyeDRiSGh4VjBwWlpqUkRhRzVNT1RnelprNVplV1l6YUZob2NFVnVRMmxJYUZkcVJuUTRTMEZsWTIxbU0ycFZjVmMxTkVaNmFXTTFDbVpTWkZWUlRIcDBZblV3Vm5rd2N6QjFObkJuVldWdkx6YzJkbkZDVURKeGVGZ3ZaMFYyWkV4bGR6QjNRM1ZDYUhsQ1ZFb3JRelJ5YjJ4TU5qY3JhRm9LY1ZGSlJFRlJRVUlLTFMwdExTMUZUa1FnVUZWQ1RFbERJRXRGV1MwdExTMHRDZ0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsICJtYWEtcG9saWN5SGFzaCI6ICIyMDBlMjcxNzM5MmJmYjE4N2I4OWM3YzQ5OGI4ZTVlYmNkNmFkMTM2ZGMwY2RiNWI4OTdmZGIxM2UzNDRjYTQwIiwgIm5iZiI6IDE1OTQ0MDU3NzYsICJwcm9kdWN0LWlkIjogMSwgInNneC1tcmVuY2xhdmUiOiAiMzgxMTYyNDRhYWMxNjczODExNmZkNjNmZWUzNzJkZGJjZmVjOTYzNDA1NDc0NjI0ZjJiNDM1OGVmOWRlYTM2MyIsICJzZ3gtbXJzaWduZXIiOiAiNGMxYWMyZGJkYzdjZTcxYTg2ZTMyZTA3NWE4ZmQ1MDViOTI4Y2Q0YzcyMzA4ZWM2YzZiZjVjZWM3YTFjMDczZSIsICJzdm4iOiAxLCAidGVlIjogInNneCJ9.Xf8CiTbSHFD-ONM75NblUqHDvBgL3YvJ5Ya3FzQbaV8FyzHisypCMI2c-0I_4nlE5MIC9YcfnKEV7_aWxX870M6xOjvxhTvbwi1dDbTFzfyYnXHw88aQLZRrq6gH8UAISoidca5tHlYAe4YlzZRhRhetWuYPui2LCPRiAiZIj00";


void test_create_and_release(
    ccf_skr_client& client,
    bool negative_test,
    const utility::string_t& key_name,
    const utility::string_t& policy_file,
    const utility::string_t& secret_data)
{
    utility::string_t key_version;
    utility::string_t policy;
    std::wifstream fs(policy_file);
    AGENT_TEST(fs);

    printf("Testing file: %ws\n", policy_file.c_str());
    std::wstringstream ss;
    ss << fs.rdbuf();
    fs.close();

    policy = ss.str();
    try
    {
        auto task = client.create_key(
            key_name,
            policy,
            secret_data);
        task.wait();
        key_version = task.get();
    }
    catch (ccf_skr_exception& e)
    {
        if (negative_test)
        {
            printf("EXPECTED Error: %s\n", e.what());
            return;
        }
        else
        {
            printf("Error: %s\n", e.what());
            AGENT_TEST(false);
        }
    }

    try
    {
        auto task = client.release_key(
            key_name,
            key_version,
            _maa_token,
            secret_data);

        task.wait();
        auto key = task.get();
        printf("Key size: %zu\n", key.size());
        AGENT_TEST(key.size() == 32);
        for (int i = 0; i < key.size(); i++)
        {
            printf("%02x ", key[i]);
        }
        printf("\n\n");
    }
    catch (ccf_skr_exception& e)
    {
        if (negative_test)
        {
            printf("EXPECTED Error: %s\n", e.what());
            return;
        }
        else
        {
            printf("Error: %s\n", e.what());
            AGENT_TEST(false);
        }      
    }
}

int main(int argc, const char* argv[])
{
    static constexpr auto IGVM_TENANT_ID = U("72f988bf-86f1-41af-91ab-2d7cd011db47");
    static constexpr auto IGVM_USER_MSI_CLIENT_ID = U("14d459e3-889f-4097-b058-8bcb936ff778");
    static constexpr auto IGVM_USER_MSI_CLIENT_SECRET= U("");

    static constexpr auto IGVM_APP_CLIENT_ID = U("000ae001-6c2f-4d4d-853f-de6809d231bd");
    static constexpr auto IGVM_APP_CLIENT_SECRET = U("6.iCi4Q21mg7Wi5~UmSc2_s.r10c4hwYFh");

    identity id(IGVM_TENANT_ID, IGVM_USER_MSI_CLIENT_ID, IGVM_USER_MSI_CLIENT_SECRET);
    ccf_skr_client client(id);

    test_create_and_release(client, false, L"valid_key", POLICY_FILE, L"secret_0");
    test_create_and_release(client, false, L"valid_key", POLICY_FILE, L"");
    test_create_and_release(client, true, L"", POLICY_FILE, L"");

    // Negative key release tests
    for (const utility::string_t v : NEGATIVE_TEST_POLICIES)
    {
        test_create_and_release(client, true, L"failing_key", v, L"negative_test");
    }

    // Test release of invalid key
    try
    {
        auto task = client.release_key(
            L"UNKNOWN",
            L"0",
            _maa_token,
            L"hello");
        task.wait();

        printf("ERROR: release_key should have failed.\n");
        AGENT_TEST(false);
    }
    catch (ccf_skr_exception& e)
    {
        printf("EXPECTED Error: %s\n", e.what());
    }

    return 0;
}
