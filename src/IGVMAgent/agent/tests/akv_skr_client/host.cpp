/*++
Copyright (c) Microsoft Corporation
--*/

#include <windows.h>
#include <tests.h>
#include <clients/akv_skr_client.h>

#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <exception>

const std::wstring POLICY_FILE = L"./data/skr_policy.json";
static const std::vector<std::wstring> NEGATIVE_TEST_POLICIES = {
    L"./data/skr_policy invalid_mrsigner.json",
    L"./data/skr_policy invalid_key_size.json",
    L"./data/skr_policy invalid_not_exportable.json"
};

using namespace clients;
using namespace agent;

std::wstring _maa_token = L"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkN0VHVoTUptRDVNN0RMZHpEMnYyeDNRS1NSWSIsImtpZCI6IkN0VHVoTUptRDVNN0RMZHpEMnYyeDNRS1NSWSJ9.eyJhdWQiOiJodHRwczovL3ZhdWx0LmF6dXJlLm5ldCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzcyZjk4OGJmLTg2ZjEtNDFhZi05MWFiLTJkN2NkMDExZGI0Ny8iLCJpYXQiOjE1ODgwMjg4MzQsIm5iZiI6MTU4ODAyODgzNCwiZXhwIjoxNTg4MTE1NTM0LCJhaW8iOiI0MmRnWUhqanhaZWQrYWJBLzdsUVVoNXZpZXdjQUE9PSIsImFwcGlkIjoiNzZjMzA3YzYtOWMwMS00NDk3LTg5MTEtMzRkNDFlZjE2YTM1IiwiYXBwaWRhY3IiOiIxIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3LyIsIm9pZCI6ImUzMDQ1YmJmLWIyNDMtNDhmOC1hNDA2LWMwZWUwMTcwOGQwMCIsInJoIjoiMC5BUm9BdjRqNWN2R0dyMEdScXkxODBCSGJSOFlIdzNZQm5KZEVpUkUwMUI3eGFqVWFBQUEuIiwic3ViIjoiZTMwNDViYmYtYjI0My00OGY4LWE0MDYtYzBlZTAxNzA4ZDAwIiwidGlkIjoiNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3IiwidXRpIjoiWjhzbEFGaS1HMGFmVG54c2Z0TnlBQSIsInZlciI6IjEuMCJ9.VJW1gy4I3ztpngGgTYmR1Y6oxoV5Tgc_MbVpGmZaH5FW2jljGgasF8wSWLwSex0PmWTdJJ7eq3-JCblrL0bTJOkKspTLayDZFKs81kuh6UQxxnR0xvzKvMGfLuYmzi33LCYtAgf_ApVtUGGQjCIrI-_REu__Eu1CJiArClOwZqiTQGn6-Yf4C7RywWcvCvdc5viPh1Y1awTa-6n9AyeP82qnvq5J7vKZXaUJLDZYTG7gLQbg7xyXsUevvGJcpxSU9kk0ViXNTREtPHc-O5ahrYIkbUVNUBb4tgNcwLJoz5rN0YV_MMKZpNqpRUSMR7kOOelsk3eFEeRW0rrQDUXKrA";

int main(int argc, const char* argv[])
{
    static constexpr auto IGVM_TENANT_ID = U("72f988bf-86f1-41af-91ab-2d7cd011db47");
    static constexpr auto IGVM_USER_MSI_CLIENT_ID = U("14d459e3-889f-4097-b058-8bcb936ff778");
    static constexpr auto IGVM_USER_MSI_CLIENT_SECRET= U("");

    static constexpr auto IGVM_APP_CLIENT_ID = U("000ae001-6c2f-4d4d-853f-de6809d231bd");
    static constexpr auto IGVM_APP_CLIENT_SECRET = U("P8onDIX4g2QG0.K~v~4E20mdhFg~nPw7~S");

    //identity id(IGVM_TENANT_ID, IGVM_USER_MSI_CLIENT_ID, IGVM_USER_MSI_CLIENT_SECRET);
    identity id(IGVM_TENANT_ID, IGVM_APP_CLIENT_ID, IGVM_APP_CLIENT_SECRET);
    akv_skr_client client(id);

    // Test release key
    try
    {
        auto task = client.release_key(
            L"keyname0",
            L"5dacadbe9fad41d987be170e218d9085",
            _maa_token,
            L"");
        task.wait();
        auto key = task.get();
        printf("Release_key JWK:\n");
        for (int i = 0; i < key.size(); i++)
        {
            printf("%02x ", key[i]);
        }
        printf("\n\n");
    }
    catch (std::exception& e)
    {
        printf("ERROR: %s\n", e.what());
        AGENT_TEST(false);
    }

    return 0;
}
