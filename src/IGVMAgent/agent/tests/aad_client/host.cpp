/*++
Copyright (c) Microsoft Corporation
--*/

#include <tests.h>
#include <clients/aad_client.h>

using namespace clients;

void main()
{
    aad_client client_instance;
    auto task = client_instance.GetAADToken(
        U("72f988bf-86f1-41af-91ab-2d7cd011db47"),
        U("78dc3e40-2d45-4b3c-96c2-64e8373b76a0"),
        U("6.iCi4Q21mg7Wi5~UmSc2_s.r10c4hwYFh"),
        U("https://vault.azure.net/.default"));
    auto authentication_token = task.get();

    AGENT_TEST(authentication_token.is_valid_access_token());
}