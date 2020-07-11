/*!
 * Copyright (c) Microsoft Corporation
 * Abstract:
 *    Secure Key Release class using AKV server
 */

#pragma once

#include <string>

namespace agent
{
    class identity
    {
    public:
        identity(
            std::wstring tenant_id,
            std::wstring client_id,
            std::wstring client_secret)
        : _tenant_id(tenant_id),
          _client_id(client_id),
          _client_secret(client_secret)
        {
            // Nothing to do
        };

        ~identity() {};

        std::wstring _tenant_id;
        std::wstring _client_id;
        std::wstring _client_secret;

    private:

    };
}