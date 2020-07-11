/*!
 * Copyright (c) Microsoft Corporation
 * Abstract:
 *    Secure Key Release class header file
 */

#pragma once

#include <wil/resource.h>
#include <cpprest/http_client.h>
#include <clients/aad_client.h>
#include <common/identity.h>

namespace clients
{
    class skr_client
    {       

    public:
        skr_client()
        {

        };
        virtual ~skr_client() 
        {

        };

        /*!
         * Create a key.
         *
         * \param key_name[in] The name of the key to create.
         * \param policy[in] Policy string in json format.
         * \param secret[in] Secret string to used for key derivation.
         *
         * \return key_version The key version of the newly created key.
         *
         */
        virtual pplx::task<utility::string_t> create_key(
            const utility::string_t& key_name,
            const utility::string_t& policy,
            const utility::string_t& secret) noexcept(false) = 0;

        /*!
         * Release the key for the given key_name and key_version.
         *
         * \param key_name[in]    The name of the key to release.
         * \param key_version[in] The version of the key to release.
         * \param maa_token[in]   The MAA token from attestation service.
         * \param secret[in]      Secret string to used for key derivation.
         *
         * \return encrypted_key The encrypted key
         *
         */
        virtual pplx::task<std::vector<BYTE>> release_key(
            const utility::string_t& key_name,
            const utility::string_t& key_version,
            const utility::string_t& maa_token,
            const utility::string_t& secret) noexcept(false) = 0;

    protected:

    private:
        skr_client(const skr_client& rhs);
        skr_client& operator=(const skr_client& rhs);
    };
}
