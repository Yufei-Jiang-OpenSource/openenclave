/*!
 * Copyright (c) Microsoft Corporation
 * Abstract:
 *    Secure Key Release class using CCF server
 */

#pragma once

#include <clients/skr_client.h>
#include <clients/aad_client.h>
#include <common/identity.h>

#include <bcrypt.h>

namespace clients
{
    class ccf_skr_exception : public client_exception
    {
    private:
        ccf_skr_exception();

    public:
        ccf_skr_exception(web::json::value& result)
            : client_exception(result)
        {
        }
        ccf_skr_exception(const std::string& message)
            : client_exception(message)
        {
        }
        ccf_skr_exception(const web::http::http_response& response)
            : client_exception(response)
        {
        }
    };

    class ccf_skr_client : public skr_client
    {
        static constexpr auto CCF_SERVER_URI = U("https://sewongccf.canadacentral.cloudapp.azure.com/");
        static constexpr auto CCF_SERVER_VERSION = U("0.0.1");
        static constexpr auto CCF_SERVER_SCOPE = U("https://vault.azure.net/.default");

    public:
        ccf_skr_client(agent::identity& id);
        virtual ~ccf_skr_client();

        /*!
         * Create a key.
         *
         * \param key_name[in] The name of the key to create.
         * \param policy[in] Policy string in json format.
         * \param secret[in] Secret string to used for key derivation.

         * \return key_version The key version of the newly created key.
         */
        virtual pplx::task<utility::string_t> create_key(
            const utility::string_t& key_name,
            const utility::string_t& policy,
            const utility::string_t& secret) noexcept(false);

        /*!
         * Release the key for the given key_name and key_version.
         *
         * \param key_name[in]    The name of the key to release.
         * \param key_version[in] The version of the key to release.
         * \param maa_token[in]   The MAA token from attestation service.
         * \param secret[in]      Secret string to used for key derivation.

         * \return encrypted_key The encrypted key
         */
        virtual pplx::task<std::vector<BYTE>> release_key(
            const utility::string_t& key_name,
            const utility::string_t& key_version,
            const utility::string_t& maa_token,
            const utility::string_t& secret) noexcept(false);

    private:
        ccf_skr_client();
        ccf_skr_client(const ccf_skr_client& rhs);
        ccf_skr_client& operator=(const ccf_skr_client& rhs);

        web::http::client::http_client* _client;
        web::http::client::http_client_config _config;
        web::http::uri_builder _urib;
        web::http::oauth2::experimental::oauth2_token _authentication_token;
        BCRYPT_ALG_HANDLE _hAlgo;

        void create_key_pair(
            BCRYPT_ALG_HANDLE hAlgo,
            DWORD keySize,
            DWORD* publicKeySize,
            PBYTE* publicKeyBuffer,
            DWORD* privateKeySize,
            PBYTE* privateKeyBuffer);
    };
}
