/*!
 * Copyright (c) Microsoft Corporation
 * Abstract:
 *    Secure Key Release class using AKV server
 */

#pragma once

#include <clients/skr_client.h>
#include <common/identity.h>

namespace clients
{
    class akv_skr_exception : public client_exception
    {
    private:
        akv_skr_exception();

    public:
        akv_skr_exception(web::json::value& result)
            : client_exception(result)
        {
        }
        akv_skr_exception(const std::string& message)
            : client_exception(message)
        {
        }
        akv_skr_exception(const web::http::http_response& response)
            : client_exception(response)
        {
        }
    };

    class akv_skr_client : public skr_client
    {
        static constexpr auto AKV_SERVER_URI = U("https://sewong-akv.vault.azure.net/");
        static constexpr auto AKV_SERVER_VERSION = U("2016-10-01");
        static constexpr auto AKV_SERVER_SCOPE = U("https://vault.azure.net/.default");
        static constexpr auto AKV_SERVER_SCOPE_MSI = U("https://vault.azure.net");

    public:
        akv_skr_client(agent::identity& id);
        virtual ~akv_skr_client();

        /*!
         * Create a key.
         *
         * \param key_name[in] The name of the key to create.
         * \param policy[in] Policy string in json format.
         * \param secret[in] Secret string to used for key derivation.
         *
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
         *
         * \return encrypted_key The encrypted key
         */
        virtual pplx::task<std::vector<BYTE>> release_key(
            const utility::string_t& key_name,
            const utility::string_t& key_version,
            const utility::string_t& maa_token,
            const utility::string_t& secret) noexcept(false);

    private:
        akv_skr_client();
        akv_skr_client(const akv_skr_client& rhs);
        akv_skr_client& operator=(const akv_skr_client& rhs);

        web::http::client::http_client* _client;
        web::http::client::http_client_config _config;
        web::http::uri_builder _urib;
        web::http::oauth2::experimental::oauth2_token _authentication_token;
    };
}
