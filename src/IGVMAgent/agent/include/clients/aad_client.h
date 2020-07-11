/*!
 * Copyright (c) Microsoft Corporation
 * Abstract:
 *    AAD Client class header file
 */

#pragma once

#include <clients/client_exceptions.h>
#include <wil/resource.h>
#include <cpprest/http_client.h>
#include <common/identity.h>

namespace clients
{
    class aad_client_exception : public client_exception
    {
    private:
        aad_client_exception();

    public:
        aad_client_exception(web::json::value& result)
        : client_exception(result)
        {
        }
        aad_client_exception(const std::string& message)
        : client_exception(message)
        {
        }
        aad_client_exception(const web::http::http_response& response)
        : client_exception(response)
        {
        }
    };

    class aad_client
    {
    public:
        static constexpr auto AAD_URI = L"https://login.windows.net/";

        //http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.Azure.com/
        static constexpr auto MSI_USER_IDENTITY_VM_URI = L"http://169.254.169.254/metadata/identity/oauth2/token";

        //http://127.0.0.1:<IMDS_PORT>/metadata/identity/oauth2/token?cid=<container id>&api-version=2018-02-01&resource=https://management.azure.com/
        static constexpr auto MSI_USER_IDENTITY_HOST_URI = L"http://127.0.0.1:8889/metadata/identity/oauth2/token";

        static constexpr auto CONTENT_TYPE = L"application/x-www-form-urlencoded";

        aad_client();
        virtual ~aad_client();

        /*!
        * Get the AAD oauth2 authentication token.
        *
        * \param id[in]                    The id of the igvmagent.
        * \param scope[in]                 The scope of the token audience.
        *
        * \result authentication_token     The authentication token
        */
        virtual pplx::task<web::http::oauth2::experimental::oauth2_token> GetAADToken(
            const agent::identity& id,
            const utility::string_t& scope);

        /*!
         * Get the AAD oauth2 authentication token.
         *
         * \param tenant_id[in]             The id of the tenant.
         * \param client_id[in]             The id of the client.
         * \param secret[in]                The shared secret between the app and the AAD.
         * \param scope[in]                 The scope of the token audience.
         *
         * \result authentication_token     The authentication token
         */
        virtual pplx::task<web::http::oauth2::experimental::oauth2_token> GetAADToken(
            const utility::string_t& tenant_id,
            const utility::string_t& client_id,
            const utility::string_t& secret,
            const utility::string_t& scope);

        void GetAADUserMsiTokenFromHost(
            const utility::string_t& container_id,
            const utility::string_t& scope,
            web::http::oauth2::experimental::oauth2_token& authentication_token);

        void GetAADUserMsiTokenFromVm(
            const utility::string_t& scope,
            web::http::oauth2::experimental::oauth2_token& authentication_token);

    protected:
        web::http::client::http_client* _aad_http_client;
        
    private:
        aad_client(const aad_client& rhs);
        aad_client& operator=(const aad_client& rhs);
    };
}