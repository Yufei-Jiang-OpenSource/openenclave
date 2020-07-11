/*!
 * Copyright (c) Microsoft Corporation
 * Abstract:
 *    Microsoft Azure Attestation (MAA) Client class header file
 */

#pragma once

#include <clients/aad_client.h>
#include <common/identity.h>
#include <cpprest/http_client.h>

namespace clients
{
    class maa_client_exception : public client_exception
    {
    private:
        maa_client_exception();

    public:
        maa_client_exception(web::json::value& result)
            : client_exception(result)
        {
        }
        maa_client_exception(const std::string& message)
            : client_exception(message)
        {
        }
        maa_client_exception(const web::http::http_response& response)
            : client_exception(response)
        {
        }
    };

    class maa_client
    {
    public:
        static constexpr auto MAA_URI = U("https://shareduks.uks.attest.azure.net");
        static constexpr auto MAA_SCOPE = U("https://attest.azure.net/.default");

        /* Body fields */
        static constexpr auto REPORT = U("Quote");
        static constexpr auto ENCLAVE_HELD_DATA = U("EnclaveHeldData");

        static constexpr auto MAA_OE_SGX_PATH = U("/attest/Tee/OpenEnclave");
        static constexpr auto MAA_API_VERSION = U("2018-09-01-preview");
        
        maa_client(agent::identity& id);
        virtual ~maa_client();

        /*!
         * Get the attestation verification results token returned by the MAA.
         *
         * \param report_base64url[in]          The remote attestation report
         * \param private_data_base64url[in]    The customer held data
         *
         * \return authentication_token         The token returned by MAA
         */
        virtual pplx::task<utility::string_t> GetMAAToken(
            const utility::string_t& report_base64url,
            const utility::string_t& private_data_base64url);

    private:
        maa_client();
        maa_client(const maa_client& rhs);
        maa_client& operator=(const maa_client& rhs);

        web::http::client::http_client* _client;
        web::uri_builder _maa_urib;
        web::http::oauth2::experimental::oauth2_token _authentication_token;
    };
}