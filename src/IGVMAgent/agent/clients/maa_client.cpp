/*!
 * Copyright (c) Microsoft Corporation
 * Abstract:
 *    Microsoft Azure Attestation (MAA) Client class
 */

#include <clients/maa_client.h>
#include <cpprest/filestream.h>
#include <common/Logger.h>

#include <winhttp.h>

namespace clients
{
    using namespace utility;                    // Common utilities like string conversions
    using namespace web;                        // Common features like URIs.
    using namespace web::http;                  // Common HTTP functionality
    using namespace web::http::client;          // HTTP client features
    using namespace concurrency::streams;       // Asynchronous streams
    using namespace agent;

    maa_client::maa_client(agent::identity& id){
        http_client_config cfg;

        // Do not validate server cert
        cfg.set_validate_certificates(true);
        // No client certs
        cfg.set_nativehandle_options([](web::http::client::native_handle h)
        {
            BOOL win32Result = FALSE;
            win32Result = WinHttpSetOption(h,
                WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                WINHTTP_NO_CLIENT_CERT_CONTEXT,
                0);
            if (FALSE == win32Result)
            {
                LOG_ERROR("Failed to configure no client cert option: %x", HRESULT_FROM_WIN32(GetLastError()));
                throw maa_client_exception("Failed to configure no client cert option.");
            }
        });

        clients::aad_client c;
        try
        {
            auto task = c.GetAADToken(id, MAA_SCOPE);
            task.wait();

            _authentication_token = task.get();
        }
        catch (web::http::http_exception& e)
        {
            LOG_ERROR("http_exception: %s", e.what());
        }
        catch (std::exception& e)
        {
            LOG_ERROR("Unknown exception: %s", e.what());
        }

        uri_builder aad_uri(aad_client::AAD_URI);
        aad_uri.append(id._tenant_id);
        aad_uri.append(U("/oauth2/v2.0/token"));

        oauth2::experimental::oauth2_config oauth2_config(
            id._client_id,
            id._client_secret,
            L"",                    // Auth endpoint
            aad_uri.to_string(),    // token endpoint
            L"",                    // Redirect URI
            MAA_SCOPE);
        oauth2_config.set_token(_authentication_token);
        oauth2_config.set_bearer_auth(true);
        cfg.set_oauth2(oauth2_config);
        _client = new web::http::client::http_client(MAA_URI, cfg);
    }
    maa_client::~maa_client()
    {
        free(_client);
        _client = nullptr;
    }

    pplx::task<utility::string_t> maa_client::GetMAAToken(
        const utility::string_t& report_base64url,
        const utility::string_t& private_data_base64url)
    {
        if (report_base64url.empty())
        {
            throw maa_client_exception("Invalid value for report.");
        }
        if (private_data_base64url.empty())
        {
            throw maa_client_exception("Invalid value for private data.");
        }

        LOG_INFO(L"Attempt to obtain the MAA token...");

        _maa_urib.append_path(MAA_OE_SGX_PATH);
        _maa_urib.append_query(U("api-version"), MAA_API_VERSION);

        auto body = web::json::value::object();
        body[REPORT] = web::json::value::string(report_base64url);
        body[ENCLAVE_HELD_DATA] = web::json::value::string(private_data_base64url);

        pplx::task<utility::string_t> task = _client->request(methods::POST, _maa_urib.to_string(), body)
            .then([](const http_response& response)
                {
                    utility::string_t maa_token;
                    LOG_STRING(response.to_string().c_str());

                    if (response.status_code() == 200)
                    {
                        maa_token = response.extract_string().get();
                    }
                    else
                    {
                        LOG_ERROR("%ws", response.to_string().c_str());
                        throw maa_client_exception(response);
                    }

                    return std::move(maa_token);
                });

        return task;
    }
}