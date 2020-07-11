/*!
 * Copyright (c) Microsoft Corporation
 * Abstract:
 *    Secure Key Release class using CCF server
 */

#include <clients/akv_skr_client.h>
#include <clients/client_exceptions.h>
#include <common/Logger.h>

#include <cpprest/http_client.h>
#include <cpprest/filestream.h>

#include <winhttp.h>

namespace clients
{
    using namespace utility;                    // Common utilities like string conversions
    using namespace web;                        // Common features like URIs.
    using namespace web::http;                  // Common HTTP functionality
    using namespace web::http::client;          // HTTP client features
    using namespace concurrency::streams;       // Asynchronous streams
    using namespace agent;

    akv_skr_client::akv_skr_client(agent::identity& id)
        : skr_client()
    {
         _urib.append_query(U("api-version"), AKV_SERVER_VERSION);

        http_client_config cfg;

        // Do validate server cert
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
                throw akv_skr_exception("Failed to configure no client cert option.");
            }
        });

        try
        {
            clients::aad_client c;
            auto task = c.GetAADToken(id, AKV_SERVER_SCOPE);

            task.wait();
            _authentication_token = task.get();
            //c.GetAADUserMsiTokenFromHost(U("37c0feee-3ecd-4dad-81c5-72fb56a6afe6"), AKV_SERVER_SCOPE_MSI, _authentication_token);
            //c.GetAADUserMsiTokenFromVm(AKV_SERVER_SCOPE_MSI, _authentication_token);
        }
        catch (web::http::http_exception& e)
        {
            LOG_ERROR("http_exception: %s", e.what());
        }
        catch (std::exception& e)
        {
            LOG_ERROR("Unknown exception: %s", e.what());
        }

        //uri_builder aad_uri(aad_client::MSI_USER_IDENTITY_VM_URI);
        uri_builder aad_uri(aad_client::AAD_URI);
        aad_uri.append(id._tenant_id);
        aad_uri.append(U("/oauth2/v2.0/token"));

        oauth2::experimental::oauth2_config oauth2_config(
            id._client_id,
            id._client_secret,
            L"",    // Auth endpoint
            aad_uri.to_string(), // token endpoint
            L"", // Redirect URI
            AKV_SERVER_SCOPE);
        oauth2_config.set_token(_authentication_token);
        oauth2_config.set_bearer_auth(true);
        cfg.set_oauth2(oauth2_config);

        _client = new web::http::client::http_client(AKV_SERVER_URI, cfg);
    };
    akv_skr_client::~akv_skr_client()
    {
        free(_client);
        _client = nullptr;
    }

    pplx::task<utility::string_t> akv_skr_client::create_key(
        const utility::string_t& key_name,
        const utility::string_t& policy,
        const utility::string_t& secret) noexcept(false)
    {
        if (key_name.empty())
        {
            throw akv_skr_exception("Invalid value for key_name.");
        }
        if (policy.empty())
        {
            throw akv_skr_exception("Invalid value for policy.");
        }

        LOG_INFO(L"Creating key: %ws", key_name.c_str());

        throw akv_skr_exception("Not Implemented.");
    }

    pplx::task<std::vector<BYTE>> akv_skr_client::release_key(
        const utility::string_t& key_name,
        const utility::string_t& key_version,
        const utility::string_t& maa_token,
        const utility::string_t& secret) noexcept(false)
    {
        UNREFERENCED_PARAMETER(secret);

        if (key_name.empty())
        {
            throw akv_skr_exception("Invalid value for key_name.");
        }
        if (key_version.empty())
        {
            throw akv_skr_exception("Invalid value for key_version.");
        }
        if (maa_token.empty())
        {
            throw akv_skr_exception("Invalid value for maa_token.");
        }

        LOG_INFO(L"Releasing key: %ws(%ws)", key_name.c_str(), key_version.c_str());

        web::uri_builder urib(_urib);
        urib.append_path(KEYS);
        urib.append_path(key_name);
        urib.append_path(key_version);
        LOG_STRING(urib.to_string().c_str());

        // TODO: Add MAA token
        auto body = web::json::value::object();
        body[ENV] = web::json::value::string(maa_token);

        http_request request(methods::GET);
        request.set_request_uri(urib.to_uri());

        LOG_INFO("Request: %ws", request.to_string().c_str());

        pplx::task<std::vector<BYTE>> requestTask = _client->request(request)
            .then([](const http_response& response)
                {
                    LOG_STRING(response.to_string().c_str());

                    std::vector<BYTE> encrypted_key;
                    if (response.status_code() == 200)
                    {
                        encrypted_key = response.extract_vector().get();
                    }
                    else
                    {
                        LOG_ERROR("%ws", response.to_string().c_str());
                        throw akv_skr_exception(response);
                    }

                    return std::move(encrypted_key);
                });

        return requestTask;
    }
}