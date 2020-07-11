/*!
 * Copyright (c) Microsoft Corporation
 * Abstract:
 *    Secure Key Release class using CCF server
 */

#include <clients/ccf_skr_client.h>
#include <clients/client_exceptions.h>
#include <common/Logger.h>

#include <cpprest/http_client.h>
#include <cpprest/filestream.h>

#include <winhttp.h>

#define TLS_ALGO        (BCRYPT_ECDSA_P384_ALGORITHM)
#define TLS_ALGO_SIZE   (384u)

namespace clients
{
    using namespace utility;                    // Common utilities like string conversions
    using namespace web;                        // Common features like URIs.
    using namespace web::http;                  // Common HTTP functionality
    using namespace web::http::client;          // HTTP client features
    using namespace concurrency::streams;       // Asynchronous streams
    using namespace agent;

    ccf_skr_client::ccf_skr_client(identity& id)
        : skr_client()
    {
        // Initialize crypto library
        //THROW_IF_NTSTATUS_FAILED_MSG(BCryptOpenAlgorithmProvider(
        //    &_hAlgo,
        //    TLS_ALGO,
        //    NULL,
        //    0),
        //    "Failed to open algo provider.");

        _urib.append_query(U("api-version"), CCF_SERVER_VERSION);

        http_client_config cfg;
        // TODO: Using client certs for TLS
        //DWORD publicKeySize;
        //PBYTE publicKeyBuffer;
        //DWORD privateKeySize;
        //PBYTE privateKeyBuffer;

        //create_key_pair(_hAlgo, TLS_ALGO_SIZE,
        //    &publicKeySize,
        //    &publicKeyBuffer,
        //    &privateKeySize,
        //    &privateKeyBuffer);

        // Do not validate server cert
        cfg.set_validate_certificates(false);
        // No client certs
        cfg.set_nativehandle_options([](web::http::client::native_handle h)
        {
            BOOL win32Result = WinHttpSetOption(h,
                WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                WINHTTP_NO_CLIENT_CERT_CONTEXT,
                0);
            if (FALSE == win32Result)
            {
                LOG_ERROR("Failed to configure no client cert option: %x", HRESULT_FROM_WIN32(GetLastError()));
                throw ccf_skr_exception("Failed to configure no client cert option.");
            }
        });

        // TODO: CCF server does not support having a bearer token yet.
        // See https://github.com/microsoft/CCF/issues/1203
        //
        //try
        //{
        //    clients::aad_client c;
        //    c.GetAADToken(id, CCF_SERVER_SCOPE, _authentication_token);
        //}
        //catch (web::http::http_exception& e)
        //{
        //    LOG_ERROR("http_exception: %s", e.what());
        //}
        //catch (std::exception& e)
        //{
        //    LOG_ERROR("Unknown exception: %s", e.what());
        //}

        _client = new web::http::client::http_client(CCF_SERVER_URI, cfg);
    };
    ccf_skr_client::~ccf_skr_client()
    {
        /*BCryptCloseAlgorithmProvider(_hAlgo, 0);*/

        free(_client);
        _client = nullptr;
    }

    void ccf_skr_client::create_key_pair(
        BCRYPT_ALG_HANDLE hAlgo,
        DWORD keySize,
        DWORD* publicKeySize,
        PBYTE* publicKeyBuffer,
        DWORD* privateKeySize,
        PBYTE* privateKeyBuffer)
    {
        BCRYPT_KEY_HANDLE hKey;
        *publicKeySize = 0;
        *privateKeySize = 0;

        DWORD pubKeySize;
        DWORD privKeySize;
        PBYTE pubKey = NULL;
        PBYTE privKey = NULL;

        THROW_IF_NTSTATUS_FAILED_MSG( BCryptGenerateKeyPair(
            hAlgo,
            &hKey,
            keySize,
            0),
            "Failed to generate key pair.");

        THROW_IF_NTSTATUS_FAILED(BCryptFinalizeKeyPair(hKey, 0));
        THROW_IF_NTSTATUS_FAILED(BCryptExportKey(hKey,
            nullptr,
            BCRYPT_PUBLIC_KEY_BLOB,
            nullptr,
            0,
            &pubKeySize,
            0));
        THROW_IF_NTSTATUS_FAILED(BCryptExportKey(hKey,
            nullptr,
            BCRYPT_PRIVATE_KEY_BLOB,
            nullptr,
            0,
            &privKeySize,
            0));

        pubKey = (BYTE*)calloc(1, pubKeySize);
        THROW_IF_NULL_ALLOC(pubKey);
        privKey = (BYTE*)calloc(1, privKeySize);
        THROW_IF_NULL_ALLOC(privKey);

        THROW_IF_NTSTATUS_FAILED(BCryptExportKey(hKey,
            nullptr,
            BCRYPT_PUBLIC_KEY_BLOB,
            pubKey,
            pubKeySize,
            &pubKeySize,
            0));
        THROW_IF_NTSTATUS_FAILED(BCryptExportKey(hKey,
            nullptr,
            BCRYPT_PRIVATE_KEY_BLOB,
            privKey,
            privKeySize,
            &privKeySize,
            0));
        
        THROW_IF_NTSTATUS_FAILED(BCryptDestroyKey(hKey));
    }

    pplx::task<utility::string_t> ccf_skr_client::create_key(
        const utility::string_t& key_name,
        const utility::string_t& policy,
        const utility::string_t& secret) noexcept(false)
    {
        if (key_name.empty())
        {
            throw ccf_skr_exception("Invalid value for key_name.");
        }
        if (policy.empty())
        {
            throw ccf_skr_exception("Invalid value for policy.");
        }

        LOG_INFO(L"Creating key: %ws", key_name.c_str());

        web::uri_builder urib(_urib);
        urib.append_path(USERS);
        urib.append_path(KEYS);
        urib.append_path(key_name);
        urib.append_path(CREATE);

        auto body = web::json::value::object();
        body[POLICY_DATA] = web::json::value::parse(policy);
        body[SECRET_DATA] = web::json::value::string(secret);
        
        pplx::task<utility::string_t> task = _client->request(methods::POST, urib.to_string(), body)
            .then([](const http_response& response)
                {
                    utility::string_t key_version;
                    if (response.status_code() == 200)
                    {
                        auto response_json = response.extract_json().get();
                        if (response_json.has_field(KEY_VERSION))
                        {
                            key_version = response_json[KEY_VERSION].as_string();
                        }
                        else
                        {
                            throw ccf_skr_exception(response_json);
                        }
                    }
                    else
                    {
                        throw ccf_skr_exception(response);
                    }

                    return key_version;
                });

        return task;
    }

    pplx::task<std::vector<BYTE>> ccf_skr_client::release_key(
        const utility::string_t& key_name,
        const utility::string_t& key_version,
        const utility::string_t& maa_token,
        const utility::string_t& secret) noexcept(false)
    {
        if (key_name.empty())
        {
            throw ccf_skr_exception("Invalid value for key_name.");
        }
        if (key_version.empty())
        {
            throw ccf_skr_exception("Invalid value for key_version.");
        }
        if (maa_token.empty())
        {
            throw ccf_skr_exception("Invalid value for maa_token.");
        }

        LOG_INFO(L"Releasing key: %ws(%ws)", key_name.c_str(), key_version.c_str());

        web::uri_builder urib(_urib);
        urib.append_path(USERS);
        urib.append_path(KEYS);
        urib.append_path(key_name);
        urib.append_path(key_version);
        urib.append_path(EXPORT);

        auto body = web::json::value::object();
        body[ENV] = web::json::value::string(maa_token);
        body[SECRET_DATA] = web::json::value::string(secret);

        pplx::task<std::vector<BYTE>> requestTask = 
            _client->request(methods::POST, urib.to_string(), body)
            .then([](const http_response& response)
            {
                std::vector<BYTE> encrypted_key;
                if (response.status_code() == 200)
                {
                    auto response_json = response.extract_json().get();
                    if (response_json.has_field(VALUE_FIELD))
                    {
                        auto result = response_json[VALUE_FIELD].as_array();
                        for (web::json::value v : result)
                        {
                            encrypted_key.push_back((BYTE)v.as_integer());
                        }
                    }
                    else
                    {
                        throw ccf_skr_exception(response_json);
                    }
                }
                else
                {
                    throw ccf_skr_exception(response);
                }

                return std::move(encrypted_key);
            });

        return requestTask;
    }
}