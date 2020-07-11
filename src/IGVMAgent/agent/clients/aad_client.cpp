/*!
 * Copyright (c) Microsoft Corporation
 * Abstract:
 *    Azure Active Directory Client class
 */

#include <clients/aad_client.h>
#include <clients/client_exceptions.h>
#include <common/Logger.h>

#include <cpprest/http_client.h>
#include <cpprest/filestream.h>

using namespace utility;                    // Common utilities like string conversions
using namespace web;                        // Common features like URIs.
using namespace web::http;                  // Common HTTP functionality
using namespace web::http::client;          // HTTP client features
using namespace web::http::oauth2::experimental;
using namespace concurrency::streams;       // Asynchronous streams
using namespace agent;

namespace clients
{   
    aad_client::aad_client()
    {
        _aad_http_client = new http_client(AAD_URI);
        //_aad_http_client = new http_client(MSI_USER_IDENTITY_VM_URI);
        //_aad_http_client = new http_client(MSI_USER_IDENTITY_HOST_URI);
    }
    aad_client::~aad_client()
    {
        free(_aad_http_client);
        _aad_http_client = nullptr;
    }

    pplx::task<web::http::oauth2::experimental::oauth2_token> aad_client::GetAADToken(
        const agent::identity& id,
        const utility::string_t& scope)
    {
        return GetAADToken(id._tenant_id, id._client_id, id._client_secret, scope);
    }

    pplx::task<web::http::oauth2::experimental::oauth2_token> aad_client::GetAADToken(
        const utility::string_t& tenant_id,
        const utility::string_t& client_id,
        const utility::string_t& secret,
        const utility::string_t& scope)
    {
        if (tenant_id.empty())
        {
            throw aad_client_exception("Invalid value for tenant_id.");
        }
        if (client_id.empty())
        {
            throw aad_client_exception("Invalid value for client_id.");
        }
        if (scope.empty())
        {
            throw aad_client_exception("Invalid value for scope.");
        }

        LOG_INFO(L"AAD access token retrieval begins");
        LOG_INFO(L"The tenant id is %ws", tenant_id.c_str());
        LOG_INFO(L"The client id is %ws", client_id.c_str());
        LOG_INFO(L"The scope is %ws", scope.c_str());

        uri_builder token_endpoint(tenant_id);
        token_endpoint.append_path(U("/oauth2/v2.0/token"));

        uri_builder post_data;
        post_data.append_query(U("grant_type"), U("client_credentials"));
        post_data.append_query(U("client_id"), client_id);
        if (!secret.empty())
            post_data.append_query(U("client_secret"), secret); 
        post_data.append_query(U("scope"), scope);
        // post_data at this moment is "/?grant_type=client_credentials&client_id=......"
        // Need to remove the first two chars from post_data.
        // The behavior here follows the OAuth 2.0 Client Credentials Grant flow.
        // Find more details in the IETF standard: https://tools.ietf.org/html/rfc6749#section-4.4
        auto post_data_str = post_data.to_string().substr(2);

        pplx::task<web::http::oauth2::experimental::oauth2_token> task =
            _aad_http_client->request(methods::POST, token_endpoint.to_string(), post_data_str, CONTENT_TYPE)
            .then([](const http_response& response)
                {
                    web::http::oauth2::experimental::oauth2_token authentication_token;
                    if (response.status_code() == 200)
                    {
                        auto response_json = response.extract_json().get();
                        if (response_json.has_field(U("access_token"))) {
                            utility::string_t token_str = response_json[U("access_token")].as_string();
                            LOG_INFO(L"The AAD access token is: %ws", token_str.c_str());
                            authentication_token.set_access_token(token_str);
                        }
                        else
                        {
                            LOG_ERROR("%ws", response.to_string().c_str());
                            throw aad_client_exception(response_json);
                        }
                    }
                    else
                    {
                        LOG_ERROR("%ws", response.to_string().c_str());
                        throw aad_client_exception(response);
                    }

                    return authentication_token;
                });

        return task;
    }

    void aad_client::GetAADUserMsiTokenFromHost(
        const utility::string_t& container_id,
        const utility::string_t& scope,
        web::http::oauth2::experimental::oauth2_token& authentication_token)
    {
        if (container_id.empty())
        {
            throw aad_client_exception("Invalid value for container_id.");
        }
        if (scope.empty())
        {
            throw aad_client_exception("Invalid value for scope.");
        }
        
        LOG_INFO(L"GetAADUserMsiTokenFromHost: AAD access token retrieval begins");
        LOG_INFO(L"The container_id id is %ws", container_id.c_str());
        LOG_INFO(L"The scope is %ws", scope.c_str());

        uri_builder token_endpoint;
        token_endpoint.append_query(U("cid"), container_id);
        token_endpoint.append_query(U("api-version"), U("2018-02-01"));
        token_endpoint.append_query(U("resource"), scope);

        http_request request(methods::GET);
        request.headers().add(U("metadata"), U("true"));
        request.set_request_uri(token_endpoint.to_uri());
        LOG_INFO(L"URI: ", request.absolute_uri().to_string().c_str());
        LOG_INFO(L"Request: ", request.to_string().c_str());

        http_response response = _aad_http_client->request(request).get();
        response.content_ready().get();

        if (response.status_code() == 200)
        {
            auto response_json = response.extract_json().get();
            if (response_json.has_field(U("access_token"))) {
                utility::string_t token_str = response_json[U("access_token")].as_string();
                LOG_INFO(L"The AAD access token is: %ws", token_str.c_str());
                authentication_token.set_access_token(token_str);
            }
            else
            {
                LOG_ERROR("%ws", response.to_string().c_str());
                throw aad_client_exception(response_json);
            }
        }
        else
        {
            LOG_ERROR("%ws", response.to_string().c_str());
            throw aad_client_exception(response);
        }
    }

    void aad_client::GetAADUserMsiTokenFromVm(
        const utility::string_t& scope,
        web::http::oauth2::experimental::oauth2_token& authentication_token)
    {
        LOG_INFO(L"GetAADUserMsiTokenFromVm: AAD access token retrieval begins");

        uri_builder token_endpoint;
        token_endpoint.append_query(U("api-version"), U("2018-02-01"));
        token_endpoint.append_query(U("resource"), scope);

        http_request request(methods::GET);
        request.headers().add(U("metadata"), U("true"));
        request.set_request_uri(token_endpoint.to_uri());
        LOG_INFO(L"URI: %ws", request.absolute_uri().to_string().c_str());
        LOG_INFO(L"Request: %ws", request.to_string().c_str());

        http_response response = _aad_http_client->request(request).get();
        response.content_ready().get();

        if (response.status_code() == 200)
        {
            auto response_json = response.extract_json().get();
            if (response_json.has_field(U("access_token"))) {
                utility::string_t token_str = response_json[U("access_token")].as_string();
                LOG_INFO(L"The AAD access token is: %ws", token_str.c_str());
                authentication_token.set_access_token(token_str);
            }
            else
            {
                LOG_ERROR("%ws", response.to_string().c_str());
                throw aad_client_exception(response_json);
            }
        }
        else
        {
            LOG_ERROR("%ws", response.to_string().c_str());
            throw aad_client_exception(response);
        }
    }
}