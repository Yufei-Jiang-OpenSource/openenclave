/*!
 * Copyright (c) Microsoft Corporation
 * Abstract:
 *    Client exceptions
 */

#pragma once

#include <wil/resource.h>
#include <cpprest/http_client.h>

#include <exception>
#include <string>
#include <codecvt>

namespace clients
{
    /* Body fields */
    static constexpr auto SECRET_DATA = U("secret_data");
    static constexpr auto POLICY_DATA = U("policy_data");
    static constexpr auto ENV = U("env");

    /* URI fields */
    static constexpr auto USERS = U("users");
    static constexpr auto KEYS = U("keys");
    static constexpr auto KEY_VERSION = U("key_version");
    static constexpr auto CREATE = U("create");
    static constexpr auto EXPORT = U("export");

    /* Result fields */
    static constexpr auto ERROR_FIELD = U("error");
    static constexpr auto VALUE_FIELD = U("value");

    class client_exception : public std::exception
    {
    private:
        client_exception();
        std::string _error;

    public:
        client_exception(web::json::value& result)
        {
            utility::string_t werror;
            if (result.has_field(ERROR_FIELD))
            {
                werror = result[ERROR_FIELD].as_string();
            }
            else
            {
                werror = result.as_string();
            }

            using convert_type = std::codecvt_utf8<wchar_t>;
            std::wstring_convert<convert_type, wchar_t> converter;

            _error = converter.to_bytes(werror);
        }
        client_exception(const std::string& message)
        {
            _error = message;
        }
        client_exception(const web::http::http_response& response)
        {
            using convert_type = std::codecvt_utf8<wchar_t>;
            std::wstring_convert<convert_type, wchar_t> converter;

            auto reason = response.reason_phrase();
            _error = converter.to_bytes(reason);
        }
        virtual const char* what() const throw()
        {
            return _error.c_str();
        }
    };
}