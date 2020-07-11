# Azure Active Directory (AAD) client

The AAD client provides an interface for fetching AAD authentication token from AAD.

## AAD Client Class
```C++
    class aad_client
    {
    public:
        static constexpr auto AAD_URI = L"https://login.microsoftonline.com/";

        aad_client(){};
        virtual ~aad_client();

        /*!
         * Get the AAD oauth2 authentication token.
         *
         * \param tenant_id[in]             The id of the tenant.
         * \param client_id[in]             The id of the client.
         * \param secret[in]                The shared secret between the app and the AAD.
         * \param scope[in]                 The scope of the token audience.
         * \param authentication_token[out] The authentication token
         */
        virtual void GetAADToken(
            const utility::string_t& tenant_id,
            const utility::string_t& client_id,
            const utility::string_t& secret,
            const utility::string_t& scope,
            web::http::oauth2::experimental::oauth2_token* authentication_token);

    protected:
        web::http::client::http_client* _aad_http_client;

    private:
        aad_client(const aad_client& rhs);
        aad_client& operator=(const aad_client& rhs);
    };
```

# Microsoft Azure Attestation (MAA) client
The MAA client provides an interface for sending the Confiential VM (CVM) remote attestation report to MAA and getting back the report verification results.

## MAA Client Class
```C++
    class maa_client
    {
    public:
        static constexpr auto MAA_URI = L"https://tradewinds.us.attest.azure.net";

        maa_client()
        {
            _maa_urib.set_host(MAA_URI);
        };
        virtual ~maa_client() {};

        /*!
         * Get the attestation verification results token returned by the MAA.
         *
         * \param authentication_token[in]      The authentication token
         * \param report_base64url[in]          The remote attestation report
         * \param private_data_base64url[in]    The customer held data
         * \param authentication_token[out]     The token returned by MAA
         */
        virtual HRESULT GetMAAToken(
            const web::http::oauth2::experimental::oauth2_token& authentication_token,
            const utility::string_t& report_base64url,
            const utility::string_t& private_data_base64url,
            maa_token_t* maa_token) = 0;

    protected:
        web::uri_builder _maa_urib;

    private:
        maa_client(const maa_client& rhs);
        maa_client& operator=(const maa_client& rhs);
    };
```

## MAA Token Class
The MAA Token class provides an abstraction to represent the token returned by MAA.

To be defined.