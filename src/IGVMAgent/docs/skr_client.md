# Secure Key Release (SKR) client

The SKR client provides an interface for releasing keys from a secure remote store. There are 2 flavors of the client:

- One for the CCF server implementation of SKR (ccf_skr_client).
- One for the AKV server implementation of SKR (akv_skr_client).

*Note*: The clients will have a method for creating keys as well, but this will be used for testing purposes only.

## SKR Client Base Class
```C
class skr_client
{
public:
    skr_client(const utility::string_t& host_uri)
    {
        _urib.set_host(host_uri);
    };
    virtual ~skr_client() {};

    /*!
    * Create a key.
    *
    * \param key_name[in] The name of the key to create.
    * \param policy[in] Policy string in json format.
    * \param secret[in] Secret string to used for key derivation.
    * \param key_version[out] The key version of the newly created key.
    */
    virtual void create_key(
        const utility::string_t& key_name,
        const utility::string_t& policy,
        const utility::string_t& secret,
        utility::string_t& key_version) = 0;

    /*!
    * Release the key for the given key_name and key_version.
    *
    * \param key_name[in]    The name of the key to release.
    * \param key_version[in] The version of the key to release.
    * \param maa_token[in]   The MAA token from attestation service.
    * \param secret[in]      Secret string to used for key derivation.
    * \param encrypted_key[out] The encrypted key
    */
    virtual void release_key(
        const utility::string_t& key_name,
        const utility::string_t& key_version,
        const std::vector<BYTE>& maa_token,
        const utility::string_t& secret,
        std::vector<BYTE>& encrypted_key) = 0;

protected:
    web::uri_builder _urib;

private:
    skr_client();
    skr_client(const skr_client& rhs);
    skr_client& operator=(const skr_client& rhs);
};
```

## CCF SKR Client

### Release key flow
1. On instantiation, the object will get the corresponding AAD token.
    - Token will be used until it expires, which will then cause the renewal of the token.
2. If AAD token has not expired, it will use it together with the given MAA token to 
get key.
    - If AAD token expired, it will renew the token.

```C
class ccf_skr_client : public skr_client
{
public:
    ccf_skr_client()
        : skr_client(CCF_SERVER_URI)
    {
            
    };
    virtual ~ccf_skr_client() {};

    /*!
    * Create a key.
    *
    * \param key_name[in] The name of the key to create.
    * \param policy[in] Policy string in json format.
    * \param secret[in] Secret string to used for key derivation.
    * \param key_version[out] The key version of the newly created key.
    */
    virtual void create_key(
        const utility::string_t& key_name,
        const utility::string_t& policy,
        const utility::string_t& secret,
        utility::string_t& key_version);

    /*!
    * Release the key for the given key_name and key_version.
    *
    * \param key_name[in]    The name of the key to release.
    * \param key_version[in] The version of the key to release.
    * \param maa_token[in]   The MAA token from attestation service.
    * \param secret[in]      Secret string to used for key derivation.
    * \param encrypted_key[out] The encrypted key
    */
    virtual void release_key(
        const utility::string_t& key_name,
        const utility::string_t& key_version,
        const std::vector<BYTE>& maa_token,
        const utility::string_t& secret,
        std::vector<BYTE>& encrypted_key);

private:
    ccf_skr_client(const ccf_skr_client& rhs);
    ccf_skr_client& operator=(const ccf_skr_client& rhs);
};
```

## AKV SRK Client
```C
class akv_skr_client : public skr_client
{
public:
    akv_skr_client()
        : skr_client(CCF_SERVER_URI)
    {
            
    };
    virtual ~akv_skr_client() {};

    /*!
     * Create a key.
     *
     * \param key_name[in] The name of the key to create.
     * \param policy[in] Policy string in json format.
     * \param secret[in] Secret string to used for key derivation.
     *
     * \return The version of the key.
     */
    virtual utility::string_t create_key(
        const utility::string_t& key_name,
        const utility::string_t& policy,
        const utility::string_t& secret = L"");

    /*!
     * Release the key for the given key_name and key_version.
     *
     * \param key_name[in]    The name of the key to release.
     * \param key_version[in] The version of the key to release.
     * \param maa_token[in]   The MAA token from attestation service.
     * \param secret[in]      Secret string to used for key derivation.
     */
    virtual std::vector<BYTE> release_key(
        const utility::string_t& key_name,
        const utility::string_t& key_version,
        const maa_token_t& maa_token,
        const utility::string_t& secret = L"");

private:
    akv_skr_client(const akv_skr_client& rhs);
    akv_skr_client& operator=(const akv_skr_client& rhs);
};
```

