// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include "remoteattestation_u.h"

#include <mbedtls/base64.h>
#include <memory.h>
#include <stdint.h>
#include <stdlib.h>

int encode_base64(const uint8_t* in, size_t in_len, char** out, size_t* out_len)
{
    int ret;
    size_t bytes_written = 0;
    ret = mbedtls_base64_encode(NULL, 0, &bytes_written, in, in_len);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
    {
        return -1;
    }
    *out = static_cast<char*>(malloc(bytes_written));
    if (*out == NULL)
    {
        return -1;
    }
    ret = mbedtls_base64_encode(
        reinterpret_cast<unsigned char*>(*out),
        bytes_written,
        out_len,
        in,
        in_len);
    if (ret != 0)
    {
        free(*out);
        *out = 0;
        *out_len = 0;
        return -1;
    }

    return 0;
}

int encode_base64url(
    const uint8_t* in,
    size_t in_len,
    char** out,
    size_t* out_len)
{
    int ret = encode_base64(in, in_len, out, out_len);
    if (ret != 0)
    {
        return -1;
    }
    if (*out && *out_len)
    {
        int i = 0;
        while (i != *out_len)
        {
            if ((*out)[i] == '+')
            {
                (*out)[i] = '-';
            }
            else if ((*out)[i] == '/')
            {
                (*out)[i] = '_';
            }
            i++;
        }

        while (*out_len && ((*out)[(*out_len) - 1]) == '=')
        {
            (*out_len)--;
            (*out)[*out_len] = '\0';
        }
    }
    return 0;
}

oe_enclave_t* create_enclave(const char* enclave_path)
{
    oe_enclave_t* enclave = NULL;

    printf("Host: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_remoteattestation_enclave(
        enclave_path,
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        printf(
            "Host: oe_create_remoteattestation_enclave failed. %s",
            oe_result_str(result));
    }
    else
    {
        printf("Host: Enclave successfully created.\n");
    }
    return enclave;
}

void terminate_enclave(oe_enclave_t* enclave)
{
    oe_terminate_enclave(enclave);
    printf("Host: Enclave successfully terminated.\n");
}

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave_a = NULL;
    oe_enclave_t* enclave_b = NULL;
    uint8_t* encrypted_msg = NULL;
    size_t encrypted_msg_size = 0;
    oe_result_t result = OE_OK;
    int ret = 1;
    uint8_t* pem_key = NULL;
    size_t pem_key_size = 0;
    uint8_t* remote_report = NULL;
    size_t remote_report_size = 0;

    char* report_base64 = NULL;
    size_t report_base64_size = 0;

    char* pem_key_base64 = NULL;
    size_t pem_key_base64_size = 0;

    /* Check argument count */
    if (argc != 3)
    {
        printf("Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    printf("Host: Creating two enclaves\n");
    enclave_a = create_enclave(argv[1]);
    if (enclave_a == NULL)
    {
        goto exit;
    }
    enclave_b = create_enclave(argv[2]);
    if (enclave_b == NULL)
    {
        goto exit;
    }

    printf("Host: requesting a remote report and the encryption key from 1st "
           "enclave\n");
    result = get_remote_report_with_pubkey(
        enclave_a,
        &ret,
        &pem_key,
        &pem_key_size,
        &remote_report,
        &remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    printf("Host: 1st enclave's public key: \n%s", pem_key);

    ret = encode_base64url(
        remote_report, remote_report_size, &report_base64, &report_base64_size);
    if (ret != 0)
    {
        fprintf(stderr, "Failed to base64url report\n");
        goto exit;
    }
    printf("Report in its original format: \n%s\n", remote_report);
    printf("Report in base64: \n%s\n", report_base64);

    ret = encode_base64url(
        pem_key, pem_key_size, &pem_key_base64, &pem_key_base64_size);
    if (ret != 0)
    {
        fprintf(stderr, "Failed to base64url pem key\n");
        goto exit;
    }
    printf("pem key in base64: \n%s\n", pem_key_base64);

    printf("Host: requesting 2nd enclave to attest 1st enclave's the remote "
           "report and the public key\n");
    result = verify_report_and_set_pubkey(
        enclave_b,
        &ret,
        pem_key,
        pem_key_size,
        remote_report,
        remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    free(pem_key);
    pem_key = NULL;
    free(remote_report);
    remote_report = NULL;

    printf("Host: Requesting a remote report and the encryption key from "
           "2nd enclave=====\n");
    result = get_remote_report_with_pubkey(
        enclave_b,
        &ret,
        &pem_key,
        &pem_key_size,
        &remote_report,
        &remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf("Host: 2nd enclave's public key: \n%s", pem_key);

    printf("Host: Requesting first enclave to attest 2nd enclave's "
           "remote report and the public key=====\n");
    result = verify_report_and_set_pubkey(
        enclave_a,
        &ret,
        pem_key,
        pem_key_size,
        remote_report,
        remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    free(pem_key);
    pem_key = NULL;
    free(remote_report);
    remote_report = NULL;

    printf("Host: Remote attestation Succeeded\n");

    // Free host memory allocated by the enclave.
    free(encrypted_msg);
    encrypted_msg = NULL;
    ret = 0;

exit:
    if (pem_key)
        free(pem_key);

    if (remote_report)
        free(remote_report);

    if (encrypted_msg != NULL)
        free(encrypted_msg);

    printf("Host: Terminating enclaves\n");
    if (enclave_a)
        terminate_enclave(enclave_a);

    if (enclave_b)
        terminate_enclave(enclave_b);

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
