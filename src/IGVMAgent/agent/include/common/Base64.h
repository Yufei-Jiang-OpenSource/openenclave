//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

#pragma once

#include <array>
#include <minwindef.h>
#include "SafeConvert.h"
#include <vector>
#include <string>

// Code adapted from Base64EncodeA() in /onecore/ds/security/cryptoapi/common/pkifmt/base64.cpp.
namespace base64
{
    static const UCHAR s_abEncodeBase64[] =
        /*  0 thru 25: */ "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        /* 26 thru 51: */ "abcdefghijklmnopqrstuvwxyz"
        /* 52 thru 61: */ "0123456789"
        /* 62 and  63: */ "+/";

    static const UCHAR s_abEncodeBase64URL[] =
        /*  0 thru 25: */ "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        /* 26 thru 51: */ "abcdefghijklmnopqrstuvwxyz"
        /* 52 thru 61: */ "0123456789"
        /* 62 and  63: */ "-_";

#define BASE64ENCODE_URL_NOPADDING 1

#ifndef IMAGE_ENCLAVE_LONG_ID_LENGTH
#define IMAGE_ENCLAVE_LONG_ID_LENGTH      32
#endif

#ifndef IMAGE_ENCLAVE_SHORT_ID_LENGTH
#define IMAGE_ENCLAVE_SHORT_ID_LENGTH     16
#endif 

    // _ReturnType must be a type with a function push_back(char).
    // _InputType must be a type with a function cbegin() and size(). It must also have individual elements of size char.
    template<typename _ReturnType, typename _InputType>
    std::enable_if_t<
        std::is_same<_InputType, std::string>::value ||
        std::is_same<_InputType, std::vector<BYTE>>::value ||
        std::is_same<_InputType, std::array<UINT8, IMAGE_ENCLAVE_LONG_ID_LENGTH>>::value ||
        std::is_same<_InputType, std::array<UINT8, IMAGE_ENCLAVE_SHORT_ID_LENGTH>>::value, _ReturnType>
        Base64Encode(const _InputType& input, DWORD dwFlags)
    {
        _ReturnType retval{};

        bool fUrlEncoding = 0 != (dwFlags & BASE64ENCODE_URL_NOPADDING);
        BYTE const *abEncode = fUrlEncoding ? s_abEncodeBase64URL : s_abEncodeBase64;

        auto inputIt = input.cbegin();
        long size = SafeWrap(input.size());
        while (size > 0)    // signed comparison -- size can wrap
        {
            BYTE ab3[3]{};
            CHAR achRaw[4]{};

            // Process one 3 byte quantum into 4 characters.
            ab3[0] = *inputIt++;
            if (size > 1)
            {
                ab3[1] = *inputIt++;
                if (size > 2)
                {
                    ab3[2] = *inputIt++;
                }
            }
            achRaw[0] = abEncode[ab3[0] >> 2];
            achRaw[1] = abEncode[((ab3[0] << 4) | (ab3[1] >> 4)) & 0x3f];
            achRaw[2] = size > 1 ? abEncode[((ab3[1] << 2) | (ab3[2] >> 6)) & 0x3f] : '=';
            achRaw[3] = size > 2 ? abEncode[ab3[2] & 0x3f] : '=';
            for (size_t i = 0; i < ARRAYSIZE(achRaw); i++)
            {
                if (fUrlEncoding && '=' == achRaw[i])
                {
                    break;		// no padding for URL format
                }

                retval.push_back(achRaw[i]);  // Safe conversion from char to wchar_t if std::wstring is used as _ReturnType.
            }
            size -= 3;
        }

        return retval;
    }
}; // attest