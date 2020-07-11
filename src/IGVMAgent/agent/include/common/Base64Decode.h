//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
#pragma once

#include "Base64.h"
#include <minwindef.h>
#include <safeint.h>
#include <wil\result_macros.h>

// COPIED FROM Common/inc/common/Base64.h, Commit ed876c0f20453d9b202104e4b522cef6e11fd038.
//
// Code adapted from Base64DecodeA() in /onecore/ds/security/cryptoapi/common/pkifmt/base64.cpp.

namespace base64
{
#define chDECODEBASE	0x2b // '+'
    static const BYTE s_abDecodeBase64[] =
    {
        /* 20: */                                             62, 64, 64, 64, 63,
        /* 30: */ 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
        /* 40: */ 64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        /* 50: */ 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
        /* 60: */ 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        /* 70: */ 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    };

    static const BYTE s_abDecodeBase64URL[] =
    {
        /* 20: */                                             64, 64, 62, 64, 64,
        /* 30: */ 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
        /* 40: */ 64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        /* 50: */ 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 63,
        /* 60: */ 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        /* 70: */ 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    };

    template<typename _ReturnType, typename _InputIterator>
    _ReturnType Base64Decode(const _InputIterator &first, const _InputIterator &last, DWORD dwFlags)
    {
        _ReturnType retval{};

        bool fUrlDecoding = 0 != (dwFlags & BASE64ENCODE_URL_NOPADDING);
        BYTE const *abDecode = fUrlDecoding ? s_abDecodeBase64URL : s_abDecodeBase64;
        static_assert(ARRAYSIZE(s_abDecodeBase64) == ARRAYSIZE(s_abDecodeBase64URL), "Base64 array size doesn't match UrlBase64 array");

        BYTE ab4[4]{};
        DWORD cch = 0; // current number of collected base64 characters

        for (auto inputIt = first; inputIt != last; inputIt++)
        {
            BYTE abOut[3];
            BYTE ch = static_cast<BYTE>(*inputIt);

            if ('=' == ch)
            {
                break;
            }

            int index = static_cast<int>(ch) - chDECODEBASE;
            if (index < 0 ||
                index >= ARRAYSIZE(s_abDecodeBase64) ||
                abDecode[index] > 63)
            {
                THROW_WIN32_MSG(ERROR_INVALID_DATA, "Invalid char in Base64Decode");
            }

            ab4[cch++] = ch;

            if (ARRAYSIZE(ab4) == cch)
            {
                // We have a full quantum; process it:
                // Translate 4 input characters into 6 bits each, and deposit
                // the resulting 24 bits into 3 output bytes by shifting as
                // necessary.
                //
                // out[0] = in[0]:in[1] 6:2
                // out[1] = in[1]:in[2] 4:4
                // out[2] = in[2]:in[3] 2:6

                abOut[0] = (BYTE)((abDecode[ab4[0] - chDECODEBASE] << 2) | (abDecode[ab4[1] - chDECODEBASE] >> 4));
                abOut[1] = (BYTE)((abDecode[ab4[1] - chDECODEBASE] << 4) | (abDecode[ab4[2] - chDECODEBASE] >> 2));
                abOut[2] = (BYTE)((abDecode[ab4[2] - chDECODEBASE] << 6) | abDecode[ab4[3] - chDECODEBASE]);

                for (size_t i = 0; i < ARRAYSIZE(abOut); i++)
                {
                    retval.push_back(abOut[i]);
                }

                cch = 0;
                memset(ab4, 0, sizeof(ab4));
            }
        }

        if (cch > 0)
        {
            // Handle a partial quantum

            retval.push_back((BYTE)((abDecode[ab4[0] - chDECODEBASE] << 2) | ((cch > 1 ? abDecode[ab4[1] - chDECODEBASE] : 64) >> 4)));

            if (cch > 2)
            {
                retval.push_back((BYTE)((abDecode[ab4[1] - chDECODEBASE] << 4) | (abDecode[ab4[2] - chDECODEBASE] >> 2)));
            }
        }

        return retval;
    }

    template<typename _ReturnType>
    _ReturnType Base64Decode(const std::vector<BYTE>& input, DWORD dwFlags)
    {
        return Base64Decode<_ReturnType>(input.begin(), input.end(), dwFlags);
    }

    template<typename _ReturnType>
    _ReturnType Base64Decode(const std::wstring& input, DWORD dwFlags)
    {
        return Base64Decode<_ReturnType>(input.begin(), input.end(), dwFlags);
    }
}; // attest
