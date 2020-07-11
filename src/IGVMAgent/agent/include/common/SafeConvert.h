//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

#pragma once

#include <safeint.h>
#include <type_traits>
#include <wil/result_macros.h>

namespace base64
{

    /*
    HELPERS FOR CHECKING FOR INTEGER OVERFLOW / UNDERFLOW DURING NARROWING CONVERSIONS
    */

    // Wraps a value as a SafeInt of the specified type.
    template<typename _Out, typename _In>
    auto SafeWrapAs(_In value) {
        return msl::utilities::SafeInt<_Out>(value);
    };

    // Wraps a value as a SafeInt of the inferred type.
    template<typename _Int>
    auto SafeWrap(_Int value) {
        return SafeWrapAs<_Int>(value);
    };

    // Wraps a value as a SafeInt, converting from _Int to unsigned _Int in the process.
    template<typename _Int>
    auto SafeWrapAsUnsigned(_Int value) {
        return SafeWrapAs<std::make_unsigned_t<_Int>>(value);
    };

    /*
    HELPERS FOR CHANGING REPRESENTATIONS BETWEEN BITS AND BYTES
    */

    // Converts bits to bytes with overflow / underflow checks
    template<typename _Int>
    auto SafeBitsToBytes(_Int inputInBits) {
        // bit lengths must be non-negative
        auto wrapped = SafeWrapAsUnsigned(inputInBits);

        // input must be a multiple of 8
        if (wrapped % 8UL != 0) {
            THROW_WIN32(ERROR_INVALID_PARAMETER);
        }

        return wrapped / 8UL;
    };

    // Converts bytes to bits with overflow / underflow checks
    template<typename _Int>
    auto SafeBytesToBits(_Int inputInBytes) {
        return SafeWrapAsUnsigned(inputInBytes) * 8UL;
    };
}; // attest