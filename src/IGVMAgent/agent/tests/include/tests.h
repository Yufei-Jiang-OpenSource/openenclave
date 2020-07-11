// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#ifndef _TESTS_H_
#define _TESTS_H_

#define AGENT_TEST(COND) \
    if (!(COND))      \
        abort();    \

#endif