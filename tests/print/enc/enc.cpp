// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "../args.h"

OE_ECALL void TestPrint(void* args_)
{
    TestPrintArgs* args = (TestPrintArgs*)args_;
    size_t n;

    /* Write to standard output */
    {
        oe_host_printf("oe_host_printf(stdout)\n");

        printf("printf(stdout)\n");

        n = fwrite("fwrite(stdout)\n", 1, 15, stdout);
        OE_TEST(n == 15);
        int r = fputc('o', stdout);
        OE_TEST(r == 'o');
        /* Note that gcc seems to optimize fputs to fwrite, and fprintf to
           fputc, iff we ignore the result. */
        fprintf(stdout, "\n");
        r = fputs("", stdout);
        OE_TEST(r == 0);
        r = fputs("fputs(stdout)\n", stdout);
        OE_TEST(r >= 0);

        const char str[] = "__oe_host_print(stdout)\n";
        __oe_host_print(0, str, (size_t)-1);
        __oe_host_print(0, str, sizeof(str) - 1);
    }

    /* Write to standard error */
    {
        n = fwrite("fwrite(stderr)\n", 1, 15, stderr);
        OE_TEST(n == 15);
        int r = fputc('e', stderr);
        OE_TEST(r == 'e');
        /* Note that gcc seems to optimize fputs to fwrite, and fprintf to
           fputc, iff we ignore the result. */
        fprintf(stderr, "\n");
        r = fputs("fputs(stderr)\n", stderr);
        OE_TEST(r >= 0);
        const char str[] = "__oe_host_print(stderr)\n";
        __oe_host_print(1, str, (size_t)-1);
        __oe_host_print(1, str, sizeof(str) - 1);
    }

    args->rc = 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
