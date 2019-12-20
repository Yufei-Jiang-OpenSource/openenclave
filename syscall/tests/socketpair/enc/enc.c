/* Copyright (c) Open Enclave SDK contributors. */
/* Licensed under the MIT License. */

#include <openenclave/enclave.h>
#include <openenclave/internal/time.h>
#include <syscall/module.h>

// enclave.h must come before socket.h
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openenclave/internal/tests.h>
#include <sys/socket.h>
#include <unistd.h>

#include <socketpair_test_t.h>
#include <stdio.h>
#include <string.h>

int sockfd[2] = {-1, -1};
char done = false;

int init_enclave()
{
    int ret = -1;

    OE_TEST(oe_load_module_host_socket_interface() == OE_OK);
    {
        char buf[1024] = {0};
        OE_TEST(gethostname(buf, sizeof(buf)) == 0);
        printf("hostname=%s\n", buf);
        OE_TEST(strlen(buf) > 0);
    }

    {
        char buf[1024] = {0};
        OE_TEST(getdomainname(buf, sizeof(buf)) == 0);
        printf("domainname=%s\n", buf);
        //  OE_TEST(strlen(buf) > 0); Always fails on jenkins
    }

    {
        if (socketpair(OE_AF_LOCAL, SOCK_STREAM, 0, sockfd) < 0)
        {
            printf("could not create socketpair. errno = %d\n", errno);
            OE_TEST(errno == 0);
        }
    }
    ret = 0;
    return ret;
}

/* This client connects to an echo server, sends a text message,
 * and outputs the text reply.
 */
int run_enclave_client(char* recv_buff, ssize_t* recv_buff_len)
{
    ssize_t n = 0;
    size_t buff_len = (size_t)*recv_buff_len;

    printf("------------ start client\n");
    memset(recv_buff, '0', buff_len);

    printf("socket[0] fd = %d\n", sockfd[0]);
    printf("socket[1] fd = %d\n", sockfd[1]);
    int sockdup = dup(sockfd[1]);

    printf("reading...\n");
    int numtries = 0;
    do
    {
        n = read(sockdup, recv_buff, buff_len);

        *recv_buff_len = n;
        if (n > 0)
        {
            printf("finished reading: %ld bytes...\n", n);
            done = true;
            break;
        }
        else
        {
            printf("Read error, retry\n");
            numtries++;
            oe_sleep_msec(3000);
        }
    } while (numtries < 10);

    done = true; // Stop the server
    if (numtries >= 10)
    {
        printf("Read error, Fail\n");
        return OE_FAILURE;
    }
    oe_host_printf("success close\n");
    close(sockdup); // We don't close the socket pair
    return OE_OK;
}

/* This server acts as an echo server.  It accepts a connection,
 * receives messages, and echoes them back.
 */
int run_enclave_server()
{
    int status = OE_FAILURE;
    static const char TESTDATA[] = "This is TEST DATA\n";

    printf("------------ start server\n");

    do
    {
        printf("enclave: writing on sockfd[0]\n");
        ssize_t n = write(sockfd[0], TESTDATA, strlen(TESTDATA));
        if (n > 0)
        {
            printf("write test data n = %ld\n", n);
        }
        else
        {
            printf("write test data n = %ld errno = %d\n", n, errno);
        }
        oe_sleep_msec(1000);
    } while (!done);

    // Shutdown the writing

    if (oe_shutdown(sockfd[0], OE_SHUT_WR) < 0)
    {
        printf("could not shutdown socket %d. errno = %d\n", sockfd[0], errno);
        OE_TEST(errno == 0);
    }

    ssize_t bytes_written = write(sockfd[0], TESTDATA, strlen(TESTDATA));
    OE_TEST(bytes_written <= 0);

    // We let the server close both sides
    close(sockfd[0]);
    close(sockfd[1]);
    printf("exit from server thread\n");
    return status;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    256,  /* HeapPageCount */
    256,  /* StackPageCount */
    4);   /* TCSCount */
