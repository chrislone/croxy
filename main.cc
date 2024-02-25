#include <openssl/bio.h> /* BasicInput/Output streams */
#include <openssl/err.h> /* errors */
#include <openssl/ssl.h> /* core library */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "child.cc"

#include <iostream>
#include <vector>
#include <algorithm>

#define BUF_LEN 1024

using namespace std;

namespace {
    const int PORT = 4433;
}

BIO *sbio, *bbio, *acpt, *bio_tmp;
SSL_CTX *ctx;
SSL *ssl;

pid_t pid;
vector<pid_t> pid_vector;

void loop_wait_to_the_end() {
    while(1) {
        int wstatus;
        int w = waitpid(-1, &wstatus, WNOHANG);
        if (w == -1) {
            break;
        } else if (w > 0) {
            cout << "w: " << w << endl;
        }
    }
}

void sig_handler(int signo) {
    if (signo == SIGCHLD) {
        printf("received SIGCHLD, pid: %d\n", pid);
        /**
         * waitpid(): on success, returns the process ID of the child whose
         * state has changed; if WNOHANG was specified and one or more
         * child(ren) specified by pid exist, but have not yet changed
         * state, then 0 is returned.  On failure, -1 is returned.
         */
        loop_wait_to_the_end();
    }
}

int create_socket()
{
    int s;
    int optval = 1;
    struct sockaddr_in addr;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* Reuse the address; good for quick restarts */
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        perror("bind fail");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("listen fail");
        exit(EXIT_FAILURE);
    }

    return s;
}

void configure_server_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_chain_file(ctx, "cert/localhost.pem") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "cert/localhost.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

SSL_CTX* create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

//    if (isServer)
        method = TLS_server_method();
//    else
//        method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int main()
{
    if (signal(SIGCHLD, sig_handler) == SIG_ERR)
        printf("\ncan't catch SIGCHLD\n");

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int server_skt = -1;
    int client_skt = -1;

    /* used by getline relying on realloc, can't be statically allocated */
    char *txbuf = NULL;
    size_t txcap = 0;
    int txlen;


    struct sockaddr_in addr;
    unsigned int addr_len = sizeof(addr);

    printf("We are the server on port: %d\n\n", PORT);

    /* Create context used by both client and server */
    ssl_ctx = create_context();

    /* Configure server context with appropriate key files */
    configure_server_context(ssl_ctx);

    /* Create server socket; will bind with server port and listen */
    server_skt = create_socket();

    /*
     * Loop to accept clients.
     * Need to implement timeouts on TCP & SSL connect/read functions
     * before we can catch a CTRL-C and kill the server.
     */
    while (true) {
        /* Wait for TCP connection from client */
        client_skt = accept(server_skt, (struct sockaddr *) &addr, &addr_len);
        if (client_skt < 0) {
            perror("accept fail");
            exit(EXIT_FAILURE);
        }

        if ((pid = fork()) == 0) {
            // child process
            handle_child_process(ssl_ctx, client_skt);
        } else {
            // parent process
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_skt);
        }
    }

    return 0;
}
