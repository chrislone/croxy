#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/bio.h> /* BasicInput/Output streams */
#include <openssl/err.h> /* errors */
#include <llhttp/llhttp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/poll.h>

#include <string>
#include <iostream>
#include <vector>
#include <algorithm>
#include <map>
#include <vector>
#include <utility>
#include <locale>

using namespace std;

#define BUF_LEN 1024

static int len;
static char tmpbuf[BUF_LEN];

//BIO *out;

namespace {
    bool server_running = true;
    bool isComplete = false;
    vector<pair<string, string>> headers;
}

void setHeadersField(const char* field) {
    printf("setHeadersField %s\n", field);
    string v = string(field);
    headers.push_back(pair<string, string>(v, ""));
};

void setHeadersValue(const char* value) {
    printf("setHeadersValue %s\n", value);
    (headers[headers.size() - 1]).second = string(value);
};

int on_url_handler(llhttp_t* parser, const char* at, size_t length) {
    char substr[length + 1];
    // 将子字符串复制到新的字符串中
    strncpy(substr, at, length);
    substr[length] = '\0';  // 添加字符串结束符
    printf("on_url_handler: %s\n", substr);
    return 0;
}

int on_body(llhttp_t* parser, const char* at, size_t length) {
    char substr[length + 1];
    strncpy(substr, at, length);
    substr[length] = '\0';  // 添加字符串结束符
    printf("on_body_handler: %s\n", substr);
    return 0;
}

int on_headers_complete(llhttp_t *parser) {
//    char substr[length + 1];
//    strncpy(substr, at, length);
//    substr[length] = '\0';  // 添加字符串结束符

    cout << "on_headers_complete: \x0A\x0A" << parser->status_code << endl;
    cout << "on_headers_complete: content_length" << parser->status_code << endl;
    return 0;
};

string stringToUpper(string &str) {
    const char *c_str = str.c_str();
    char *c = (char *)c_str;
    for(; *c != 0; c++) {
        *c = toupper(*c);
    }
    return string(c_str);
}

class ChildProcess {
public:
    ChildProcess() = default;
    ~ChildProcess() {};
    std::string acceptHttpStr;
    SSL *ssl;
    int backwardSocketFd = -1;
    void settingParse();
    void doParse();
    llhttp_t parser;
    llhttp_settings_t settings;
    static int onUrlHandler(llhttp_t* parser, const char* at, size_t length);
    static int onBody(llhttp_t* parser, const char* at, size_t length);
    static int onHeadersComplete(llhttp_t *parser);
    static int onHeaderField(llhttp_t *parser, const char *at, size_t length);
    static int onHeaderValue(llhttp_t *parser, const char *at, size_t length);
    static int onMessageComplete(llhttp_t *parser);
    static int onHeaderFieldComplete(llhttp_t *parser);
    static string findHeader(string s);
    string forwardHostName;
    string forwardPort = "80";
    SSL_CTX *forwardCtx;
    SSL *forwardSsl;
    int forwardSocketFd = -1;
//    void retResponse();
    void retConnectResponse();
    void getForwardHostAndPort();
    void configForwardCtx();
    int createForwardClientSocket();
    string getForwardDottedIp();
    // connect to remote server and notice client
    void connectClientAndRemote();
private:
};

// llhttp_t ====
//struct llhttp__internal_s {
//    int32_t _index;
//    void* _span_pos0;
//    void* _span_cb0;
//    int32_t error;
//    const char* reason;
//    const char* error_pos;
//    void* data;
//    void* _current;
//    uint64_t content_length;
//    uint8_t type;
//    uint8_t method;
//    uint8_t http_major;
//    uint8_t http_minor;
//    uint8_t header_state;
//    uint16_t lenient_flags;
//    uint8_t upgrade;
//    uint8_t finish;
//    uint16_t flags;
//    uint16_t status_code;
//    uint8_t initial_message_completed;
//    void* settings;
//};

void ChildProcess::settingParse() {
//    llhttp_t parser;
//    llhttp_settings_t settings;
    llhttp_settings_init(&(this->settings));
    llhttp_init(&(this->parser), HTTP_BOTH, &(this->settings));

    settings.on_url = ChildProcess::onUrlHandler;
    settings.on_body = ChildProcess::onBody;
    settings.on_headers_complete = ChildProcess::onHeadersComplete;
    settings.on_header_field = ChildProcess::onHeaderField;
    settings.on_header_value = ChildProcess::onHeaderValue;
    settings.on_message_complete = ChildProcess::onMessageComplete;
}

//void ChildProcess::doParse() {
//    enum llhttp_errno err = llhttp_execute(&(this->parser), this->acceptHttpStr.c_str(), this->acceptHttpStr.size());
//    if (err == HPE_OK) {
//        /* Successfully parsed! */
//        cout << "llhttp_errno err: " << err << endl;
//    } else {
//        fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(err), parser.reason);
//    }
//}

int ChildProcess::onUrlHandler(llhttp_t* parser, const char* at, size_t length) {
    char substr[length + 1];
    // 将子字符串复制到新的字符串中
    strncpy(substr, at, length);
    substr[length] = '\0';  // 添加字符串结束符
    printf("on_url_handler: %s\n", substr);
    return 0;
}

int ChildProcess::onBody(llhttp_t* parser, const char* at, size_t length) {
    char substr[length + 1];
    strncpy(substr, at, length);
    substr[length] = '\0';  // 添加字符串结束符
//    printf("on_body_handler: %s\n", substr);
    return 0;
}

int ChildProcess::onHeadersComplete(llhttp_t* parser) {
//    cout << "on_headers_complete: \x0A\x0A" << parser->status_code << endl;
//    cout << "on_headers_complete parser->data: \x0A" << parser->data << endl;
    return 0;
}

int ChildProcess::onHeaderField(llhttp_t *parser, const char *at, size_t length) {
    char substr[length + 1];
    strncpy(substr, at, length);
    substr[length] = '\0';  // 添加字符串结束符
//    cout << "on_header_field: \x0A" << substr << endl;
    setHeadersField(substr);
    return 0;
}

int ChildProcess::onHeaderValue(llhttp_t *parser, const char *at, size_t length) {
    char substr[length + 1];
    strncpy(substr, at, length);
    substr[length] = '\0';  // 添加字符串结束符
//    cout << "on_header_value: \x0A" << substr << endl;
    setHeadersValue(substr);
    return 0;
}

int ChildProcess::onMessageComplete(llhttp_t* parser) {
    fprintf(stdout, "Message completed!\n");
    printf("parser->method: %d, %s\n", parser->method, llhttp_method_name((llhttp_method_t)parser->method));
    cout << "onMessageComplete headers[0]: " << ChildProcess::findHeader("host") << endl;
    if(parser->method != HTTP_CONNECT) {
        isComplete = true;
    }
    return 0;
}

string ChildProcess::findHeader(string s) {
    string upperStr = stringToUpper(s);
    auto it = find_if(headers.begin(), headers.end(), [&upperStr](pair<string, string> pairItem) -> bool { return stringToUpper(pairItem.first) == upperStr; });
    if(it != headers.cend()) {
        return headers[it - headers.cbegin()].second;
    }
    return "";
}

void ChildProcess::configForwardCtx() {
    const SSL_METHOD *method;
    method = TLS_client_method();

    this->forwardCtx = SSL_CTX_new(method);

    if (this->forwardCtx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // use the default system certificate
    SSL_CTX_set_default_verify_paths(this->forwardCtx);
}

void ChildProcess::connectClientAndRemote() {
    this->getForwardDottedIp();
    this->retConnectResponse();

    /* Loop to send input from keyboard */
    char buf[BUF_LEN];

    int fdCount = 2;

    /*struct pollfd {
        int   fd;         *//* file descriptor *//*
        short events;     *//* requested events *//*
        short revents;    *//* returned events *//*
    };*/

    struct pollfd poll_read_fds_list[fdCount];
    poll_read_fds_list[0].fd = this->backwardSocketFd;
    poll_read_fds_list[1].fd = this->forwardSocketFd;

    for(int i = 0; i < fdCount; ++i)
    {
        // indicate when some fd has inbound data or error occurred, poll() return immediately
        poll_read_fds_list[i].events = POLLRDHUP | POLLIN | POLLERR;
    }

    for(;;) {
        int readyCount = poll(poll_read_fds_list, fdCount, -1);
//        if(readyCount == 0) {
//            continue;
//        }
        if(readyCount < 0) {
            break;
        }
        for(int idx = 0; idx < fdCount; idx++) {
            if ((poll_read_fds_list[idx].revents & POLLRDHUP) || (poll_read_fds_list[idx].revents & POLLERR)) {
                cout << "close" << endl;
                SSL_shutdown(this->ssl);
                SSL_free(this->ssl);
                SSL_shutdown(this->forwardSsl);
                SSL_free(this->forwardSsl);
                close(this->forwardSocketFd);
                close(this->backwardSocketFd);
                exit(0);
            }
            // read from client ready
            if (poll_read_fds_list[idx].fd == this->backwardSocketFd && (poll_read_fds_list[idx].revents & POLLIN)) {
                memset(buf, 0, sizeof(buf));
                int read_byte = SSL_read(this->ssl, buf, BUF_LEN - 1);
                if (read_byte == 0) {
                    break;
                }
                if(read_byte < 0) {
                    close(this->forwardSocketFd);
                    close(this->backwardSocketFd);
                    exit(0);
                }
                write(this->forwardSocketFd, buf, read_byte);
            }

            // read from remote server ready
            if (poll_read_fds_list[idx].fd == this->forwardSocketFd && (poll_read_fds_list[idx].revents & POLLIN)) {
                memset(buf, 0, sizeof(buf));
                int read_byte = read(this->forwardSocketFd, buf, BUF_LEN - 1);
                if (read_byte == 0) {
                    break;
                }
                if(read_byte < 0) {
                    close(this->forwardSocketFd);
                    close(this->backwardSocketFd);
                    exit(0);
                }
                SSL_write(this->ssl, buf, read_byte);
            }
        }
    }
}

string ChildProcess::getForwardDottedIp() {
    int sfd, s;
    char buf[BUF_LEN];
    struct addrinfo hints;
    struct addrinfo *result, *rp;

    /* Obtain address(es) matching host/port. */

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    s = getaddrinfo(this->forwardHostName.c_str(), this->forwardPort.c_str(), &hints, &result);

    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

    /* getaddrinfo() returns a list of address structures.
       Try each address until we successfully connect(2).
       If socket(2) (or connect(2)) fails, we (close the socket
       and) try the next address. */
    struct sockaddr_in *addr;
    char ipbuf[16] = {0};
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
        {
            struct sockaddr_in *addr = (struct sockaddr_in *)rp->ai_addr;
            printf("ip: %s\n", inet_ntop(AF_INET, &addr->sin_addr, ipbuf, sizeof(ipbuf)));
            printf("port: %d\n", ntohs(addr->sin_port));
            printf("rp->ai_addrlen: %d\n", rp->ai_addrlen);
            this->forwardSocketFd = sfd;
            break;                  /* Success */
        }

        close(sfd);
    }

    freeaddrinfo(result);           /* No longer needed */

    if(strlen(ipbuf) > 0) {
        return string(ipbuf);
    }
    return "";
}

void ChildProcess::retConnectResponse() {
    string returnStr = "HTTP/1.1 200 Connection established\r\n";
    returnStr += "Proxy-Agent: croxy/0.0.1\r\n";
    returnStr += "\r\n";

    /* Response it back */
    if (SSL_write(this->ssl, returnStr.c_str(), returnStr.size()) <= 0) {
        ERR_print_errors_fp(stderr);
    }
}

void ChildProcess::getForwardHostAndPort() {
    // host:port
    string hostAndPort = ChildProcess::findHeader("host");
    int index = hostAndPort.find(":");

    if(index >= 0) {
        this->forwardHostName = hostAndPort.substr(0, index);
        string port = hostAndPort.substr(index + 1, hostAndPort.size() - index);
        if(port.size() > 0) {
            this->forwardPort = port;
        }
    }
}

void handle_child_process(SSL_CTX *ssl_ctx, int client_skt) {
    ChildProcess childItem;

    childItem.settingParse();

    childItem.backwardSocketFd = client_skt;

    char rxbuf[BUF_LEN];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    /* Create server SSL structure using newly accepted client socket */
    childItem.ssl = SSL_new(ssl_ctx);

    SSL *ssl = childItem.ssl;
    SSL_set_fd(ssl, client_skt);

    /* Wait for SSL connection from the client */
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        server_running = false;
    } else {
        printf("Client SSL connection accepted\n\n");

        /* Echo loop */
        while (!isComplete) {
            /* Get message from client; will fail if client closes connection */
            if ((rxlen = SSL_read(ssl, rxbuf, BUF_LEN)) <= 0) {
                ERR_print_errors_fp(stderr);
                break;
            }
            /* Insure null terminated input */
            rxbuf[rxlen] = 0;
            /* Look for kill switch */
//            if (strcmp(rxbuf, "kill\n") == 0) {
//                /* Terminate...with extreme prejudice */
//                printf("Server received 'kill' command\n");
//                server_running = false;
//                break;
//            }
            /* Show received message */
            enum llhttp_errno err = llhttp_execute(&(childItem.parser), rxbuf, rxlen);
            if (err == HPE_OK) {
                /* Successfully parsed! */
                cout << "Successfully parsed!" << endl;
            } else {
                fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(err), childItem.parser.reason);
                if(childItem.parser.method == HTTP_CONNECT) {
                    childItem.getForwardHostAndPort();
//                    childItem.retConnectResponse();
                    childItem.connectClientAndRemote();
                }
                break;
            }
            if (rxlen <= 0) {
                printf("Client closed connection\n");
                break;
            } else {
                printf("SSL_read returned %d\n", rxlen);
            }
        }
    }
    if (isComplete) {
        /* Cleanup for next client */
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_skt);
        exit(0);
    }
}
