#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#define FAIL    -1

// create the SSL socket and initialize the socket address structure
int OpenListener(int port) {
    int sockfd;
    struct sockaddr_in addr;

    // setup the socket
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));

    // set up the socket options
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    // bind the socket
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("can't bind port");
        abort();
    }

    if (listen(sockfd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }
	// return descriptor of socket
    return sockfd;
}

// utility function to assert root privlage
int isRoot() {
	//check uid
	if (getuid() != 0) {
		return 0;
	}else {
		return 1;
	}
}

// init ssl server context for connection
SSL_CTX *InitServerCTX(void) {
   const SSL_METHOD *method;
    SSL_CTX *ctx;

    // load & register all cryptos, etc.
    OpenSSL_add_all_algorithms();
    // load all errors messages
    SSL_load_error_strings();
    // create new server-method instance
    method = TLS_server_method();
    // create new context from method
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX *ctx, char *certFile, char *keyFile) {
    // set the local certificate from certFile
    if (SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    // set the private key from keyFile (may be the same as certFile)
    if (SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();        
    }

    // verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    } 
}

void ShowCerts(SSL *ssl) {
    X509 *cert;
    char *line;

    // get certificates (if available)
    cert = SSL_get_peer_certificate(ssl);

    if (cert != NULL) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }else {
        printf("No client certificates.\n");
    }
}

// serve the connection -- threadable
void Servlet(SSL *ssl) {
    char buff[1024] ={0};
    int sockfd, bytes;
    const char *serverResponse = "<Body><Name>aticleworld.com<\\Name><year>1.5<\\year><BlogType>Embedede and c\\c++<\\BlogType><Author>amlendra<\\Author><\\Body>";

    const char *cpValidMessage = "<Body><UserName>aticle<UserName><Password>123<Password><\\Body>";

    if (SSL_accept(ssl) == FAIL) { // do SSL-protocol accept 
        ERR_print_errors_fp(stderr);
    }else {
        // get any certificates
        ShowCerts(ssl); 
        // get request
        bytes = SSL_read(ssl, buff, sizeof(buff));
        buff[bytes] = '\0';

        printf("Client msg: \"%s\"\n", buff);

        if (bytes > 0) {
            if (strcmp(cpValidMessage, buff) == 0) {
                // send reply
                SSL_write(ssl, serverResponse, strlen(serverResponse));
            }else {
                SSL_write(ssl, "Inavlid Message", strlen("Invalid Message"));
            }
        }else {
            ERR_print_errors_fp(stderr);
        }
    }
    // get socket connection
    sockfd = SSL_get_fd(ssl);
    // release SSL state
    SSL_free(ssl);
    // close connection
    close(sockfd);
}

int main(int count, char *Argc[]) {
    SSL_CTX *ctx;
    int server;
    char *portnum;

    // only root user have the permission to run the server
    if (!isRoot()) {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }

    if (count != 2) {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }

    // initialize the ssl library
    SSL_library_init();

    portnum = Argc[1];
    // initialize SSL
    ctx = InitServerCTX();
    // load certs
    LoadCertificates(ctx, "mycert.pem", "mycert.pem");
    // create server socket
    server = OpenListener(atoi(portnum));
    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        // accept conenction
        int client = accept(server, (struct sockaddr*)&addr, &len);
        printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        // get new SSL state with context
        ssl = SSL_new(ctx);
        // set connection socket to SSL state
        SSL_set_fd(ssl, client);
        // service connection
        Servlet(ssl);
    }
    // close server socket
    close(server);
    // release context
    SSL_CTX_free(ctx);
}
