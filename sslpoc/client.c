#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <resolv.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenConnection(const char * hostname, int port) {
	int sockfd;
	struct hostent *host;
	struct sockaddr_in addr;
	
	// get host ip
	if ((host = gethostbyname(hostname)) == NULL) {
		perror(hostname);
		abort();
	}
	
	// setup socket
	sockfd =  socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	
	// set some options
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    // connect to server
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sockfd);
        perror(hostname);
        abort();
    }

    return sockfd;	
}

SSL_CTX *InitCTX(void) {
   const SSL_METHOD *method;
    SSL_CTX *ctx;

    // load cryptos, et.al.
    OpenSSL_add_all_algorithms();
    // bring in and register error messages
    SSL_load_error_strings();
    // create new client-method instance
    method = TLS_client_method();
    // create new context
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl) {
    X509 *cert;
    char *line;

    // get the server's certificate
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        // free the malloc'ed certificate copy
        X509_free(cert);
    }else{
        printf("INFO: No server? certificates configured");
    }
}

int main(int count, char * strings[]) {
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buff[1024];
    char acClientRequest[1024] = {0};
    int bytes;
    char *hostname, *portnum;
    
    // assert args are given
    if (count != 3) {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    hostname = strings[1];
    portnum = strings[2];

    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));
    // create new SSL conenction state
    ssl = SSL_new(ctx);
    // attach the socket descriptor
    SSL_set_fd(ssl, server);
    // perform connection
    if (SSL_connect(ssl) == FAIL) {
        ERR_print_errors_fp(stderr);
    }else {
        char acUsername[16] = {0};
        char acPassword[16] = {0};
        const char *cpRequestMessage = "<Body><UserName>%s<UserName><Password>%s<Password><\\Body>";
        printf("Enter the User Name: ");
        scanf("%s", acUsername);

		printf("\n\nEnter the Password : ");
		scanf("%s", acPassword);
		
        // construct reply
        sprintf(acClientRequest, cpRequestMessage, acUsername, acPassword);

        printf("\n\nConencted with %s encryption\n", SSL_get_cipher(ssl));
        // get any certs
        ShowCerts(ssl);
        // encrypt & send message
        SSL_write(ssl, acClientRequest, strlen(acClientRequest));
        // get reply & decrypt
        bytes = SSL_read(ssl, buff, sizeof(buff));
        buff[bytes]= 0;
        printf("Recieved: \"%s\"\n", buff);
        // release connection state
        SSL_free(ssl);
    }
    // close socket
    close(server);
    // release context
    SSL_CTX_free(ctx);
    return 0;
}
