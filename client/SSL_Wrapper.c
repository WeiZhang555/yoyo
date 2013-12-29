#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "util.h"

void ShowCerts(SSL *ssl)
{
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl);

	if(cert)
	{
		printf("Digital Certification information:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Certificate:%s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Issuer:%s\n", line);
		free(line);
		X509_free(cert);
	}else{
		printf("Can't get the certification information!\n");
	}
	fflush(NULL);
	sleep(20);
	return;
}

SSL *SSL_Init(SSL_CTX *ctx, int sockfd)
{
	/*build a new ssl connection on the basis of the connected fd*/
	SSL *ssl = SSL_new(ctx);
	if(!ssl)
	{
		return NULL;
	}

	SSL_set_fd(ssl, sockfd);	/*bind the read-write socket*/
	if(-1==SSL_connect(ssl))
	{
		perror("SSL connect failed!");
		SSL_free(ssl);
		return NULL;
	}else{
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);
	}
	return ssl;
}

void SSL_DeInit(SSL *ssl)
{
	if(ssl)
	{
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
}

SSL_CTX *SSL_CTX_Init()
{	
	/*initialize a new ssl object*/
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
	if(!ctx)
	{
		perror("SSL_CTX_new error!");
		return NULL;
	}
	return ctx;
}

int SSL_CTX_DeInit(SSL_CTX *ctx)
{
	SSL_CTX_free(ctx);
}

