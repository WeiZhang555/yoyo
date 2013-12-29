#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "util.h"

SSL *SSL_Init(SSL_CTX *ctx, int connfd)
{
	if(!ctx || connfd<=0)
		return NULL;
	SSL *ssl = SSL_new(ctx);
	if(!ssl)
		return NULL;
	
	SSL_set_fd(ssl, connfd);
	if(-1==SSL_accept(ssl))
	{
		perror("SSL accept error.");
		if(ssl)
		{
			SSL_free(ssl);
		}
		return NULL;
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
	SSL_CTX *ctx = NULL;
	/*Initialize the ssl encryption part*/
	SSL_library_init();
	/*load all the ssl error message*/
	SSL_load_error_strings();
	/*load all the ssl algorithms*/
	OpenSSL_add_ssl_algorithms();
	/*Create an new ssl ctx*/
	ctx = SSL_CTX_new(SSLv23_server_method());	
	/*load the user's certificate*/
	if(!SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM))
	{
		perror("use certificate file error!");
		return NULL;
	}
	/*load user's private key*/
	if(!SSL_CTX_use_PrivateKey_file(ctx, CERT_FILE, SSL_FILETYPE_PEM))
	{
		perror("use private key file error!");
		return NULL;
	}
	/*check whether the private key is correct or not*/
	if(!SSL_CTX_check_private_key(ctx))
	{
		perror("private key check error!");
		return NULL;
	}

	return ctx;
}

int SSL_CTX_DeInit(SSL_CTX *ctx)
{
	SSL_CTX_free(ctx);
}
