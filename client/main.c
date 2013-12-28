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

int main(int argc, char **argv)
{
	if(argc<3)
	{
		printf("Usage: %s IP PORT\n", argv[0]);
		exit(-1);
	}

	int sockfd;
	int servport;
	struct sockaddr_in servaddr;
	char buffer[1024];
	int sendLen, recvLen;
	SSL_CTX *ctx = NULL;

	/*initialize a new ssl object*/
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(SSLv23_client_method());
	if(!ctx)
	{
		perror("SSL CTX new error!");
		return;
	}

	/*create a client socket to connect to the server*/
	servport = atoi(argv[2]);
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0)
	{
		perror("socket() failed!");
		exit(-1);
	}

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(argv[1]);
	servaddr.sin_port = htons(servport);
	inet_pton(AF_INET, argv[1], &servaddr.sin_addr);

	/*connect to server*/
	if(connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
	{
		perror("connect() failed!");
		exit(-1);
	}

	/*build a new ssl connection on the basis of the connected fd*/
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sockfd);	/*bind the read-write socket*/
	if(-1==SSL_connect(ssl))
	{
		perror("SSL connect failed!");
		return -1;
	}else{
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);
	}

	sprintf(buffer, "%s", "This is a client test!");	
	SSL_write(ssl, buffer, strlen(buffer)+1);
	bzero(buffer, 1024);
	recvLen = SSL_read(ssl, buffer, 1024);
	if(recvLen>0)
	{
		printf("From server: %s\n", buffer);
		fflush(NULL);
	}

	/*close ssl connection*/
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sockfd);
	SSL_CTX_free(ctx);
	return 0;
}
