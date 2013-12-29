#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "util.h"

extern SSL *SSL_Init(SSL_CTX *ctx, int sockfd);
extern void SSL_DeInit(SSL *ssl);
extern SSL_CTX *SSL_CTX_Init();
extern int SSL_CTX_DeInit(SSL_CTX *ctx);

int Client_Service_Start(char *ip, int servport)
{
	int sockfd;
	struct sockaddr_in servaddr;
	char buffer[1024];
	int sendLen, recvLen;
	SSL_CTX *ctx = NULL;

	ctx = SSL_CTX_Init();
	if(!ctx)
	{
		return -1;
	}

	/*create a client socket to connect to the server*/
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0)
	{
		perror("socket() failed!");
		return -1;
	}

	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(servport);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);

	/*connect to server*/
	if(connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
	{
		perror("connect() failed!");
		return -1;
	}

	/*build a new ssl connection on the basis of the connected fd*/
	SSL *ssl = SSL_Init(ctx, sockfd);
	if(!ssl)
		return -1;

	sprintf(buffer, "%s", "This is a client test!");	
	SSL_write(ssl, buffer, strlen(buffer)+1);
	bzero(buffer, 1024);
	recvLen = SSL_read(ssl, buffer, 1024);
	if(recvLen>0)
	{
		printf("From server: %s\n", buffer);
		fflush(NULL);
	}

	sleep(10);
	/*close ssl connection*/
	SSL_DeInit(ssl);
	SSL_CTX_DeInit(ctx);
	close(sockfd);
	return 0;
}
