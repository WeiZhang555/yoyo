#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "../lib/SSL/SSL_Wrapper.h"
#include "util.h"

void HandleClientMsg(SSL_CLIENT_DATA* ssl_data)
{
	if(!ssl_data)
		return;
	SSL *ssl = ssl_data->ssl;
	char buffer[1024];
	int recvLen;
	bzero(buffer, 1024);
	recvLen = SSL_read(ssl, buffer, 1024);
	if(recvLen <= 0 || strncmp(buffer, "quit", 4)==0)
	{
		printf("client quit!\n");
		SSL_Client_Leave(ssl_data);
		return;
	}
	printf("Receive from client %d: %s\n", SSL_get_fd(ssl_data->ssl), buffer);
	fflush(NULL);
	SSL_write(ssl, "Hello client!\n", 14);
}




/**
 *Start the network service, this is the main part of server.
 *return value: -1 if error occurs, 0 if everything is ok.
 */
int NetworkServiceStart()
{
	int status = SSL_Listening_Loop(SERVER_PORT, MAX_EVENTS,SERVER_CERT_FILE, HandleClientMsg);
	//TODO: MUST find some approximate time to stop listening.
	//close(listenfd);
	//SSL_CTX_DeInit(ctx);
	return status;
}
