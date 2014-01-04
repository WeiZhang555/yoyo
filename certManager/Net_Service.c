#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>

#include "../lib/SSL_Wrapper.h"
#include "util.h"

#define BUFF_LEN 2048

void HandleClientMsg(SSL_CLIENT_DATA* ssl_data, int epollfd)
{
	if(!ssl_data)
		return;
	SSL *ssl = ssl_data->ssl;
	char buffer[BUFF_LEN];
	int recvLen;
	bzero(buffer, BUFF_LEN);
	recvLen = SSL_recv(ssl, buffer, BUFF_LEN);
	if(recvLen <= 0 || strncmp(buffer, "quit", 4)==0)
	{
		printf("client quit!\n");
		SSL_Client_Leave(ssl_data, epollfd);
		return;
	}
	printf("Receive from client %d: %s\n", SSL_get_fd(ssl_data->ssl), buffer);
	fflush(NULL);
	SSL_send(ssl, "Hello client!\n", 14);
}

static void Server_Intr()
{
	printf("Server quit, bye.\n");
	return;
}

/**
 *Start the network service, this is the main part of server.
 *return value: -1 if error occurs, 0 if everything is ok.
 */
int NetworkServiceStart()
{
	signal(SIGINT, Server_Intr);
	return SSL_Listening_Loop(SERVER_PORT, MAX_EVENTS,SERVER_CERT_FILE, HandleClientMsg);
	//TODO: MUST find some approximate time to stop listening.
}
