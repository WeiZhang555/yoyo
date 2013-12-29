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
#include "../lib/SSL/SSL_Wrapper.h"
#include "../lib/cJSON/cJSON.h"

void SendInformation(char *ip, int port)
{
	char buffer[1024];
	int sendLen, recvLen;
	SSL_CLIENT_DATA *ssl_data = SSL_Connect_To(ip, port);
	SSL *ssl = ssl_data->ssl;
	sprintf(buffer, "%s", "This is a client test!");	
	SSL_write(ssl, buffer, strlen(buffer)+1);
	bzero(buffer, 1024);
	recvLen = SSL_read(ssl, buffer, 1024);
	if(recvLen>0)
	{
		printf("From server: %s\n", buffer);
		fflush(NULL);
	}

	sleep(4);
	SSL_Connect_Close(ssl_data);
}

void Register()
{
	SendInformation(SERVER_IP, SERVER_PORT);
}

int Client_Service_Start(char *ip, int servport)
{
	while(1)
	{
		char cmd[256];
		bzero(cmd, sizeof(char)*256);
		printf("What's you command,sir? >");
		fgets(cmd, 256, stdin);
		int len = strlen(cmd);
		if(cmd[len-1]=='\n')
		{
			cmd[--len] = '\0';
		}

		if(0==strcmp("reg", cmd))
		{
			Register();
		}else{
			printf("You can use these commands:\n");
			printf("reg: register a new user.\n");
			printf("\n");
		}
	}
	
	return 0;
}
