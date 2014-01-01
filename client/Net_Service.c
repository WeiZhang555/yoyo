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
	SSL_send(ssl, buffer, strlen(buffer)+1);
	bzero(buffer, 1024);
	recvLen = SSL_recv(ssl, buffer, 1024);
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

int Sanitize(char input[])
{
	int len = strlen(input);
	if(input[len-1]=='\n')
	{
		input[--len] = '\0';
	}
	return len;
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
			char name[256], passwd[256], email[256];
			bzero(name, 256);
			bzero(passwd, 256);
			bzero(email, 256);
			printf("UserName:");
			fgets(name, 256, stdin);
			if(Sanitize(name)==0)
			{
				printf("UserName can not be empty. Exit.\n");
				continue;
			}
			printf("Password:");
			fgets(passwd, 256, stdin);
			if(Sanitize(passwd)==0)
			{
				printf("Password can not be empty. Exit.\n");
				continue;
			}

			printf("Email:");
			fgets(email, 256, stdin);
			if(Sanitize(email)==0)
			{
				printf("Email can not be empty. Exit.\n");
				continue;
			}
			Register();
		}else if(0==strcmp("quit", cmd)){
			printf("Client quit, bye.\n");
			exit(0);
		}else{
			printf("Commands usable:\n\n");
			printf("1.reg: register a new user.\n");
			printf("quit: quitting the client.\n\n");
			printf("\n");
		}
	}
	
	return 0;
}
