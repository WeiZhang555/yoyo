#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>

#include "util.h"
#include "../lib/SSL_Wrapper.h"
#include "../lib/cJSON/cJSON.h"

char *CreateNewAccountJSON(char *name, char *passwd, char *email)
{
	cJSON *newAccount = cJSON_CreateObject();
	cJSON_AddStringToObject(newAccount, "cmd", "register");
	cJSON *attr = cJSON_CreateObject();
	cJSON_AddItemToObject(newAccount, "attr", attr);
	cJSON_AddStringToObject(attr, "username", name);
	cJSON_AddStringToObject(attr, "password", passwd);
	cJSON_AddStringToObject(attr, "email", email);
	char *accountStr = cJSON_Print(newAccount);
	cJSON_Delete(newAccount);
	return accountStr;
}

/*Register a new user*/
int RegisterAccount(char *name, char *passwd, char *email)
{
	if(!name || !passwd || !email)
		return -1;
	char buffer[1024], *accountStr;
	int sendLen, recvLen;
	
	accountStr = CreateNewAccountJSON(name, passwd, email);
	printf("account:%s\n", accountStr);

	SSL_CLIENT_DATA *ssl_data = SSL_Connect_To(SERVER_IP, SERVER_PORT);
	SSL *ssl = ssl_data->ssl;
	SSL_send(ssl, accountStr, strlen(accountStr));
	bzero(buffer, 1024);
	recvLen = SSL_recv(ssl, buffer, 1024);
	if(recvLen>0)
	{
		printf("From server: %s\n", buffer);
		fflush(NULL);
	}

	SSL_Connect_Close(ssl_data);
	free(accountStr);
}

/*To register a new user*/
void Register()
{
	char name[256], passwd[256], email[256];
	bzero(name, 256);
	bzero(passwd, 256);
	bzero(email, 256);
	printf("UserName:");
	fgets(name, 256, stdin);
	if(Sanitize(name)<=0)
	{
		printf("UserName can not be empty. Exit.\n");
		return;
	}
	printf("Password:");
	fgets(passwd, 256, stdin);
	if(Sanitize(passwd)<=0)
	{
		printf("Password can not be empty. Exit.\n");
		return;
	}

	printf("Email:");
	fgets(email, 256, stdin);
	if(Sanitize(email)<=0)
	{
		printf("Email can not be empty. Exit.\n");
		return;
	}

	printf("User name:%s; Password:%s; email:%s;\n", name, passwd, email);
	RegisterAccount(name, passwd, email);
}

/*Sanitize the user input, delete all the blank in the front and end*/
int Sanitize(char input[])
{
	if(!input)
		return 0;
	int leadBlank=0, i=0;
	int len = strlen(input);
	if(input[len-1]=='\n')
	{
		input[--len] = '\0';
	}

	for(len; len>0; len--)
	{
		if(isspace(input[len-1]))
		{
			input[len] = '\0';
		}else{
			break;
		}
	}

	while(leadBlank<len)
	{
		if(!isspace(input[leadBlank]))
		{
			break;
		}
		leadBlank++;
	}	

	if(leadBlank>0)
	{
		len -= leadBlank;
		for(i=0; i<len;i++)
			input[i] = input[i+leadBlank];
		input[len] = '\0';
	}
	
	return len;
}

void Client_Intr(int signum)
{
	printf("Client quit, bye.\n");
	return;
}

int Client_Service_Start(char *ip, int servport)
{
	signal(SIGINT, Client_Intr);
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
		}else if(0==strcmp("quit", cmd)){
			printf("Client quit, bye.\n");
			return 0;
		}else{
			printf("Commands usable:\n\n");
			printf("1.reg: register a new user.\n");
			printf("quit: quitting the client.\n\n");
			printf("\n");
		}
	}
	
	return 0;
}
