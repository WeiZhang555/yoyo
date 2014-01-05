#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>

#include "../lib/SSL_Wrapper.h"
#include "../lib/cJSON/cJSON.h"
#include "util.h"

#define BUFF_LEN 2048

char *GenerateErrorResp(char *errMes)
{
    cJSON *error = cJSON_CreateObject();
    cJSON_AddStringToObject(error, "cmd", "error");
    cJSON *attr = cJSON_CreateObject();
    cJSON_AddItemToObject(error, "attr", attr);
    cJSON_AddStringToObject(attr, "message", errMes);
    char *errstr = cJSON_Print(error);
    cJSON_Delete(error);
    return errstr;
}

void HandleError(SSL *ssl, char *errStr)
{
    char *resp = GenerateErrorResp(errStr);
    SSL_send(ssl, resp, strlen(resp));
    free(resp);
}

/**
 *Produce a new cert for user
 *return: -1 for error, 0 for success.
 */
int ProduceNewCertForUser(cJSON *attr)
{
	if(!attr)	return -1;
	cJSON *username=NULL, *email=NULL, *child=NULL;
	child = attr->child;
	while(child)
	{
		if(0==strcmp(child->string,"username"))
		{
			username = child;
		}else if(0==strcmp(child->string, "email"))
		{
			email = child;
		}
		child = child->next;
	}

	if(!username || !email)
	{
		return -1;
	}
	
	char *argv[3];
	argv[0] = username->valuestring;
	argv[1] = email->valuestring;
	argv[2] = NULL;
	printf("username:%s; email:%s\n", argv[0], argv[1]);
	execvp("./certs/client/buildClient.sh", argv);
	return 0;
}
	
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

	/*Parse the user cert request*/
	cJSON *root = cJSON_Parse(buffer);
	if(!root)	
	{
		HandleError(ssl, "JSON parse error!");
		goto end;
	}

	cJSON *child = root->child, *cmd=NULL, *attr=NULL;
	while(child)
	{
		if(0==strcmp(child->string, "cmd"))
			cmd = child;
		else if(0==strcmp(child->string, "attr"))
			attr = child;
		
		child = child->next;
	}

	if(0==strcmp(cmd->valuestring, "get_cert"))
	{
		if(fork()==0)
			ProduceNewCertForUser(attr);	
	}
	printf("Receive from client %d: %s\n", SSL_get_fd(ssl_data->ssl), buffer);
	fflush(NULL);
	SSL_send(ssl, "Hello client!\n", 14);
end:
	cJSON_Delete(root);
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
