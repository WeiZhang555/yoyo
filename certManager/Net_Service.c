#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
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
char *ProduceNewCertForUser(cJSON *attr)
{
	if(!attr)	return NULL;
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
		return NULL;
	}
	
	int pid = fork();
	if(pid==0)
	{
		chdir("./certs/client/");
		char *cmdName = "./buildClient.sh";
		char *argv[4];
		argv[0] = cmdName;
		argv[1] = username->valuestring;
		argv[2] = email->valuestring;
		argv[3] = NULL;
		printf("username:%s; email:%s\n", argv[0], argv[1]);
		execvp(cmdName, argv);
		exit(0);
	}else{
		wait(NULL);
	}
	char *fileName = (char*)malloc(100);
	snprintf(fileName, 100, "./certs/client/%sCert.pem", username->valuestring);
	return fileName;
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
		char *certFile = ProduceNewCertForUser(attr);	
		printf("Receive from client %d: %s\n", SSL_get_fd(ssl_data->ssl), buffer);
		printf("cerfile:%s;\n", certFile);
		fflush(NULL);
		
		/*Generate the response text*/
		char *resp = NULL;
		FILE *file = fopen(certFile, "r");
		if(!file)
		{
			HandleError(ssl, "Certificate generate failed with unknown error!\n");
		}else{
			cJSON *resp_json = cJSON_CreateObject();
			cJSON_AddStringToObject(resp_json, "cmd", "sending_cert_next");
			char *resp = cJSON_Print(resp_json);
			cJSON_Delete(resp_json);
			SSL_send(ssl, resp, strlen(resp));
			free(resp);
		}
		free(certFile);
	}

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
