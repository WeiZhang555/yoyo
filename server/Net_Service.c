#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>

#include "../lib/SSL_Wrapper.h"
#include "../lib/Security.h"
#include "../lib/cJSON/cJSON.h"
#include "Util.h"
#include "Database.h"

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

void HandleRegister(SSL *ssl, cJSON *attr)
{
	printf("Customer want to register.\n");
	cJSON *child = attr->child;
	char *username=NULL, *password=NULL, *email=NULL;
	while(child)
	{
		if(strcmp(child->string, "username")==0)
		{
			username = child->valuestring;
		}else if(strcmp(child->string, "password")==0)
		{
			password = child->valuestring;
		}else if(strcmp(child->string, "email")==0)
		{
			email = child->valuestring;
		}
		
		child = child->next;
	}

	int status = DB_Check_User(username);
	char *resp = NULL;
	if(status < 0)	/*Database error*/
	{
		resp = GenerateErrorResp("Database error!");
	}else if(status > 0)  /*user exists in the database*/
	{
		resp = GenerateErrorResp("Username already taken!");
	}else{
		/*Insert user into database*/
		if(DB_Insert_User(username, password, email))
		{
			resp = GenerateErrorResp("Database update error!");
		}else{
    		cJSON *cmd = cJSON_CreateObject();
    		cJSON_AddStringToObject(cmd, "cmd", "get_cert");
			resp = cJSON_Print(cmd);
			cJSON_Delete(cmd);
		}
	}
	
	printf("Response:\n%s\n", resp);	
	SSL_send(ssl, resp, strlen(resp));
	free(resp);
	return;
}

void HandleClientMsg(SSL_CLIENT_DATA* ssl_data, int epollfd)
{
	if(!ssl_data)
		return;
	cJSON *root=NULL, *cmd=NULL, *attr=NULL, *child=NULL;
	SSL *ssl = ssl_data->ssl;
	char buffer[BUFF_LEN];
	int recvLen;
	bzero(buffer, BUFF_LEN);

	/*Receive information from client*/
	recvLen = SSL_recv(ssl, buffer, BUFF_LEN);
	if(recvLen <= 0 || strncmp(buffer, "quit", 4)==0)
	{
		printf("client quit!\n");
		SSL_Client_Leave(ssl_data, epollfd);
		return;
	}
	printf("client %d: %s\n", SSL_get_fd(ssl_data->ssl), buffer);
	/*Parse the client message*/
	root = cJSON_Parse(buffer);
	if(!root)
	{
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());
		HandleError(ssl, "JSON format not recognized.");
		return;
	}

	child = root->child;
	while(child)
	{
		if(strcmp(child->string, "cmd")==0)
		{
			cmd = child;
		}else if(strcmp(child->string, "attr")==0)
		{
			attr = child;
		}
		
		child = child->next;
	}
	
	if(0==strcmp(cmd->valuestring, "register"))
	{
		HandleRegister(ssl, attr);
	}
	
	fflush(NULL);

	cJSON_Delete(root);
}

static void Server_Intr()
{
	printf("Server quit, bye.\n");
	return ;
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
