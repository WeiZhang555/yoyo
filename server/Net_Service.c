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
#include "Session.h"

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
	
	SSL_send(ssl, resp, strlen(resp));
	free(resp);
	return;
}

int HandleCertStatusUpdate(SSL *ssl, cJSON *attr)
{
	cJSON *child = attr->child;
	char *username=NULL;
	while(child)
	{
		if(strcmp(child->string, "username")==0)
		{
			username = child->valuestring;
		}
		
		child = child->next;
	}

	/*Just update the database silently.*/
	int status = DB_Update_Cert_Status(username);
	if(status < 0)
	{
		printf("Database update failed!");
		return -1;
	}

	return 0;
}

int HandleLogin(SSL *ssl,int epollfd, cJSON *attr)
{
	if(!ssl || !attr)	return -1;
	char *username=NULL, *password=NULL;
	cJSON *child = attr->child;
	while(child)
	{
		if(0==strcmp(child->string, "username"))
			username = child->valuestring;
		else if(0==strcmp(child->string, "password"))
			password = child->valuestring;

		child = child->next;
	}
	
	if(!username || !password)
		return -1;
	int status = DB_Login(username, password);
	cJSON *respJson; char *respStr=NULL;
	switch(status){
		case -1:	/*Unknown Error*/
			HandleError(ssl, "Unknown error!");
			break;
		case -2:	/*user not exists*/
			HandleError(ssl, "User not exists.");
			break;
		case -3:	/*password wrong*/
			HandleError(ssl, "Password is not right.");
			break;
		case -4:	/*cert status not ready*/
			HandleError(ssl, "Certificate is not ready?");
			break;
		case 0:		/*correct*/
    		respJson = cJSON_CreateObject();
    		cJSON_AddStringToObject(respJson, "cmd", "success");
    		respStr = cJSON_Print(respJson);
    		cJSON_Delete(respJson);
			SSL_send(ssl, respStr, strlen(respStr));
			/*Add the session into the list*/
			Session_Add(epollfd, username);
			/*Print all the session data for debug purpose*/
			Session_Print_All();
			free(respStr);
			break;
		default:
			break;
	}
	return 0;
}

int HandleQueryPulse(SSL *ssl, int epollfd)
{
	const SESS_DATA *sess = Session_Find(epollfd);
	if(sess)
	{
		printf("Heartbeat:%s\n", sess->username);
	}
}

int HandleFileQuery(SSL *ssl, int epollfd, cJSON *attr)
{
	cJSON *child = attr->child;
	char *to=NULL, *filename=NULL;
	int q, a;
	while(child)
	{
		if(strcmp(child->string, "to")==0)
		{
			to = child->valuestring;
		}else if(strcmp(child->string, "q"))
		{
			q = child->valueint;
		}else if(strcmp(child->string, "a"))
		{
			a = child->valueint;
		}else if(strcmp(child->string, "filename")==0)
		{
			filename = child->valuestring;
		}
		
		child = child->next;
	}

	/*Just update the database silently.*/
	int status = DB_Check_User(to);
	if(status < 0)
	{
		HandleError(ssl, "Unknown error from server database.");
		return -1;
	}else if(status==0)
	{
		HandleError(ssl, "User not exists!");
		return -1;
	}

	

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
		Session_Delete(epollfd);
		Session_Print_All();
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
	}else if(0==strcmp(cmd->valuestring, "cert_status_ok"))
	{
		HandleCertStatusUpdate(ssl, attr);
	}else if(0==strcmp(cmd->valuestring, "login"))
	{
		HandleLogin(ssl,epollfd,attr);
	}else if(0==strcmp(cmd->valuestring, "query_pulse"))
	{
		HandleQueryPulse(ssl, epollfd);
	}else if(0==strcmp(cmd->valuestring, "file_query"))
	{
		HandleFileQuery(ssl, epollfd, attr);
	}

	cJSON_Delete(root);
}

static void Server_Intr()
{
	printf("Server quit, bye.\n");
	return ;
}

static void Pipe_Broken()
{
	printf("Pipe broken!\n");
	return;
}

/**
 *Start the network service, this is the main part of server.
 *return value: -1 if error occurs, 0 if everything is ok.
 */
int NetworkServiceStart()
{
	signal(SIGINT, Server_Intr);
	signal(SIGPIPE, Pipe_Broken);
	return SSL_Listening_Loop(SERVER_PORT, MAX_EVENTS,SERVER_CERT_FILE, HandleClientMsg);
	//TODO: MUST find some approximate time to stop listening.
}
