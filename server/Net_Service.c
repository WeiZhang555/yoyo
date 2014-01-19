#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../lib/SSL_Wrapper.h"
#include "../lib/Security.h"
#include "../lib/cJSON/cJSON.h"
#include "Util.h"
#include "Database.h"
#include "Session.h"
#include "File.h"
#include "Json.h"

#define BUFF_LEN 2048

static int GetRandom(int max)
{
	srand(time(NULL));
	return rand()%max;
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

int HandleLogin(SSL *ssl, cJSON *attr)
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
	int sid=-1;
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
			/*Add the session into the list*/
			sid = Session_Add(username);
			/*Print all the session data for debug purpose*/
			Session_Print_All();
    		respJson = cJSON_CreateObject();
    		cJSON_AddStringToObject(respJson, "cmd", "success");
			cJSON *attr = cJSON_CreateObject();
			cJSON_AddItemToObject(respJson, "attr", attr);
			cJSON_AddNumberToObject(attr, "sid", sid);
    		respStr = cJSON_Print(respJson);
    		cJSON_Delete(respJson);
			SSL_send(ssl, respStr, strlen(respStr));
			free(respStr);
			break;
		default:
			break;
	}
	return 0;
}

int HandleQueryPulse(SSL *ssl, cJSON *attr)
{
	if(!attr)
		return -1;
	cJSON *child = attr->child;
	int sid=-1;
	while(child)
	{
		if(0==strcmp(child->string, "sid"))
			sid = child->valueint;
		child = child->next;
	}

	printf("sid:%d\n", sid);
	if(sid==-1)
	{
		HandleError(ssl, "Who are you?");
		return -1;
	}
	SESS_DATA *sess = Session_Find(sid);
	if(!sess)
	{
		HandleError(ssl, "Please login first!");
		return -1;
	}
		
	char *username = sess->username;
	
	FILE_REQUEST *fr = File_Request_To_Whom(username);
	if(!fr)
	{
		char *resp = "{\n\"cmd\": \"none\"\n}";
		SSL_send(ssl, resp, strlen(resp));
	}else{
		char *resp = GenerateFileSendingResp(fr->sid, fr->from, fr->fileName, fr->q, fr->xa_en);
		SSL_send(ssl, resp, strlen(resp));
		free(resp);
		/*Next is to waiting for the client's confirm*/
	}

}

int HandleFileQuery(SSL *ssl,  cJSON *attr)
{
	cJSON *child = attr->child;
	char *to=NULL, *filename=NULL;

	int q, a, sid;
	while(child)
	{
		if(strcmp(child->string, "sid")==0)
		{
			sid = child->valueint;
		}else if(strcmp(child->string, "to")==0)
		{
			to = child->valuestring;
		}else if(strcmp(child->string, "q")==0)
		{
			q = child->valueint;
		}else if(strcmp(child->string, "a")==0)
		{
			a = child->valueint;
		}else if(strcmp(child->string, "filename")==0)
		{
			filename = child->valuestring;
		}
		
		child = child->next;
	}

	/*Check whether the to user exists.*/
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

	/*Check if the user has logined in*/
	const SESS_DATA *sess = Session_Find(sid);
	if(sess==NULL)
	{
		HandleError(ssl, "Please login first!");
		return -1;
	}
	const char *from = sess->username;
	
	FILE_REQUEST *fr = File_Request_Add((char*)from, to, filename, q, a);
	if(!fr)
	{
		HandleError(ssl, "File request can not be handled.");
		return -1;
	}

	char *resp = GenerateFileRequestResp(fr->sid, fr->y);
	SSL_send(ssl, resp, strlen(resp));
	free(resp);
	File_Request_Print_All();
	return 0;
}


int HandleSendingFile(SSL *ssl, cJSON *attr)
{
	if(!ssl)
		return -1;
	int sid;
	char *xa_en=NULL;
	cJSON *child = attr->child;
	while(child)
	{
		if(strcmp(child->string, "sid")==0)
		{
			sid = child->valueint;
		}else if(strcmp(child->string, "x_en")==0)
		{
			xa_en = child->valuestring;
		}
		
		child = child->next;
	}

	printf("sid:%d; xa_en length:%d;\n", sid, (int)strlen(xa_en));
	FILE_REQUEST *fr = File_Request_Find(sid);
	if(!fr)
	{
		HandleError(ssl, "Can not find file request session!");
		return -1;
	}

	fr->xa_en = (char*)malloc(strlen(xa_en)+1);
	bzero(fr->xa_en, strlen(xa_en)+1);
	memcpy(fr->xa_en, xa_en, strlen(xa_en));
	char *resp = "{\n\"cmd\": \"waiting_to_receive\"\n}";
	SSL_send(ssl, resp, strlen(resp));
    
	char filePath[512]={0};
	char dir[256]={0};
	snprintf(dir, 255, "receiveFiles/%s", fr->from);
	if(0>access(dir, F_OK))
		mkdir(dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	snprintf(filePath,255, "%s/%s", dir, fr->fileName);
	
	FILE *f = fopen(filePath, "w");
    if(!f)
        printf("File [%s] can not open!\n", fr->fileName);

    char buffer[512];
    int len = 0;
	printf("Receive file from client [%s]...", fr->from);
    while(1)
    {
        len = SSL_recv(ssl,buffer, 511);
        if(len <=0)
            break;
        buffer[len] = '\0';
        if(0==strcmp("!@done*#",buffer ))
            break;
        else
        {
            if(f)
                fwrite(buffer, sizeof(char), len, f);
        }
    }
    if(!f)
        return -1;
    fclose(f);
	printf("done.\n");
	fr->ready = 1;
	return 0;
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
		HandleLogin(ssl,attr);
	}else if(0==strcmp(cmd->valuestring, "query_pulse"))
	{
		HandleQueryPulse(ssl, attr);
	}else if(0==strcmp(cmd->valuestring, "file_query"))
	{
		HandleFileQuery(ssl,  attr);
	}else if(0==strcmp(cmd->valuestring, "sending_file_next"))
	{
		HandleSendingFile(ssl, attr);
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
