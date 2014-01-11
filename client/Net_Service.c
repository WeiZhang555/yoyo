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

SSL_CLIENT_DATA *ssl_server_data = NULL;
SSL_CLIENT_DATA *ssl_cm_data = NULL;
char name[256]={0}, passwd[256]={0}, email[256]={0};

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

char *CreateCMJSON(char *name, char *email)
{
	cJSON *cert = cJSON_CreateObject();
	cJSON_AddStringToObject(cert, "cmd", "get_cert");
	cJSON *attr = cJSON_CreateObject();
	cJSON_AddItemToObject(cert, "attr", attr);
	cJSON_AddStringToObject(attr, "username", name);
	cJSON_AddStringToObject(attr, "email", email);
	char *CMStr = cJSON_Print(cert);
	cJSON_Delete(cert);
	return CMStr;
}

/*Return 0 for true, -1 for error*/
int ParseRegisterStep1Resp(char *buffer)
{
	if(!buffer)
		return -1;
	cJSON *root=NULL, *child=NULL, *cmd=NULL, *attr = NULL;
	root = cJSON_Parse(buffer);
	if(!root)
		return -1;
	child = root->child;
	while(child)
	{
		if(0==strcmp(child->string, "cmd"))
			cmd = child;
		else if(0==strcmp(child->string, "attr"))
			attr = child;
		child = child->next;
	}

	if(!cmd)	return -1;
	if(0==strcmp(cmd->valuestring, "error"))
	{
		if(attr->child)
			printf("Error:%s\n", attr->child->valuestring);
		return -1;
	}else if(0==strcmp(cmd->valuestring, "get_cert"))
	{
		printf("User has been registered into the server, waiting to get the private certificate.\n");
	}
	cJSON_Delete(root);
	return 0;
}

int ReceiveCertFromCM(cJSON *attr)
{
	if(!attr)
		return -1;
	char *certFile = NULL;
	cJSON *child = attr->child;
	while(child)
	{
		if(0==strcmp(child->string, "filename"))
		{
			certFile = child->valuestring;
		}
		child = child->next;
	}

	printf("Cert name:%s\n", certFile);
	if(!certFile)	return -1;
	FILE *f = fopen(certFile, "w");
	if(!f)
		printf("Certificate file [%s] can not open!\n", certFile);
	char buffer[512];
	int len = 0;
	while(1)
	{
		len = SSL_recv(ssl_cm_data->ssl,buffer, 511);
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
	return 0;
}

int ParseRegisterStep2Resp(char *buffer)
{
	if(!buffer)
		return -1;
	cJSON *root=NULL, *child=NULL, *cmd=NULL, *attr = NULL;
	root = cJSON_Parse(buffer);
	if(!root)
		return -1;
	child = root->child;
	while(child)
	{
		if(0==strcmp(child->string, "cmd"))
			cmd = child;
		else if(0==strcmp(child->string, "attr"))
			attr = child;
		child = child->next;
	}

	if(!cmd)	return -1;
	if(0==strcmp(cmd->valuestring, "error"))
	{
		if(attr->child)
			printf("Error:%s\n", attr->child->valuestring);
		return -1;
	}else if(0==strcmp(cmd->valuestring, "sending_cert_next"))
	{
		ReceiveCertFromCM(attr);
		UpdateStatusAndLogin();
	}
	cJSON_Delete(root);
	return 0;
}


/*Login process*/
int Login()
{
	/*First to check whether we get the username and password or not*/
	if(strlen(name)==0 || strlen(passwd)==0)
	{
		GetUserName();
		GetUserPassword();
	}
	/*Second must check if we have the certificates*/
	char certFile[1024]={0};
	strncpy(certFile, name, 1000);
	strcat(certFile, "Cert.pem");
	FILE *f = fopen(certFile, "r");
	if(!f)
	{
		printf("You have't got the certificate yet!\n");
		return -1;
	}
	fclose(f);

	/*Start the login process*/
	cJSON *loginJson = cJSON_CreateObject();
	cJSON_AddStringToObject(loginJson, "cmd", "login");
	cJSON *attr = cJSON_CreateObject();
	cJSON_AddItemToObject(loginJson, "attr", attr);
	cJSON_AddStringToObject(attr, "username", name);
	cJSON_AddStringToObject(attr, "password", passwd);
	char *loginStr = cJSON_Print(loginJson);
	cJSON_Delete(loginJson);
	
	if(!ssl_server_data)
		ssl_server_data = SSL_Connect_To(SERVER_IP, SERVER_PORT);
	if(!ssl_server_data)	
	{
		free(loginStr);
		printf("Connect to server failed!\n");
		return -1;
	}

	SSL_send(ssl_server_data->ssl, loginStr, strlen(loginStr));
	free(loginStr);
	char buffer[1024]={0};
	int recvLen = SSL_recv(ssl_server_data->ssl, buffer, 1024);
	if(recvLen<=0)
	{
		printf("Unknown error from server.\n");
		return -1;
	}

	printf("From Server:\n%s\n", buffer);
	return 0;
}

/*Step 3: Update the cert status to ok(certificate prepared) and login */
int UpdateStatusAndLogin()
{
	cJSON *upCert = cJSON_CreateObject();
	cJSON_AddStringToObject(upCert, "cmd", "cert_status_ok");
	cJSON *attr = cJSON_CreateObject();
	cJSON_AddItemToObject(upCert, "attr", attr);
	cJSON_AddStringToObject(attr, "username", name);
	char *certStr = cJSON_Print(upCert);
	cJSON_Delete(upCert);

	if(!ssl_server_data)
		ssl_server_data = SSL_Connect_To(SERVER_IP, SERVER_PORT);
	if(!ssl_server_data)	
	{
		printf("Connect to server failed!\n");
		return -1;
	}

	SSL_send(ssl_server_data->ssl, certStr, strlen(certStr));
	free(certStr);

	Login();
}

/*Registration step 1: log the user information into the server database*/
int RegisterIntoServer(char *name, char *passwd, char *email)
{	
	char buffer[1024], *accountStr;
	int sendLen, recvLen;
	
	accountStr = CreateNewAccountJSON(name, passwd, email);
	printf("account:%s\n", accountStr);

	if(!ssl_server_data)
		ssl_server_data = SSL_Connect_To(SERVER_IP, SERVER_PORT);
	if(!ssl_server_data)	return -1;
	SSL *ssl = ssl_server_data->ssl;
	SSL_send(ssl, accountStr, strlen(accountStr));
	bzero(buffer, 1024);
	recvLen = SSL_recv(ssl, buffer, 1024);
	if(recvLen<=0)
	{
		printf("Unknown error from server.\n");
		return -1;
	}

	printf("From Server:\n%s\n", buffer);
	int ret = ParseRegisterStep1Resp(buffer);
	free(accountStr);
	return ret;
}

/*Registration step 2: Ask the Cert Manager to generate a new certificate for this client.*/
int GetCertFromCM(char *name, char *email)
{
	if(!name || !email)	return -1;
	char buffer[1024], *certStr;
	int sendLen, recvLen;
	
	certStr = CreateCMJSON(name, email);
	printf("to CM:%s\n", certStr);

	if(!ssl_cm_data)
		ssl_cm_data = SSL_Connect_To(CM_IP, CM_PORT);
	if(!ssl_cm_data)
		return -1;
	SSL *ssl = ssl_cm_data->ssl;
	SSL_send(ssl, certStr, strlen(certStr));
	bzero(buffer, 1024);
	recvLen = SSL_recv(ssl, buffer, 1024);
	if(recvLen<=0)
	{
		printf("Unknown error from server.\n");
		return -1;
	}

	printf("From CM:%s\n", buffer);
	ParseRegisterStep2Resp(buffer);
	free(certStr);
	return 0;

}

/*Register a new user*/
int RegisterAccount(char *name, char *passwd, char *email)
{
	if(!name || !passwd || !email)
		return -1;
	/*Step 1: register the new user into the server database.*/
	if(-1==RegisterIntoServer(name, passwd, email))
	{
		printf("Register failed.\n");
		return -1;
	}
	/*Step 2: get the private cert of the client from certManager.*/
 	GetCertFromCM(name, email);
	/*Step 3: tell the server that the cert has been prepared well*/

	if(ssl_server_data!=NULL)
	{
		SSL_Connect_Close(ssl_server_data);
		ssl_server_data = NULL;
	}
	if(ssl_cm_data!=NULL)
	{
		SSL_Connect_Close(ssl_cm_data);
		ssl_cm_data = NULL;
	}
}

int GetUserName()
{
	bzero(name, 256);
	printf("UserName:");
	fgets(name, 256, stdin);
	if(Sanitize(name)<=0)
	{
		printf("UserName can not be empty. Exit.\n");
		return -1;
	}
	return 0;
}

int GetUserPassword()
{
	bzero(passwd, 256);
	printf("Password:");
	fgets(passwd, 256, stdin);
	if(Sanitize(passwd)<=0)
	{
		printf("Password can not be empty. Exit.\n");
		return -1;
	}
	return 0;
}

int GetUserEmail()
{
	bzero(email, 256);
	printf("Email:");
	fgets(email, 256, stdin);
	if(Sanitize(email)<=0)
	{
		printf("Email can not be empty. Exit.\n");
		return -1;
	}
	return 0;
}

/*To register a new user*/
void Register()
{
	if(0>GetUserName() || 0>GetUserPassword() || 0>GetUserEmail())
	{
		printf("Get account information failed. Please check!\n");
	}
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
	exit(0);
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
		}else if(0==strcmp("login", cmd)){
			Login();
		}else if(0==strcmp("clear", cmd)){
			bzero(name, 256);
			bzero(passwd, 256);
			bzero(email, 256);
		}else if(0==strcmp("quit", cmd)){
			printf("Client quit, bye.\n");
			return 0;
		}else{
			printf("\nCommands usable:\n\n");
			printf(" -reg: register a new user.\n");
			printf(" -login: login the user.\n");
			printf(" -clear: clear the stored user information.\n");
			printf(" -quit: quitting the client.\n\n");
			printf("\n");
		}
	}
	
	return 0;
}
