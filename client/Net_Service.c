#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <signal.h>
#include <libgen.h>
#include <unistd.h>
#include <sys/stat.h>

#include "util.h"
#include "Security.h"
#include "Json.h"
#include "../lib/SSL_Wrapper.h"
#include "../lib/Security.h"
#include "../lib/cJSON/cJSON.h"

SSL_CLIENT_DATA *ssl_server_data = NULL;
SSL_CLIENT_DATA *ssl_cm_data = NULL;
char name[256]={0}, passwd[256]={0}, email[256]={0};
int sid=-1;	/*Session id*/	

extern int Base64Encode(const uint8_t* buffer, size_t length, char** b64text);
extern int Base64Decode(char* b64message, uint8_t** buffer, size_t* length);
void Heartbeat(int);

void StartTimer()
{
	struct itimerval value;
	value.it_value.tv_sec = PULSE_INTERVAL;
	value.it_value.tv_usec = 0;
	value.it_interval.tv_sec = PULSE_INTERVAL ;
	value.it_interval.tv_usec = 0;
	setitimer(ITIMER_REAL, &value, NULL);
	signal(SIGALRM, Heartbeat);
}

void StopTimer()
{
	setitimer(ITIMER_REAL, NULL, NULL);
}

void Disconnect_Server()
{
	if(ssl_server_data!=NULL)
	{
		SSL_Connect_Close(ssl_server_data);
		ssl_server_data = NULL;
		StopTimer();
	}
}

void Disconnect_CM()
{
	if(ssl_cm_data!=NULL)
	{
		SSL_Connect_Close(ssl_cm_data);
		ssl_cm_data = NULL;
	}
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
		
		cJSON_Delete(root);
		return -1;
	}else if(0==strcmp(cmd->valuestring, "sending_cert_next"))
	{
		if(-1==ReceiveCertFromCM(attr))
		{
			cJSON_Delete(root);
			return -1;
		}
	}
	cJSON_Delete(root);
	return 0;
}

/**
 *Parse the login response json from server.
 *return: -1 if login failed. 0 if login succeed.
 */
int ParseLoginResponse(char *buffer)
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
		
		cJSON_Delete(root);
		return -1;
	}else if(0==strcmp(cmd->valuestring, "success"))
	{
		cJSON *child = attr->child;
		if(0==strcmp(child->string, "sid"))
			sid = child->valueint;
		cJSON_Delete(root);
		return 0;
	}
}

int HandleSendingFile(cJSON *attr)
{
	if(!attr)
	{
		printf("attr can not be NULL!\n");
		return -1;
	}
	cJSON *child = attr->child;
	int sid, q;
	char *from, *filename, *xa_en_base64;
	while(child)
	{
		if(0==strcmp(child->string, "sid"))
			sid = child->valueint;
		else if(0==strcmp(child->string, "from"))
			from = child->valuestring;
		else if(0==strcmp(child->string, "filename"))
			filename = child->valuestring;
		else if(0==strcmp(child->string, "q"))
			q = child->valueint;
		else if(0==strcmp(child->string, "xa_en"))
			xa_en_base64 = child->valuestring;
		child = child->next;
	}

	char privKeyName[512]={0};
	snprintf(privKeyName, 511, "%sCert.pem", name);
	printf("Decrypt XA witk key file:%s; \n", privKeyName);
	char *xa_en;
	int xa_en_len=0;
	Base64Decode(xa_en_base64, &xa_en, &xa_en_len);

	char *xa = NULL;
	int xa_len = RSA_Decrypt(xa_en, privKeyName, &xa);

	printf("DECRYPT:XA:%s\n", xa);
	char keyFileName[512]={0};
	char dir[256]={0};
	snprintf(dir, 255, "receiveFiles/%s", from);
	if(0!=access(dir, F_OK))
		mkdir(dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

	snprintf(keyFileName, 511, "%s/%s.key", dir, filename);
	FILE *keyf = fopen(keyFileName, "w");
	if(!keyf)
	{
		printf("Write to key file failed.\n");
		return -1;
	}
	char output[512]={0};
	snprintf(output, 511, "%d\n%s\n", q, xa);	
	fwrite(output, sizeof(char), strlen(output), keyf);
	fclose(keyf);
	return 0;
}

int Query_Period()
{
	char *pulseStr = CreateQueryPulseJSON(sid);
	
	if(!ssl_server_data)
	{
		StopTimer();
		return -1;
	}
	SSL *ssl = ssl_server_data->ssl;
	if(0>=SSL_send(ssl, pulseStr, strlen(pulseStr)))
	{
		free(pulseStr);
		StopTimer();
		Disconnect_Server();
		return -1;
	}
	free(pulseStr);

	char buffer[1024]={0};
	if(0>=SSL_recv(ssl, buffer, 1023))
	{
		printf("Server down!\n");
		StopTimer();
		Disconnect_Server();
		return -1;
	}
	
	printf("From server:%s\n", buffer);
	cJSON *root = cJSON_Parse(buffer);
	cJSON *cmd, *attr, *child;
	child = root->child;
	while(child)
	{
		if(0==strcmp(child->string, "cmd"))
			cmd = child;
		else if(0==strcmp(child->string, "attr"))
			attr = child;
		child = child->next;
	}

	if(0==strcmp(cmd->valuestring, "error"))
	{
		printf("server error:%s\n", attr->child->valuestring);
		cJSON_Delete(root);
		return -1;
	}else if(0==strcmp(cmd->valuestring, "none"))
	{
		printf("Nothing new...\n");
	}else if(0==strcmp(cmd->valuestring, "sending_file_next"))
	{
		if(-1==HandleSendingFile(attr))
		{
			printf("Handle file sending request error.\n");
			cJSON_Delete(root);
			return -1;
		}
		
	}
	cJSON_Delete(root);
	return 0;
}

/*The heartbeat pulse*/
void Heartbeat(int sig)
{
	printf("Heartbeat!\n");
	Query_Period();	
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
	if(sid>0)
	{
		printf("You already logined in!\n");
		return -1;
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
	char *loginStr = CreateLoginJSON(name, passwd);
	if(!ssl_server_data)
		ssl_server_data = SSL_Connect_To(SERVER_IP, SERVER_PORT);
	if(!ssl_server_data)	
	{
		free(loginStr);
		printf("Connect to server failed!\n");
		return -1;
	}
	if(!ssl_cm_data)
		ssl_cm_data = SSL_Connect_To(CM_IP, CM_PORT);
	if(!ssl_cm_data)	
	{
		free(loginStr);
		printf("Connect to cm failed!\n");
		return -1;
	}

	if(0>=SSL_send(ssl_server_data->ssl, loginStr, strlen(loginStr)))
	{
		printf("Can not send information to server!\n");
		free(loginStr);
		Disconnect_Server();
		return -1;
	}
	free(loginStr);
	char buffer[1024]={0};
	int recvLen = SSL_recv(ssl_server_data->ssl, buffer, 1024);
	if(recvLen<=0)
	{
		printf("Unknown error from server.\n");
		Disconnect_Server();
		return -1;
	}

	printf("From Server:\n%s\n", buffer);
	if(0==ParseLoginResponse(buffer))
	{
		printf("Login successfully!\n");
		/*Ask server if there is something new happened.
         like a new file waiting to send*/
		Query_Period();
		/*Set the timer to generate heartbeat pulse to the server periodly*/
		StartTimer();
	}
	return 0;
}

/*Step 3: Update the cert status to ok(certificate prepared) and login */
int UpdateStatusAndLogin()
{
	char *certStr = CreateStatusUpdateJSON(name);

	if(!ssl_server_data)
		ssl_server_data = SSL_Connect_To(SERVER_IP, SERVER_PORT);
	if(!ssl_server_data)	
	{
		printf("Connect to server failed!\n");
		return -1;
	}

	SSL_send(ssl_server_data->ssl, certStr, strlen(certStr));
	free(certStr);

	return Login();
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
	if(0>=SSL_send(ssl, accountStr, strlen(accountStr)))
	{
		printf("Can not send information to server!\n");
		free(accountStr);
		Disconnect_Server();
		return -1;
	}
	free(accountStr);
	bzero(buffer, 1024);
	recvLen = SSL_recv(ssl, buffer, 1024);
	if(recvLen<=0)
	{
		printf("Unknown error from server.\n");
		Disconnect_Server();
		return -1;
	}

	printf("From Server:\n%s\n", buffer);
	int ret = ParseRegisterStep1Resp(buffer);
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
	if(0>=SSL_send(ssl, certStr, strlen(certStr)))
	{
		printf("Can not send information to server!\n");
		free(certStr);
		Disconnect_Server();
		return -1;
	}
	free(certStr);
	bzero(buffer, 1024);
	recvLen = SSL_recv(ssl, buffer, 1024);
	if(recvLen<=0)
	{
		printf("Unknown error from server.\n");
		Disconnect_CM();
		return -1;
	}

	printf("From CM:%s\n", buffer);
	int ret = ParseRegisterStep2Resp(buffer);
	return ret;

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
 	if(-1==GetCertFromCM(name, email))
	{
		printf("Receiving certificates from cm failed.\n");
		return -1;
	}
	/*Step 3: tell the server that the cert has been prepared well*/
	if(-1==UpdateStatusAndLogin())
	{
		printf("Login failed!\n");
		return -1;
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


int ParseFileResponse(cJSON *attr, D_H *dh)
{
	if(!attr || !dh)
		return -1;
	int sid=-1, y=-1;
	cJSON *child = attr->child;
	while(child)
	{
		if(0==strcmp(child->string, "sid"))
		{
			sid = child->valueint;
		}else if(0==strcmp(child->string, "y"))
		{
			y = child->valueint;
		}
		child = child->next;
	}
	
	if(sid==-1 || y==-1)
		return -1;
	dh->sid = sid;
	dh->yb = y;
	dh->K = ComputeY(dh->q, dh->yb, dh->x);
	return 0;
}

/*Tell the server "I want to send a file to someone"
 *return: sid if success, -1 if failed.
 */
int SendFileRequestToServer(char *userName, char *fileName, D_H *dh)
{
	/*Compose the file sending request*/
	if(!ssl_server_data)	
		return -1;
	SSL *ssl = ssl_server_data->ssl;
	char *fileStr = CreateFileQueryJSON(sid, userName, fileName, *dh);
	SSL_send(ssl, fileStr, strlen(fileStr));
	free(fileStr);

	char buffer[1024]={0};
	if(0>=SSL_recv(ssl, buffer,1023))
	{
		Disconnect_Server();
		printf("Server down!\n");
		return -1;
	}

	printf("%s\n", buffer);
	int sid;
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
	}else if(0==strcmp(cmd->valuestring, "file_response"))
	{
		if(-1==ParseFileResponse(attr, dh))
		{
			return -1;
		}
	}
	cJSON_Delete(root);

	return 0;
}

int ReceivePubkeyFromCM(cJSON *attr)
{
	if(!attr)
		return -1;
	char *certFile=NULL, pubFile[512];
	strcpy(pubFile, "pubs/");
	cJSON *child = attr->child;
	while(child)
	{
		if(0==strcmp(child->string, "filename"))
		{
			certFile = child->valuestring;
		}
		child = child->next;
	}

	printf("Public key file name:%s\n", certFile);
	if(!certFile)	return -1;
	
	strcat(pubFile, certFile);
	FILE *f = fopen(pubFile, "w");
	if(!f)
		printf("Certificate file [%s] can not open!\n", pubFile);
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

int ParsePubkeyResponse(char *buffer)
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
	}else if(0==strcmp(cmd->valuestring, "sending_pubkey_next"))
	{
		if(-1==ReceivePubkeyFromCM(attr))
		{
			printf("Receive public key from cm failed.\n");
			return -1;
		}
	}
	cJSON_Delete(root);
	return 0;
}

int GetFriendPubKey(char *username)
{
	if(!ssl_cm_data)
		return -1;
	char buffer[1024];
	SSL *ssl = ssl_cm_data->ssl;
	if(!ssl)	return -1;

	char *pubStr = CreatePubRequestJSON(username);
	SSL_send(ssl, pubStr, strlen(pubStr));
	free(pubStr);
	bzero(buffer ,1024);	
	int len = SSL_recv(ssl, buffer, 1023 );
	if(len<=0)
	{
		printf("Cert Manager unreachable.\n");
		return -1;
	}

	int status = ParsePubkeyResponse(buffer);
	if(status<0)
		return -1;
	return 0;
}

int SendFileContentToServer(char *to, char *fileName, D_H dh)
{
	if(!ssl_server_data)
		return -1;
	char buffer[1024];
	char pubFile[512];
	strcpy(pubFile, "pubs/");
	strcat(pubFile, to);
	strcat(pubFile, "Pub.pem");
	FILE *pubf = fopen(pubFile, "r");
	if(!pubf)
	{
		printf("Can't find the public key for user [%s]!\n", name);
		return -1;
	}
	char xa[30]={0};
	sprintf(xa, "%d", dh.x);
	printf("XA:%s\n", xa);
	/*The encrypted xa which will be sent to server.*/
	printf("Encrypt XA with key:%s;\n", pubFile);
	char *xa_en = NULL;
	int xa_en_len = RSA_Encrypt(xa, strlen(xa), pubFile, &xa_en);
	
	/*Encode the xa_en with base64, for network transfer*/
	char *xa_en_base64 = NULL;
	Base64Encode(xa_en, xa_en_len, &xa_en_base64);

	char *sendingFileName = "encrypted";

	char key[100]={0};
	sprintf(key, "%d", dh.K);
	printf("Encrypting file with Key:%s...\n", key);
	if(DES_Encrypt(fileName, sendingFileName, key, strlen(key)))
	{
		printf("Encrypt failed.\n");
		return -1;
	}

	char *fileStr = CreateFileSendingJSON(dh.sid, xa_en_base64, basename(fileName));
	SSL_send(ssl_server_data->ssl, fileStr, strlen(fileStr));	

	free(xa_en);
	free(xa_en_base64);

	bzero(buffer, 1024);
	if(0>=SSL_recv(ssl_server_data->ssl, buffer, 1024))
	{
		printf("Can't receive command from server!\n");
		Disconnect_Server();
		return -1;
	}
	printf("From server:%s\n", buffer);
	cJSON *root = cJSON_Parse(buffer);
	cJSON *cmd=NULL, *attr=NULL, *child=root->child;
	while(child)
	{
		if(0==strcmp(child->string, "cmd"))
			cmd = child;
		else if(0==strcmp(child->string, "attr"))
			attr = child;
		child = child->next;
	}
	if(0==strcmp(cmd->valuestring, "error"))
	{
		printf("%s\n", attr->child->valuestring);
		cJSON_Delete(root);
	}else if(0==strcmp(cmd->valuestring, "waiting_to_receive"))
	{
		/*Begin to send file to server*/
		printf("Sending file....\n");
		char buffer[512]={0};
		FILE *file = fopen("encrypted", "r");
		int sendLen=0, len;
		while(!feof(file))
		{
			len = fread(buffer, sizeof(char), 511, file);
			if(len<=0)
				break;
			buffer[len] = '\0';
			sendLen = SSL_send(ssl_server_data->ssl, buffer, len);
			if(sendLen<len)
				break;
		}
		SSL_send(ssl_server_data->ssl, "!@done*#", 8);
		printf("Done.\n");
		fclose(file);

	}

	cJSON_Delete(root);
	free(fileStr);
	fclose(pubf);
}

int SendFile()
{
	if(!ssl_server_data)
	{
		printf("Please login first!\n");
		return -1;
	}
	SSL *ssl = ssl_server_data->ssl;
	char userName[256], fileName[1024];
	int unameLen, fnameLen;
	printf("Who do you want to send: ");
	fgets(userName, 256, stdin);
	unameLen = strlen(userName);
	if(userName[unameLen-1]=='\n')
		userName[--unameLen]='\0';
	if(unameLen<=0)
	{
		printf("Username can not be empty.\n\n");
		return -1;
	}

	printf("File path: ");
	fgets(fileName, 1024, stdin);
	fnameLen = strlen(fileName);
	if(fileName[fnameLen-1]=='\n')
		fileName[--fnameLen]='\0';
	if(fnameLen<=0)
	{
		printf("File path can not be empty.\n\n");
		return -1;
	}

	FILE *f=NULL;
	if(NULL==(f=fopen(fileName, "r")) )
	{
		printf("File not exists!\n\n");
		return -1;
	}
	fclose(f);
	printf("You are sending [%s] to [%s]\n\n", fileName, userName);

	/*Step 1:Generate the diffie-hellman struct*/
	D_H dh;
	if(-1==PickDH(&dh))
	{
		printf("Calculate Diffie-Hellman struct failed!\n\n");
		return -1;
	}

	/*Step 2: tell the server to prepare for file encryption next*/
	if(-1==SendFileRequestToServer(userName, basename(fileName), &dh))
	{
		printf("File sending failed.\n");
		return -1;
	}

	/*Step 3: File sending request accepted by server. Now we need to get the friend user's pub key*/
	/*Check if the public key exists, if no, get from cm*/
	char pubFile[512];
	strcpy(pubFile, "pubs/");
	strcat(pubFile, userName);
	strcat(pubFile, "Pub.pem");
	FILE *pubf = fopen(pubFile, "r");
	if(!pubf)
	{
		if(-1==GetFriendPubKey(userName))
		{
			printf("Get certificate from server failed.");
			return -1;
		}
	}else{
		fclose(pubf);
	}
	/*Step 4: Send file content to server*/
	
	if(-1==SendFileContentToServer(userName, fileName, dh))
	{
		printf("Error occured when sending file content to server.\n");
		return -1;
	}
	return 0;
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
	Disconnect_Server();
	Disconnect_CM();
	printf("Client quit, bye.\n");
	exit(0);
}

void Server_Down(int signum)
{
	printf("Server unavailable.\n");
}

int Client_Service_Start(char *ip, int servport)
{
	signal(SIGINT, Client_Intr);
	signal(SIGPIPE, Server_Down);
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
			sid = -1;
		}else if(0==strcmp("quit", cmd)){
			printf("Client quit, bye.\n");
			return 0;
		}else if(0==strcmp("send", cmd)){
			SendFile();
		}else{
			printf("\nCommands usable:\n\n");
			printf(" -reg: register a new user.\n");
			printf(" -login: login the user.\n");
			printf(" -clear: clear the stored user information.\n");
			printf(" -send: send file to someone\n");
			printf(" -quit: quitting the client.\n\n");
		}
	}
	
	Disconnect_Server();
	Disconnect_CM();
	return 0;
}
