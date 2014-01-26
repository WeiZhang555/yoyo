#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../lib/cJSON/cJSON.h"
#include "Security.h"

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

char *CreateLoginJSON(char *name, char *passwd)
{
	cJSON *loginJson = cJSON_CreateObject();
	cJSON_AddStringToObject(loginJson, "cmd", "login");
	cJSON *attr = cJSON_CreateObject();
	cJSON_AddItemToObject(loginJson, "attr", attr);
	cJSON_AddStringToObject(attr, "username", name);
	cJSON_AddStringToObject(attr, "password", passwd);
	char *loginStr = cJSON_Print(loginJson);
	cJSON_Delete(loginJson);
	
	return loginStr;
}

char *CreateStatusUpdateJSON(char *name)
{
	cJSON *upCert = cJSON_CreateObject();
	cJSON_AddStringToObject(upCert, "cmd", "cert_status_ok");
	cJSON *attr = cJSON_CreateObject();
	cJSON_AddItemToObject(upCert, "attr", attr);
	cJSON_AddStringToObject(attr, "username", name);
	char *certStr = cJSON_Print(upCert);
	cJSON_Delete(upCert);

	return certStr;
}

char *CreateFileQueryJSON(int sid, char *to, char *filename, D_H dh)
{
	cJSON *fileQuery = cJSON_CreateObject();
	cJSON_AddStringToObject(fileQuery, "cmd", "file_query");
	cJSON *attr = cJSON_CreateObject();
	cJSON_AddItemToObject(fileQuery, "attr", attr);
	cJSON_AddNumberToObject(attr, "sid", sid);
	cJSON_AddStringToObject(attr, "to", to);
	cJSON_AddStringToObject(attr, "filename", filename);
	cJSON_AddNumberToObject(attr, "q", dh.q);
	cJSON_AddNumberToObject(attr, "a", dh.a);
	char *fileStr = cJSON_Print(fileQuery);
	cJSON_Delete(fileQuery);
	return fileStr;
}

char *CreatePubRequestJSON(char *name)
{
	cJSON *fileQuery = cJSON_CreateObject();
	cJSON_AddStringToObject(fileQuery, "cmd", "pubkey_query");
	cJSON *attr = cJSON_CreateObject();
	cJSON_AddItemToObject(fileQuery, "attr", attr);
	cJSON_AddStringToObject(attr, "username",name );
	char *pubStr = cJSON_Print(fileQuery);
	cJSON_Delete(fileQuery);
	return pubStr;

}

char *CreateFileSendingJSON(int fid, char *xa_en, char *fileName_en)
{
	cJSON *fileQuery = cJSON_CreateObject();
	cJSON_AddStringToObject(fileQuery, "cmd", "sending_file_next");
	cJSON *attr = cJSON_CreateObject();
	cJSON_AddItemToObject(fileQuery, "attr", attr);
	cJSON_AddNumberToObject(attr, "sid", fid);
	cJSON_AddStringToObject(attr, "x_en",xa_en);
	char *fileStr = cJSON_Print(fileQuery);
	cJSON_Delete(fileQuery);
	return fileStr;
}

char *CreateQueryPulseJSON(int sid)
{
	cJSON *queryJson = cJSON_CreateObject();
	cJSON_AddStringToObject(queryJson, "cmd", "query_pulse");
	cJSON *attr = cJSON_CreateObject();
	cJSON_AddItemToObject(queryJson, "attr", attr);
	cJSON_AddNumberToObject(attr, "sid", sid);
	char *queryStr = cJSON_Print(queryJson);
	cJSON_Delete(queryJson);
	return queryStr;
}

char *CreateFileWaitingJSON(int sid)
{
	cJSON *queryJson = cJSON_CreateObject();
	cJSON_AddStringToObject(queryJson, "cmd", "receiving_file_next");
	cJSON *attr = cJSON_CreateObject();
	cJSON_AddItemToObject(queryJson, "attr", attr);
	cJSON_AddNumberToObject(attr, "sid", sid);
	char *queryStr = cJSON_Print(queryJson);
	cJSON_Delete(queryJson);
	return queryStr;
}

/**
 *sid: User's session id
 *fsid: file id
 *from: file from
 *fileName: file name
 */
char *CreateFileOpenJSON(int sid, int fsid, char *from, char *filename)
{
	cJSON *queryJson = cJSON_CreateObject();
	cJSON_AddStringToObject(queryJson, "cmd", "open_file");
	cJSON *attr = cJSON_CreateObject();
	cJSON_AddItemToObject(queryJson, "attr", attr);
	cJSON_AddNumberToObject(attr, "sid", sid);
	cJSON_AddNumberToObject(attr, "fsid", fsid);
	cJSON_AddStringToObject(attr, "from", from);
	cJSON_AddStringToObject(attr, "filename", filename);
	char *queryStr = cJSON_Print(queryJson);
	cJSON_Delete(queryJson);
	return queryStr;
}
