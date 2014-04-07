#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/cJSON/cJSON.h"

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

char *GenerateFileRequestResp(int sid, int y)
{
	cJSON *respJson = cJSON_CreateObject();
	cJSON_AddStringToObject(respJson, "cmd", "file_response");
	cJSON *attr = cJSON_CreateObject();
    cJSON_AddItemToObject(respJson, "attr", attr);
    cJSON_AddNumberToObject(attr, "sid", sid);
    cJSON_AddNumberToObject(attr, "y", y);
    char *respStr = cJSON_Print(respJson);
    cJSON_Delete(respJson);
	return respStr;
}

char *GenerateFileSendingResp(int sid, char *from, char *filename, int q, char *xa_en)
{
	cJSON *respJson = cJSON_CreateObject();
	cJSON_AddStringToObject(respJson, "cmd", "sending_file_next");
	cJSON *attr = cJSON_CreateObject();
    cJSON_AddItemToObject(respJson, "attr", attr);
    cJSON_AddNumberToObject(attr, "sid", sid);
    cJSON_AddStringToObject(attr, "from", from);
    cJSON_AddStringToObject(attr, "filename", filename);
    cJSON_AddNumberToObject(attr, "q", q);
    cJSON_AddStringToObject(attr, "xa_en", xa_en);
    char *respStr = cJSON_Print(respJson);
    cJSON_Delete(respJson);
	return respStr;
}

char *GenerateFileOpenResp(int y)
{
	cJSON *respJson = cJSON_CreateObject();
	cJSON_AddStringToObject(respJson, "cmd", "key_info");
	cJSON *attr = cJSON_CreateObject();
    cJSON_AddItemToObject(respJson, "attr", attr);
    cJSON_AddNumberToObject(attr, "y", y);
    char *respStr = cJSON_Print(respJson);
    cJSON_Delete(respJson);
	return respStr;
	
}

char *GenerateFileDeleteResp()
{
	cJSON *respJson = cJSON_CreateObject();
	cJSON_AddStringToObject(respJson, "cmd", "delete_file");
    char *respStr = cJSON_Print(respJson);
    cJSON_Delete(respJson);
	return respStr;
}

char *GenerateFileDeleteResp2(char *user_from, char *fileName)
{
	cJSON *respJson = cJSON_CreateObject();
	cJSON_AddStringToObject(respJson, "cmd", "delete_file");
	cJSON *attr = cJSON_CreateObject();
    cJSON_AddItemToObject(respJson, "attr", attr);
    cJSON_AddStringToObject(attr, "from", user_from);
	cJSON_AddStringToObject(attr, "fileName", fileName);
    char *respStr = cJSON_Print(respJson);
    cJSON_Delete(respJson);
	return respStr;
	
}
