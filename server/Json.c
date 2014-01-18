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
