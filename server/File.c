#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "File.h"

FILE_REQUEST *file_request_list = NULL;

static int GetRandom(int max)
{
	srand(time(NULL));
	return rand()%max;
}

FILE_REQUEST *File_Request_Add(char *from, char *to, char *filename, int q, int a)
{
	if(!from || !to || !filename)
		return NULL;
	const int max = (1<<30);
	FILE_REQUEST *fr = (FILE_REQUEST*)malloc(sizeof(FILE_REQUEST));
	if(!fr)	return NULL;
	bzero(fr->from, 256);
	bzero(fr->to, 256);
	bzero(fr->fileName, 512);
	strncpy(fr->from, from, 255);
	strncpy(fr->to, to, 255);
	strncpy(fr->fileName, filename, 255);
	fr->q = q;
	fr->a = a;
	fr->ready = 0;
	fr->next = NULL;
	FILE_REQUEST *iter = file_request_list;
	if(!file_request_list)
	{
		file_request_list = fr;
		fr->sid = GetRandom(max);
		
	}else{
		while(iter->next)
			iter = iter->next;
		iter->next = fr;
		fr->sid = (iter->sid+1)%max;
	}
	fr->x = GetRandom(10);
	fr->y = ComputeY(q, a, fr->x);
	return fr;
}

int File_Request_Delete(int sid)
{
	FILE_REQUEST *temp = file_request_list, *next=NULL;
	if(!file_request_list)	return -1;

	if(file_request_list->sid==sid)
	{
		temp = file_request_list->next;
		free(file_request_list->xa_en);
		free(file_request_list);
		file_request_list = temp;
	}else{
		while(temp->next)
		{
			if(temp->next->sid==sid)
				break;
			temp = temp->next;
		}

		if(NULL==temp->next)
			return -1;
		next = temp->next->next;
		free(temp->next->xa_en);
		free(temp->next);
		temp->next = next;
	}

	return 0;
}

int File_Request_Print_All()
{
	FILE_REQUEST *iter = file_request_list;
	printf("File Request Data:\n");
	while(iter)
	{
		printf("{ sid:%d; from:%s; to:%s; fileName:%s; }\n", iter->sid, iter->from, iter->to, iter->fileName);
		iter = iter->next;
	}
}

FILE_REQUEST *File_Request_Find(int sid)
{
	FILE_REQUEST *iter = file_request_list;
	while(iter)
	{
		if(iter->sid==sid)
			break;
		iter = iter->next;
	}
	return iter;
}

FILE_REQUEST *File_Request_To_Whom(char *username)
{
	FILE_REQUEST *iter = file_request_list;
	while(iter)
	{
		if(0==strcmp(username, iter->to))
			break;
		iter = iter->next;
	}
	return iter;
}
