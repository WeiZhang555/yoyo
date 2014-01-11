#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "File.h"

int GetRandom(int max)
{
	srand(time(NULL));
	return rand()%max;
}

int File_Request_Add(char *from, char *to, char *filename, int q, int a)
{
	if(!from || !to || !filename)
		return -1;
	const int max = (1<<30);
	FILE_REQUEST *fr = (FILE_REQUEST*)malloc(sizeof(FILE_REQUEST));
	if(!fr)	return -1;
	bzero(fr->from, 256);
	bzero(fr->to, 256);
	bzero(fr->filename, 512);
	strncpy(fr->from, from, 255);
	strncpy(fr->to, to, 255);
	strncpy(fr->filename, filename, 255);
	fr->q = q;
	fr->a = a;
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
	fr->yb = ;
	return 0;
}

int Session_Delete(int sid)
{
	SESS_DATA *temp = sess_list, *next;
	if(!sess_list)	return -1;

	if(sess_list->sid==sid)
	{
		temp = sess_list->next;
		free(sess_list);
		sess_list = temp;
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
		free(temp->next);
		temp->next = next;
	}

	return 0;
}

int Session_Print_All()
{
	SESS_DATA *iter = sess_list;
	printf("Session Data:\n");
	while(iter)
	{
		printf("{ sid:%d; username:%s; }\n", iter->sid, iter->username);
		iter = iter->next;
	}
}

const SESS_DATA *Session_Find(int sid)
{
	const SESS_DATA *iter = sess_list;
	while(iter)
	{
		if(iter->sid==sid)
			break;
		iter = iter->next;
	}
	return iter;
}
