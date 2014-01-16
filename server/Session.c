#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Session.h"

SESS_DATA *sess_list = NULL;

int Session_Add(int sid, char *username)
{
	SESS_DATA *s = (SESS_DATA*)malloc(sizeof(SESS_DATA));
	if(!s)	return -1;
	s->sid = sid;
	s->next = NULL;
	bzero(s->username, 256);
	strncpy(s->username, username, 255);
	SESS_DATA *iter = sess_list;
	if(!sess_list)
	{
		sess_list = s;
	}else{
		while(iter->next)
			iter = iter->next;
		iter->next = s;
	}
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
