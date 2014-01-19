#ifndef SESSION_H
#define SESSION_H

typedef struct Session_data{
	int sid;			/*Session id, we set the sid=epollId in this scenario*/
	char username[256];	/*this ssession's client user name*/
	struct Session_data *next;
}SESS_DATA;

extern int Session_Add(char *username);
extern int Session_Delete(int sid);
extern int Session_Print_All();
extern SESS_DATA *Session_Find(int sid);

#endif
