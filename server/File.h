#ifndef FILE_REQUEST_H
#define FILE_REQUEST_H

typedef struct File_Request{
	int sid;	/*file request session id*/
	char from[256];	/*File from*/
	char to[256];	/*To whom*/
	char fileName[512];	/*File name*/

	int q;	/*the encryption prime*/
	int a; 	/*root of prime q*/
	int x;	/*random number picked by server*/
	int y;	/*yb=(a^x)mod q*/
	int ready;	/*set to 1 if ready to send to friend*/
	struct File_Request *next;	/*The list pointer, points to next*/
}FILE_REQUEST;

extern FILE_REQUEST *File_Request_Add(char *from, char *to, char *filename, int q, int a);
extern int File_Request_Delete(int sid);
extern int File_Request_Print_All();
extern FILE_REQUEST *File_Request_Find(int sid);

#endif
