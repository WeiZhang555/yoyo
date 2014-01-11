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
	int yb;	/*yb=(a^x)mod q*/
	struct File_Request *next;	/*The list pointer, points to next*/
}FILE_REQUEST;

FILE_REQUEST *file_request_list = NULL;

#endif
