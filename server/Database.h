#include "File.h"

extern int DB_Init();
extern void DB_DeInit();
extern int DB_Check_User(char *username);
extern int DB_Insert_User(char *username, char *password, char *email);
extern int DB_Update_Cert_Status(char *username);
extern int DB_Login(char *username, char *password);
extern int DB_Record_File_Info(FILE_REQUEST *fr);
extern int DB_Get_YB(int fsid, char *from, char *to, char *fileName);
