#include "File.h"

extern int DB_Init();
extern void DB_DeInit();
extern int DB_Check_User(char *username);
extern int DB_Insert_User(char *username, char *password, char *email);
extern int DB_Update_Cert_Status(char *username);
extern int DB_Login(char *username, char *password);
extern int DB_Record_File_Info(FILE_REQUEST *fr);
extern int DB_Get_YB(int fsid, char *from, char *to, char *fileName);
extern int DB_RevokeFile(char *from, char *to, char *fileName);
extern int DB_Delete_File_Record(int fsid, char *from, char *to, char *fileName);
extern int DB_FileToDelete_ToWhom(char *to, int *sid, char *from, char *fileName);
