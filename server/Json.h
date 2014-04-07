extern char *GenerateErrorResp(char *errMes);
extern char *GenerateFileRequestResp(int sid, int y);
extern char *GenerateFileSendingResp(int sid, char *from, char *filename, int q, char *xa_en);
extern char *GenerateFileOpenResp(int y);
extern char *GenerateFileDeleteResp();
extern char *GenerateFileDeleteResp2(char *user_from, char *fileName);
