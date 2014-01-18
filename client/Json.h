extern char *CreateNewAccountJSON(char *name, char *passwd, char *email);
extern char *CreateCMJSON(char *name, char *email);
extern char *CreateLoginJSON(char *name, char *passwd);
extern char *CreateStatusUpdateJSON(char *name);
extern char *CreateFileQueryJSON(char *to, char *filename, D_H *dh);
extern char *CreatePubRequestJson(char *name);
