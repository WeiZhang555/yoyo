extern char *CreateNewAccountJSON(char *name, char *passwd, char *email);
extern char *CreateCMJSON(char *name, char *email);
extern char *CreateLoginJSON(char *name, char *passwd);
extern char *CreateStatusUpdateJSON(char *name);
extern char *CreateFileQueryJSON(int sid, char *to, char *filename, D_H dh);
extern char *CreatePubRequestJSON(char *name);
extern char *CreateFileSendingJSON(int sid, char *xa_en, char *fileName_en);
extern char *CreateQueryPulseJSON(int sid);
extern char *CreateFileWaitingJSON(int sid);
