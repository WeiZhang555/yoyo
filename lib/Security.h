extern void Get_RandStr(char s[], int num);
/*Encrypt string with rsa algorithm*/
extern int RSA_Encrypt(const unsigned char* plain, int plainLen, char *path_key, unsigned char** dest);
/*Decrypt string with rsa algorithm*/
int RSA_Decrypt(const unsigned char *cipher, char *path_key, unsigned char** dest);

extern int DES_Encrypt(char *inputFile, char *outputFile, unsigned char k[], int keyLen);
extern int DES_Decrypt(char *inputFile, char *outputFile, unsigned char k[], int keyLen);
