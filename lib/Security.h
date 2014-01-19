extern void Get_RandStr(char s[], int num);
/*Encrypt string with rsa algorithm*/
extern char* RSA_Encrypt(char *str,char *pub_key);
/*Decrypt string with rsa algorithm*/
extern char* RSA_Decrypt(char *str,char *priv_key);
extern int DES_Encrypt(char *inputFile, char *outputFile, unsigned char k[], int keyLen);
extern int DES_Decrypt(char *inputFile, char *outputFile, unsigned char k[], int keyLen);
