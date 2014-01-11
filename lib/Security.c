#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/des.h>

#define BUFFSIZE 1024
#define LEN_OF_KEY 8

void Get_RandStr(char s[],int num)
{
	char *str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+-,.<>";
	int i,lstr;
	char ss[2] = {0};
	lstr = strlen(str);
	bzero(s, num);
	srand((unsigned int)time((time_t *)NULL));
	for(i = 0; i < num-1; i++){
		sprintf(ss,"%c",str[(rand()%lstr)]);
  		strcat(s,ss);
 	}
}

int RSA_Encrypt(const unsigned char* plain, int plainLen, char *path_key, unsigned char** dest)
{
    FILE *file=fopen(path_key,"r");
    if(!file){
        perror("open key file error");
        return -1;    
    }
   
	char err[512]={0};
	RSA *p_rsa=PEM_read_RSA_PUBKEY(file,NULL,NULL,NULL);
    if(p_rsa==NULL){
		fclose(file);
		ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        return -1;
    }   
    //flen=strlen(str);
    int rsa_len=RSA_size(p_rsa);
    *dest = (unsigned char *)malloc(rsa_len+1);
    memset(*dest,0,rsa_len+1);
	int encLen=RSA_public_encrypt(plainLen, plain, *dest, p_rsa, RSA_PKCS1_PADDING);
    if(encLen<0){
		fclose(file);
		ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        return -1;
    }

    RSA_free(p_rsa);
    fclose(file);
    return encLen;
}

int RSA_Decrypt(const unsigned char *cipher, char *path_key, unsigned char** dest)
{
    //char *p_de;
    FILE *file=fopen(path_key,"r");
    if(!file){
        perror("open key file error");
        return -1;
    }

	char err[512]={0};
	RSA *p_rsa=PEM_read_RSAPrivateKey(file,NULL,NULL,NULL);
    if(p_rsa==NULL){
		fclose(file);
		ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        return -1;
    }

    int rsa_len=RSA_size(p_rsa);
	*dest = (unsigned char*)malloc(rsa_len+1);
	bzero(*dest, rsa_len+1);
	int decLen = RSA_private_decrypt(rsa_len, cipher, *dest, p_rsa, RSA_PKCS1_PADDING);
	if(decLen<0){
		fclose(file);
		ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        return -1;
    }
    RSA_free(p_rsa);
    fclose(file);
    return decLen;
}

int PrepareKey(unsigned char k[], int keyLen, DES_key_schedule *ks)
{
    unsigned char key[LEN_OF_KEY+1]={0};
	if(LEN_OF_KEY > keyLen)
    {	
    	memcpy(key, k, keyLen);
		memset(key + keyLen, 0x00, LEN_OF_KEY - keyLen);
	}else{
		memcpy(key, k, LEN_OF_KEY);
	}

	DES_set_key_unchecked((const_DES_cblock*)key, ks);
}

int DES_Encrypt(char *inputFile, char *outputFile, unsigned char k[], int keyLen)
{
	if(!inputFile || !outputFile || !k || keyLen<=0)
		return -1;
	
	FILE *inFile = fopen(inputFile, "r");
	if(!inFile)
		return -1;
	FILE *outFile = fopen(outputFile, "w");
	if(!outFile)
	{
		fclose(inFile);
		return -1;
	}

	unsigned char in[8];
    unsigned char out[8];

    DES_key_schedule ks;
	PrepareKey(k, keyLen, &ks);
	int i;
	while(1)
	{
		memset(in, 0, 8);
		memset(out, 0, 8);
		
		fread(in, sizeof(unsigned char), 8, inFile);
		/*If all the byte is '\0', break the loop*/
		for(i=0; i<8; i++)
		{
			if(in[i]!='\0')
				break;
		}
		if(i>=8)
			break;
	
		/*DES encrypt*/
		DES_ecb_encrypt((const_DES_cblock*)&in, (DES_cblock*)&out, &ks, DES_ENCRYPT);
		
		fwrite(out, sizeof(unsigned char), 8, outFile);
		
		if(feof(inFile))
			break;
	}

	fclose(inFile);
	fclose(outFile);
    return 0;
}

int DES_Decrypt(char *inputFile, char *outputFile, unsigned char k[], int keyLen)
{
	if(!inputFile || !outputFile || !k || keyLen<=0)
		return -1;
	
	FILE *inFile = fopen(inputFile, "r");
	if(!inFile)
		return -1;
	FILE *outFile = fopen(outputFile, "w");
	if(!outFile)
	{
		fclose(inFile);
		return -1;
	}

    unsigned char in[8];
    unsigned char out[8];
	int i;

    DES_key_schedule ks;
	PrepareKey(k, keyLen, &ks);

	while(1)
	{
		memset(in, 0, 8);
		memset(out, 0, 8);

		fread(in, sizeof(unsigned char), 8, inFile);
		/*If all the byte is '\0', break the loop*/
		for(i=0; i<8; i++)
		{
			if(in[i]!='\0')
				break;
		}
		if(i>=8)
			break;
		
		DES_ecb_encrypt((const_DES_cblock*)&in, (DES_cblock*)&out, &ks, DES_DECRYPT);

		fwrite(out, sizeof(unsigned char), 8, outFile);
	
		if(feof(inFile))
			break;
	}
	fclose(inFile);
	fclose(outFile);
    return 0;
}
