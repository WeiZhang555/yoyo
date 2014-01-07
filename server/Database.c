#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mysql.h>
#include <openssl/sha.h>

#include "../lib/Security.h"
#include "Util.h"

static MYSQL *con = NULL;

int DB_Init()
{
	con = mysql_init(NULL);
	if (con == NULL)
	{
		return -1;
	}
	if (mysql_real_connect(con, DB_SERVER, DB_USER_NAME, DB_USER_PASSWORD, DB_DB_NAME, 0, NULL, 0) == NULL)
	{
		return -1;
	}
	return 0;
}

void DB_DeInit()
{
	if(con)
	{
		mysql_close(con);
	}
}

/**
 *check if the username existed in the database;
 *return: -1 for error, 0 for false, >0 for true
 */
int DB_Check_User(char *username)
{
	char to[strlen(username)*2+1];
	mysql_real_escape_string(con, to, username, strlen(username));
	char *prep = "SELECT * FROM users WHERE username='%s' LIMIT 1";
	char sql[1024] = {0};
	snprintf(sql, 1024, prep, to);
	if (mysql_query(con, sql))
	{
		return -1;
	}

	MYSQL_RES *result = mysql_store_result(con);
	if (result == NULL)
	{
		return -1;
	}
	int num_rows = mysql_num_rows(result);
	
	mysql_free_result(result);
	return num_rows;
}

/**
 *Insert user into the database.
 *return; -1 for error, 0 for success.
 */

extern int Base64Encode(const uint8_t* buffer, size_t length, char** b64text);

int DB_Insert_User(char *username, char *password, char *email)
{
	char salt[21]={0};
	Get_RandStr(salt, 21);

	char name_es[strlen(username)*2+1], email_es[strlen(email)*2+1];
	mysql_real_escape_string(con, name_es, username, strlen(username));
	mysql_real_escape_string(con, email_es, email, strlen(email));
	
	/*Generate the SHA hash string as the new password*/
	char newpass[1024] = {0};
	strcpy(newpass, password);
	strcat(newpass, salt);
	unsigned char digest[SHA_DIGEST_LENGTH];

	printf("SHA length:%d\n", SHA_DIGEST_LENGTH);
	/*Get the SHA1 digest with salt */    
    SHA1(newpass, strlen(newpass), (unsigned char*)&digest);    
	/*Get the base64 string of the digest, for convenience of database store.*/
	char *base64Digest = NULL;
	Base64Encode(digest, SHA_DIGEST_LENGTH, &base64Digest);

	char sql[1024];
	snprintf(sql, 1024, "INSERT INTO users(username, password, salt, email) values('%s', '%s', '%s', '%s')",
						name_es, base64Digest, salt, email_es);
	if(mysql_query(con, sql))
	{
		printf("mysql_query error()!\n");
		return -1;
	}

	free(base64Digest);
	return 0;
}