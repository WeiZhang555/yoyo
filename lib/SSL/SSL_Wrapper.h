#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct SSL_Client_Data
{
	SSL *ssl;
	SSL_CTX *ctx;
}SSL_CLIENT_DATA;

typedef struct SSL_Server_Data
{
	int listenfd;
	SSL *ssl;
	SSL_CTX *ctx;
}SSL_Server_DATA;

extern void ShowCerts(SSL *ssl);
extern SSL *SSL_Init_Server(SSL_CTX *ctx, int connfd);
extern SSL *SSL_Init_Client(SSL_CTX *ctx, int sockfd);
extern void SSL_DeInit(SSL *ssl);
extern SSL_CTX *SSL_CTX_Init_Server(char *cert);
extern SSL_CTX *SSL_CTX_Init_Client();
extern int SSL_CTX_DeInit(SSL_CTX *ctx);

extern SSL_CLIENT_DATA *SSL_Connect_To(char *ip, int servport);
extern void SSL_Connect_Close(SSL_CLIENT_DATA *ssl_data);
extern int SSL_Listening_Loop(int port, int maxEvents, char *cert, void(*clientHandler)(SSL_CLIENT_DATA*, int));
extern void SSL_Client_Leave(SSL_CLIENT_DATA *ssl_data, int epollfd);
