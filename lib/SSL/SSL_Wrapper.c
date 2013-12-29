#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <signal.h>

#include "SSL_Wrapper.h"

void ShowCerts(SSL *ssl)
{
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl);

	if(cert)
	{
		printf("Digital Certification information:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Certificate:%s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Issuer:%s\n", line);
		free(line);
		X509_free(cert);
	}else{
		printf("Can't get the certification information!\n");
	}
	fflush(NULL);
	sleep(20);
	return;
}

SSL *SSL_Init_Server(SSL_CTX *ctx, int connfd)
{
	if(!ctx || connfd<=0)
		return NULL;
	SSL *ssl = SSL_new(ctx);
	if(!ssl)
		return NULL;
	
	SSL_set_fd(ssl, connfd);
	if(-1==SSL_accept(ssl))
	{
		perror("SSL accept error.");
		if(ssl)
		{
			SSL_free(ssl);
		}
		return NULL;
	}
	return ssl;
}

SSL *SSL_Init_Client(SSL_CTX *ctx, int sockfd)
{
	/*build a new ssl connection on the basis of the connected fd*/
	SSL *ssl = SSL_new(ctx);
	if(!ssl)
	{
		return NULL;
	}

	SSL_set_fd(ssl, sockfd);	/*bind the read-write socket*/
	if(-1==SSL_connect(ssl))
	{
		perror("SSL connect failed!");
		SSL_free(ssl);
		return NULL;
	}else{
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);
	}
	return ssl;
}

void SSL_DeInit(SSL *ssl)
{
	if(ssl)
	{
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
}

SSL_CTX *SSL_CTX_Init_Server(char *cert)
{
	SSL_CTX *ctx = NULL;
	/*Initialize the ssl encryption part*/
	SSL_library_init();
	/*load all the ssl error message*/
	SSL_load_error_strings();
	/*load all the ssl algorithms*/
	OpenSSL_add_ssl_algorithms();
	/*Create an new ssl ctx*/
	ctx = SSL_CTX_new(SSLv23_server_method());	
	/*load the user's certificate*/
	if(!SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM))
	{
		perror("use certificate file error!");
		return NULL;
	}
	/*load user's private key*/
	if(!SSL_CTX_use_PrivateKey_file(ctx, cert, SSL_FILETYPE_PEM))
	{
		perror("use private key file error!");
		return NULL;
	}
	/*check whether the private key is correct or not*/
	if(!SSL_CTX_check_private_key(ctx))
	{
		perror("private key check error!");
		return NULL;
	}

	return ctx;
}

SSL_CTX *SSL_CTX_Init_Client()
{	
	/*initialize a new ssl object*/
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
	if(!ctx)
	{
		perror("SSL_CTX_new error!");
		return NULL;
	}
	return ctx;
}

int SSL_CTX_DeInit(SSL_CTX *ctx)
{
	SSL_CTX_free(ctx);
}

SSL_CLIENT_DATA *SSL_Connect_To(char *ip, int servport)
{
	int sockfd;
	struct sockaddr_in servaddr;
	SSL_CTX *ctx = NULL;

	ctx = SSL_CTX_Init_Client();
	if(!ctx)
	{
		return NULL;
	}

	/*create a client socket to connect to the server*/
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0)
	{
		perror("socket() failed!");
		return NULL;
	}

	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(servport);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);

	/*connect to server*/
	if(connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
	{
		perror("connect() failed!");
		return NULL;
	}

	/*build a new ssl connection on the basis of the connected fd*/
	SSL *ssl = SSL_Init_Client(ctx, sockfd);
	if(!ssl)
		return NULL;
	SSL_CLIENT_DATA *ssl_data = (SSL_CLIENT_DATA*)malloc(sizeof(SSL_CLIENT_DATA));
	ssl_data->ssl = ssl;
	ssl_data->ctx = ctx;
	return ssl_data;
}

void SSL_Connect_Close(SSL_CLIENT_DATA *ssl_data)
{
	/*close ssl connection*/
	int sockfd = SSL_get_fd(ssl_data->ssl);
	SSL_DeInit(ssl_data->ssl);
	SSL_CTX_DeInit(ssl_data->ctx);
	close(sockfd);
	free(ssl_data);
}


//TODO: we need to close the listening socket somewhere
//and we also need to free the SSL_CTX somewhere
static void Server_Int()
{
	printf("Server quit, bye bye!\n");
	return;
}

int SSL_Listening_Loop(int port, int maxEvents, char *cert, void(*clientHandler)(SSL_CLIENT_DATA*))
{
	/*Handle the INTERRUPT signal*/
	signal(SIGINT, Server_Int);

	int listenfd, connfd;
	int recvLen, sendLen;
	int epollfd, nfds, n;
	socklen_t client_len;
	struct sockaddr_in cliaddr, servaddr;
	char buffer[1024];
	struct epoll_event ev, events[maxEvents];
	SSL_CTX *ctx;


	/*Initialize the SSL context*/
	ctx = SSL_CTX_Init_Server(cert);
	if(!ctx)
		return -1;

	/*open a server listening socket*/
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if(listenfd<0)
	{
		perror("socket() failed!");
		return -1;
	}

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	/*set the socket address to be reuseable*/
	int optVal = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(optVal));
	
	if(bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
	{
		perror("bind() failed!");
		return -1;
	}

	if(listen(listenfd, 10) < 0)
	{
		perror("listen() error!");
		return -1;
	}

	epollfd = epoll_create(maxEvents);
	if (epollfd == -1) {
		perror("epoll_create()");
		return -1;
	}

	ev.events = EPOLLIN;
	ev.data.fd = listenfd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listenfd, &ev) == -1) {
		perror("epoll_ctl()");
		return -1;
	}
	
	while(1){
		nfds = epoll_wait(epollfd, events, maxEvents, -1);
		if (nfds == -1) {
			perror("epoll_wait()");
			return -1;
		}

		for(n = 0; n < nfds; ++n) {
			if (events[n].data.fd == listenfd) {
				connfd = accept(listenfd, (struct sockaddr*)&cliaddr, &client_len);
				if(connfd < 0)
				{
					perror("accept()");
					return -1;
				}
				printf("accept successfully!\n");
				/*Initialize SSL connection*/
				SSL *ssl = SSL_Init_Server(ctx, connfd);
				if(!ssl)
				{
					close(connfd);
					continue;
				}

				SSL_CLIENT_DATA *ssl_data = (SSL_CLIENT_DATA*)malloc(sizeof(SSL_CLIENT_DATA));
				ssl_data->ssl = ssl;
				ssl_data->ctx = ctx;

				ev.events = EPOLLIN;
				ev.data.ptr = ssl_data;
				if (epoll_ctl(epollfd, EPOLL_CTL_ADD, connfd, &ev) == -1) {
					perror("epoll_ctl()");
					return -1;
				}
			}else{
				clientHandler(events[n].data.ptr);
			}
		} /*end for loop*/
	} /*end while*/
}

void SSL_Client_Leave(SSL_CLIENT_DATA *ssl_data)
{
	/*close ssl connection*/
	int sockfd = SSL_get_fd(ssl_data->ssl);
	SSL_DeInit(ssl_data->ssl);
	close(sockfd);
	free(ssl_data);
}
