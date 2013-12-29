#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>

#include "util.h"

extern SSL *SSL_Init(SSL_CTX *ctx, int sockfd);
extern void SSL_DeInit(SSL *ssl);
extern SSL_CTX *SSL_CTX_Init();
extern int SSL_CTX_DeInit(SSL_CTX *ctx);

void HandleClientMsg(SSL* ssl)
{
	if(!ssl)
		return;
	char buffer[1024];
	int recvLen;
	int connfd;
	connfd = SSL_get_fd(ssl);
	bzero(buffer, 1024);
	recvLen = SSL_read(ssl, buffer, 1024);
	if(recvLen <= 0 || strncmp(buffer, "quit", 4)==0)
	{
		printf("client quit!\n");
		SSL_DeInit(ssl);		
		close(connfd);
		return;
	}
	printf("Receive from client %d: %s\n", connfd, buffer);
	fflush(NULL);
	SSL_write(ssl, "Hello client!\n", 14);
}


static void Sigint_Handler()
{
	printf("Server quit, bye bye!\n");
	return;
}


/**
 *Start the network service, this is the main part of server.
 *return value: -1 if error occurs, 0 if everything is ok.
 */
int NetworkServiceStart()
{
	int listenfd, connfd;
	int recvLen, sendLen;
	int epollfd, nfds, n;
	socklen_t client_len;
	struct sockaddr_in cliaddr, servaddr;
	char buffer[1024];
	struct epoll_event ev, events[MAX_EVENTS];
	SSL_CTX *ctx;

	/*Handle the INTERRUPT signal*/
	signal(SIGINT, Sigint_Handler);

	/*Initialize the SSL context*/
	ctx = SSL_CTX_Init();
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
	servaddr.sin_port = htons(SERVER_PORT);

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

	epollfd = epoll_create(MAX_EVENTS);
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
		nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
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
				SSL *ssl = SSL_Init(ctx, connfd);
				if(!ssl)
				{
					close(connfd);
					continue;
				}
				ev.events = EPOLLIN;
				ev.data.ptr = ssl;
				if (epoll_ctl(epollfd, EPOLL_CTL_ADD, connfd, &ev) == -1) {
					perror("epoll_ctl()");
					return -1;
				}
			}else{
				HandleClientMsg(events[n].data.ptr);
			}
		} /*end for loop*/
	} /*end while*/
	close(listenfd);
	SSL_CTX_DeInit(ctx);
	return 0;
}
