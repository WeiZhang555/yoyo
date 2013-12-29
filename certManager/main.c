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
#define CERT_FILE "CMCert.pem"

#define MAX_EVENTS 10


void HandleClientMsg(SSL* ssl)
{
	char buffer[1024];
	int recvLen;
	int connfd;
	connfd = SSL_get_fd(ssl);
	bzero(buffer, 1024);
	recvLen = SSL_read(ssl, buffer, 1024);
	if(recvLen <= 0 || strncmp(buffer, "quit", 4)==0)
	{
		printf("client quit!\n");
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(connfd);
		return;
	}
	printf("Receive from client %d: %s\n", connfd, buffer);
	fflush(NULL);
	SSL_write(ssl, "Hello client!\n", 14);
}

void Close_up()
{
	printf("Server quit, bye bye!\n");
	return;
}

int main(int argc, char **argv)
{
	int listenfd, connfd;
	int recvLen, sendLen;
	int epollfd, nfds, n;
	socklen_t client_len;
	struct sockaddr_in cliaddr, servaddr;
	char buffer[1024];
	struct epoll_event ev, events[MAX_EVENTS];
	SSL_CTX *ctx;

	/*Initialize the ssl encryption part*/
	signal(SIGINT, Close_up);
	SSL_library_init();
	/*load all the ssl error message*/
	SSL_load_error_strings();
	/*load all the ssl algorithms*/
	OpenSSL_add_ssl_algorithms();
	/*Create an new ssl ctx*/
	ctx = SSL_CTX_new(SSLv23_server_method());	
	/*load the user's certificate*/
	if(!SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM))
	{
		perror("use certificate file error!");
		return;
	}
	/*load user's private key*/
	if(!SSL_CTX_use_PrivateKey_file(ctx, CERT_FILE, SSL_FILETYPE_PEM))
	{
		perror("use private key file error!");
		return;
	}
	/*check whether the private key is correct or not*/
	if(!SSL_CTX_check_private_key(ctx))
	{
		perror("private key check error!");
		return;
	}

	/*open a server listening socket*/
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if(listenfd<0)
	{
		perror("socket() failed!");
		exit(-1);
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
		exit(-1);
	}

	if(listen(listenfd, 10) < 0)
	{
		perror("listen() error!");
		exit(-1);
	}

	epollfd = epoll_create(MAX_EVENTS);
	if (epollfd == -1) {
		perror("epoll_create()");
		exit(EXIT_FAILURE);
	}

	ev.events = EPOLLIN;
	ev.data.fd = listenfd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listenfd, &ev) == -1) {
		perror("epoll_ctl()");
		exit(EXIT_FAILURE);
	}
	
	while(1){
		nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
		if (nfds == -1) {
			perror("epoll_wait()");
			exit(EXIT_FAILURE);
		}

		for(n = 0; n < nfds; ++n) {
			if (events[n].data.fd == listenfd) {
				connfd = accept(listenfd, (struct sockaddr*)&cliaddr, &client_len);
				if(connfd < 0)
				{
					perror("accept()");
					exit(EXIT_FAILURE);
				}
				printf("accept successfully!\n");
				/*add the connfd into the SSL*/
				SSL *ssl = SSL_new(ctx);
				SSL_set_fd(ssl, connfd);
				if(-1==SSL_accept(ssl))
				{
					perror("SSL accept error.");
					close(connfd);
					continue;
				}
				ev.events = EPOLLIN;
				ev.data.ptr = ssl;
				if (epoll_ctl(epollfd, EPOLL_CTL_ADD, connfd, &ev) == -1) {
					perror("epoll_ctl()");
					exit(EXIT_FAILURE);
				}
			}else{
				HandleClientMsg(events[n].data.ptr);
			}
		} /*end for loop*/
	} /*end while*/
	close(listenfd);
	SSL_CTX_free(ctx);
	return 0;
}
